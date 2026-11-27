//! The drand quicknet beacon that seeds a print
//! (`docs/architecture/node-selection.md`).
//!
//! The mint verifies every signature it is given, so nothing here is
//! trusted: a mirror that lies costs a failed simulation, not a bad seed.
//! The client's jobs are to wait for round `R`, fetch it, and hand the mint
//! the point in the form it takes.

use std::time::Duration;

use ark_bls12_381::G1Affine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::error::ClientError;

/// quicknet's chain hash: the chain the mint's beacon key belongs to.
pub const QUICKNET: &str = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";

/// Public HTTP mirrors, tried in order. Independent operators, so one being
/// down or wrong does not stall a print.
pub const MIRRORS: &[&str] = &[
    "https://api.drand.sh",
    "https://drand.cloudflare.com",
    "https://api2.drand.sh",
    "https://api3.drand.sh",
];

/// Fetches beacon rounds.
#[derive(Clone)]
pub struct Beacon {
    http: reqwest::Client,
    mirrors: Vec<String>,
    chain: String,
}

/// Replaces [`MIRRORS`]: a comma-separated list of base URLs, or `none` for
/// no mirrors at all.
///
/// `none` is for testing the mint's fallback seed: with no beacon, this
/// client seeds by the fallback once it opens. It changes nothing the mint
/// accepts, since every signature is verified there; at worst a machine
/// configured this way stops posting rounds itself, and others still do.
pub const MIRRORS_ENV: &str = "KENTER_BEACON_MIRRORS";

/// The mirror list `value` of [`MIRRORS_ENV`] asks for: the public list
/// when unset or blank, none for `none`, otherwise each URL given.
fn mirrors_from(value: Option<&str>) -> Vec<String> {
    match value.map(str::trim) {
        None | Some("") => MIRRORS.iter().map(|m| m.to_string()).collect(),
        Some(v) if v.eq_ignore_ascii_case("none") => Vec::new(),
        Some(v) => v
            .split(',')
            .map(|m| m.trim().trim_end_matches('/').to_string())
            .filter(|m| !m.is_empty())
            .collect(),
    }
}

impl Beacon {
    /// quicknet, through the public mirrors, or those named in
    /// [`MIRRORS_ENV`].
    pub fn quicknet() -> Result<Self, ClientError> {
        let set = std::env::var(MIRRORS_ENV).ok();
        let mirrors = mirrors_from(set.as_deref());
        if set.as_deref().is_some_and(|v| !v.trim().is_empty()) {
            tracing::warn!("{MIRRORS_ENV} is set: beacon mirrors {mirrors:?}");
        }
        Self::new(QUICKNET, mirrors)
    }

    pub fn new(chain: &str, mirrors: Vec<String>) -> Result<Self, ClientError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Beacon { http, mirrors, chain: chain.to_string() })
    }

    /// Round `round`'s signature, uncompressed, as `seed_print` takes it.
    /// Tries each mirror; fails only if none returns that round.
    pub async fn signature(&self, round: u64) -> Result<[u8; 96], ClientError> {
        let mut last = String::from("no mirrors");
        for m in &self.mirrors {
            match self.from_mirror(m, round).await {
                Ok(sig) => return Ok(sig),
                Err(e) => last = format!("{m}: {e}"),
            }
        }
        Err(ClientError::Other(format!("beacon round {round}: {last}")))
    }

    async fn from_mirror(&self, mirror: &str, round: u64) -> Result<[u8; 96], ClientError> {
        let url = format!("{mirror}/{}/public/{round}", self.chain);
        let resp = self.http.get(&url).send().await?;
        if !resp.status().is_success() {
            return Err(ClientError::Other(format!("HTTP {}", resp.status().as_u16())));
        }
        let body: serde_json::Value = resp.json().await?;
        // A mirror answering with another round would only fail at the
        // mint, but saying so here names the right culprit.
        if body["round"].as_u64() != Some(round) {
            return Err(ClientError::Other(format!("answered round {}", body["round"])));
        }
        let hex_sig = body["signature"]
            .as_str()
            .ok_or_else(|| ClientError::Other("no signature".into()))?;
        let raw = hex::decode(hex_sig).map_err(|e| ClientError::Other(format!("signature hex: {e}")))?;
        let compressed: [u8; 48] = raw
            .try_into()
            .map_err(|_| ClientError::Other("signature is not 48 bytes".into()))?;
        g1_uncompressed(&compressed)
    }
}

/// A compressed G1 point (as drand publishes it) in Soroban's uncompressed
/// encoding: `be(x) || be(y)`, flags clear. The point is checked to be on
/// the curve and in the subgroup on the way in.
pub fn g1_uncompressed(compressed: &[u8; 48]) -> Result<[u8; 96], ClientError> {
    let p = G1Affine::deserialize_compressed(&compressed[..])
        .map_err(|e| ClientError::Other(format!("not a G1 point: {e}")))?;
    // arkworks reads any input with the infinity flag as the identity,
    // ignoring the other bits (48 bytes of 0xff "decompress"). No beacon
    // signature is the identity, and the mint would refuse it, but this
    // should not hand the mint garbage dressed as a point.
    if p.infinity {
        return Err(ClientError::Other("the identity is not a beacon signature".into()));
    }
    let mut out = Vec::with_capacity(96);
    p.serialize_uncompressed(&mut out)
        .map_err(|e| ClientError::Other(format!("encode G1: {e}")))?;
    out.try_into()
        .map_err(|_| ClientError::Other("uncompressed G1 is not 96 bytes".into()))
}

#[cfg(test)]
mod tests {
    use super::{MIRRORS, mirrors_from};

    #[test]
    fn the_mirror_setting_reads_as_documented() {
        let public: Vec<String> = MIRRORS.iter().map(|m| m.to_string()).collect();
        assert_eq!(mirrors_from(None), public);
        assert_eq!(mirrors_from(Some("  ")), public);
        assert!(mirrors_from(Some("none")).is_empty());
        assert!(mirrors_from(Some(" NONE ")).is_empty());
        assert_eq!(
            mirrors_from(Some("https://a.example/, ,https://b.example")),
            vec!["https://a.example".to_string(), "https://b.example".to_string()]
        );
    }

    /// The fixture round the mint's suite and the spike use: compressed as
    /// drand published it, and uncompressed as the mint verified it.
    #[test]
    fn decompresses_to_what_the_mint_verified() {
        let c: [u8; 48] = hex::decode(
            "8414a8586cf92eaca970d9d177ff4a323506c409e65a2862df44dfb5a0959073bb989d31a2844fdb69043a918a2a0d6e",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let u = super::g1_uncompressed(&c).unwrap();
        assert_eq!(
            hex::encode(u),
            "0414a8586cf92eaca970d9d177ff4a323506c409e65a2862df44dfb5a0959073bb989d31a2844fdb69043a918a2a0d6e0104bf3a1d2f71367e0d31e654fb0cce3d75cb50f22204c8c52c7aa741faedf428f8bbf151be33a8ad846a787a22d5fe"
        );
    }

    #[test]
    fn garbage_is_not_a_point() {
        assert!(super::g1_uncompressed(&[0xffu8; 48]).is_err());
    }
}
