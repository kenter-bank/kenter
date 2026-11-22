//! Reading what a mint actually escrows.
//!
//! A note is a claim on the mint's `pay_token`, which is immutable
//! constructor config — so the client has no business assuming it. Everything
//! downstream follows from this one read: what symbol amounts are shown in,
//! and whether the holder needs a trustline before they can deposit or be
//! paid out.
//!
//! A Stellar Asset Contract answers all of it. `symbol()` gives the code,
//! and `name()` gives `CODE:ISSUER` for a classic asset or the bare string
//! `native` for XLM — which is also exactly the test for whether a trustline
//! is needed, since only classic assets have one.

use sha2::{Digest, Sha256};
use stellar_xdr::curr::{
    AccountId, AlphaNum12, AlphaNum4, Asset as XdrAsset, AssetCode12, AssetCode4,
    ContractIdPreimage, Hash, HashIdPreimage, HashIdPreimageContractId, Limits, PublicKey,
    ScString, ScVal, Uint256, WriteXdr,
};

use crate::error::ClientError;
use crate::tx::TxBuilder;

/// What a mint escrows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    /// The SAC contract id, as the mint reports it.
    pub contract_id: String,
    /// Asset code: `USDC`, or `native` for XLM.
    pub code: String,
    /// Issuer, for a classic asset. `None` for native XLM.
    pub issuer: Option<String>,
    pub decimals: u32,
}

impl Asset {
    /// Does holding or receiving this need a Stellar trustline?
    ///
    /// Only classic assets do. It matters more on the way out than on the way
    /// in: a redemption pays the holder, and a payout cannot reach an account
    /// with no trustline — so a holder without one can end up with good notes
    /// they cannot redeem.
    pub fn needs_trustline(&self) -> bool {
        self.issuer.is_some()
    }

    /// How amounts in this asset are shown.
    ///
    /// `$` for a dollar stablecoin, because that is what it *is* rather than
    /// a stand-in. Otherwise the asset's own code. Never a ticker invented
    /// for this project — there is no Kenter token, and labelling amounts
    /// with one claims an asset exists that does not.
    pub fn symbol(&self) -> String {
        match self.code.as_str() {
            "native" => "XLM ".to_string(),
            "USDC" | "USDx" | "EURC" if self.code.starts_with("USD") => "$".to_string(),
            other => format!("{other} "),
        }
    }
}

/// The contract address of the Stellar Asset Contract for `code:issuer` (or
/// native XLM, as `native` with no issuer) on the network `passphrase` names.
///
/// `SHA-256(HashIdPreimage::ContractId { network_id, FromAsset(asset) })`,
/// which is how the network derives it: nothing here is asked of an endpoint.
pub fn sac_contract_id(
    passphrase: &str,
    code: &str,
    issuer: Option<&str>,
) -> Result<String, ClientError> {
    let asset = match issuer {
        None if code == "native" => XdrAsset::Native,
        None => {
            return Err(ClientError::XdrDecode(format!("asset {code} has no issuer")));
        }
        Some(issuer) => {
            let key = stellar_strkey::ed25519::PublicKey::from_string(issuer)
                .map_err(|e| ClientError::InvalidAddress(format!("{issuer}: {e}")))?;
            let issuer = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key.0)));
            let bytes = code.as_bytes();
            match bytes.len() {
                1..=4 => {
                    let mut c = [0u8; 4];
                    c[..bytes.len()].copy_from_slice(bytes);
                    XdrAsset::CreditAlphanum4(AlphaNum4 { asset_code: AssetCode4(c), issuer })
                }
                5..=12 => {
                    let mut c = [0u8; 12];
                    c[..bytes.len()].copy_from_slice(bytes);
                    XdrAsset::CreditAlphanum12(AlphaNum12 { asset_code: AssetCode12(c), issuer })
                }
                _ => {
                    return Err(ClientError::XdrDecode(format!("asset code {code:?} is not 1-12 bytes")));
                }
            }
        }
    };
    let preimage = HashIdPreimage::ContractId(HashIdPreimageContractId {
        network_id: Hash(Sha256::digest(passphrase.as_bytes()).into()),
        contract_id_preimage: ContractIdPreimage::Asset(asset),
    });
    let xdr = preimage
        .to_xdr(Limits::none())
        .map_err(|e| ClientError::XdrEncode(e.to_string()))?;
    Ok(stellar_strkey::Contract(Sha256::digest(&xdr).into()).to_string().as_str().to_owned())
}

/// Read-only view of a Stellar Asset Contract.
pub struct AssetClient {
    tx: TxBuilder,
    contract_id: String,
}

impl AssetClient {
    pub fn new(tx: TxBuilder, contract_id: &str) -> Self {
        AssetClient { tx, contract_id: contract_id.to_string() }
    }

    /// Everything the client needs about this asset, in three reads.
    pub async fn describe(&mut self) -> Result<Asset, ClientError> {
        let code = self.string_call("symbol").await?;
        let name = self.string_call("name").await?;
        let decimals = self.u32_call("decimals").await?;

        // `CODE:ISSUER` for a classic asset, bare `native` for XLM.
        let (name_code, issuer) = match name.split_once(':') {
            Some((c, i)) => (c.to_string(), Some(i.to_string())),
            None => (name.clone(), None),
        };

        // Believe the name only if it is the asset this contract is. A Stellar
        // Asset Contract's address is derived from the network and the asset,
        // so it can be recomputed here and compared: without that, whatever
        // endpoint answered `name()` chose the issuer the holder then signs a
        // trustline to. Also refuses any token contract that
        // is not a SAC, which is the only kind a trustline can be for.
        let expected = sac_contract_id(
            self.tx.rpc().network_passphrase(),
            &name_code,
            issuer.as_deref(),
        )?;
        if expected != self.contract_id {
            return Err(ClientError::XdrDecode(format!(
                "{} says it is {name}, but that asset's contract is {expected}",
                self.contract_id
            )));
        }
        if code != name_code {
            return Err(ClientError::XdrDecode(format!(
                "{} reports symbol {code} but name {name}",
                self.contract_id
            )));
        }

        Ok(Asset {
            contract_id: self.contract_id.clone(),
            code,
            issuer,
            decimals,
        })
    }

    async fn string_call(&mut self, func: &str) -> Result<String, ClientError> {
        let result = self.tx.simulate_invoke(&self.contract_id, func, vec![]).await?;
        match result.as_ref().ok_or(ClientError::MissingReturnValue)? {
            ScVal::String(ScString(s)) => Ok(s.to_utf8_string_lossy()),
            // A SAC returns these as String, but a non-SAC token contract may
            // use Symbol. Accept both rather than failing on a technicality.
            ScVal::Symbol(s) => Ok(s.to_utf8_string_lossy()),
            other => Err(ClientError::XdrDecode(format!(
                "{func} returned {other:?}, expected a string"
            ))),
        }
    }

    async fn u32_call(&mut self, func: &str) -> Result<u32, ClientError> {
        let result = self.tx.simulate_invoke(&self.contract_id, func, vec![]).await?;
        crate::tx::scval_to_u32(result.as_ref().ok_or(ClientError::MissingReturnValue)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TESTNET: &str = "Test SDF Network ; September 2015";

    /// Both as the testnet uses them: the native SAC in every stake
    /// transfer, testnet USDC in a cancelled print's refund.
    #[test]
    fn sac_ids_match_the_ones_the_network_uses() {
        assert_eq!(
            sac_contract_id(TESTNET, "native", None).unwrap(),
            "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC"
        );
        assert_eq!(
            sac_contract_id(
                TESTNET,
                "USDC",
                Some("GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5")
            )
            .unwrap(),
            "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA"
        );
    }

    #[test]
    fn a_different_issuer_or_network_gives_a_different_contract() {
        let real = sac_contract_id(
            TESTNET,
            "USDC",
            Some("GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"),
        )
        .unwrap();
        let other_issuer = sac_contract_id(
            TESTNET,
            "USDC",
            Some("GAYDUPIP4RRKM74GAPKLXPZZKVYOIMEQDMZS2ZLNCWJ34HHR2JOWZJDY"),
        )
        .unwrap();
        let other_net = sac_contract_id(
            "Public Global Stellar Network ; September 2015",
            "USDC",
            Some("GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"),
        )
        .unwrap();
        assert_ne!(real, other_issuer);
        assert_ne!(real, other_net);
    }

    fn asset(code: &str, issuer: Option<&str>) -> Asset {
        Asset {
            contract_id: "C...".into(),
            code: code.into(),
            issuer: issuer.map(String::from),
            decimals: 7,
        }
    }

    #[test]
    fn native_needs_no_trustline_and_shows_as_xlm() {
        let a = asset("native", None);
        assert!(!a.needs_trustline());
        assert_eq!(a.symbol(), "XLM ");
    }

    /// The case that matters: a payout cannot reach an account with no
    /// trustline, so getting this wrong strands value rather than just
    /// looking untidy.
    #[test]
    fn a_classic_asset_needs_a_trustline() {
        let a = asset("USDC", Some("GBBD47IF"));
        assert!(a.needs_trustline());
    }

    #[test]
    fn a_dollar_stablecoin_shows_a_dollar_sign() {
        assert_eq!(asset("USDC", Some("G...")).symbol(), "$");
    }

    /// Reads live testnet mints, named by `KENTER_TEST_MINT_NATIVE` and
    /// `KENTER_TEST_MINT_USDC`. Ignored by default - it needs the
    /// network - but it is the only check that the SAC actually answers the
    /// way this module assumes, which is the part worth being sure of.
    #[tokio::test]
    #[ignore = "network"]
    async fn the_live_mints_describe_their_own_assets() {
        use crate::{MintClient, SorobanRpcClient, TxBuilder};
        use kenter_crypto::keypair::StellarKeypair;

        const RPC: &str = "https://soroban-testnet.stellar.org";
        const PASS: &str = "Test SDF Network ; September 2015";

        // `simulate_invoke` needs a sequence number, so a config read needs a
        // *funded* source account - unlike `get_token`, which reads ledger
        // entries directly and is why reconciliation works with a throwaway
        // key. Supplied by the environment so no secret lands in the repo.
        let Ok(secret) = std::env::var("KENTER_TEST_SECRET") else {
            eprintln!("skipped: set KENTER_TEST_SECRET to a funded testnet secret");
            return;
        };
        let kp = StellarKeypair::from_stellar_secret(&secret).expect("bad KENTER_TEST_SECRET");
        let build = || TxBuilder::new(SorobanRpcClient::new(RPC, PASS), kp.clone());

        for (var, want_code, want_trustline) in [
            ("KENTER_TEST_MINT_NATIVE", "native", false),
            ("KENTER_TEST_MINT_USDC", "USDC", true),
        ] {
            let Ok(mint) = std::env::var(var) else {
                eprintln!("skipped {want_code}: set {var} to a testnet mint escrowing it");
                continue;
            };
            let mint = mint.as_str();
            let mut m = MintClient::new(build(), mint);
            let token = m.pay_token().await.unwrap();
            let asset = AssetClient::new(build(), &token).describe().await.unwrap();
            assert_eq!(asset.code, want_code, "{mint}");
            assert_eq!(asset.needs_trustline(), want_trustline, "{mint}");
            assert!(!asset.symbol().contains("KEN"));
        }
    }

    /// The `KENTER_TEST_SECRET` account must trust USDC, which checks the
    /// positive case against the live ledger; a fresh account checks the
    /// negative.
    #[tokio::test]
    #[ignore = "network"]
    async fn a_trustline_is_visible_when_it_exists_and_absent_when_it_does_not() {
        use crate::{SorobanRpcClient, TxBuilder};
        use kenter_crypto::keypair::StellarKeypair;

        const RPC: &str = "https://soroban-testnet.stellar.org";
        const PASS: &str = "Test SDF Network ; September 2015";
        const USDC_ISSUER: &str =
            "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

        let Ok(secret) = std::env::var("KENTER_TEST_SECRET") else {
            eprintln!("skipped: set KENTER_TEST_SECRET to a funded testnet secret");
            return;
        };
        let kp = StellarKeypair::from_stellar_secret(&secret).expect("bad KENTER_TEST_SECRET");
        let holder = TxBuilder::new(SorobanRpcClient::new(RPC, PASS), kp);
        assert!(holder.has_trustline("USDC", USDC_ISSUER).await.unwrap());

        // An account that has never existed trusts nothing.
        let stranger = TxBuilder::new(
            SorobanRpcClient::new(RPC, PASS),
            StellarKeypair::random(),
        );
        assert!(!stranger.has_trustline("USDC", USDC_ISSUER).await.unwrap());
    }

    /// Anything else shows its own code rather than a made-up one.
    #[test]
    fn an_unknown_asset_shows_its_own_code() {
        assert_eq!(asset("GOLD", Some("G...")).symbol(), "GOLD ");
        for a in [asset("GOLD", Some("G...")), asset("native", None)] {
            assert!(!a.symbol().contains("KEN"));
        }
    }
}
