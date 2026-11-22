//! Which Stellar network a build talks to, and where.
//!
//! **The network is fixed when the binary is built**: a release built with the `mainnet` feature talks to mainnet
//! and nothing a holder sets can turn it into a testnet client, or the
//! reverse. A runtime switch would let a missing or wrong setting put
//! someone's money on the wrong network.
//!
//! What *can* change at runtime is where the network is reached: the RPC
//! endpoint (a Settings field, or `KENTER_RPC`) and the Horizon endpoint
//! (`KENTER_HORIZON`). A custom endpoint is checked against the build's
//! passphrase before it is trusted ([`check_endpoint`]), so pointing a
//! mainnet build at a testnet server is refused rather than discovered.
//!
//! The mint, the roster and the relays are part of the network, and are
//! baked in at build time: `KENTER_{TESTNET,MAINNET}_MINT`,
//! `KENTER_{TESTNET,MAINNET}_ROSTER` and `KENTER_{TESTNET,MAINNET}_RELAYS`
//! (see `build.rs`). On testnet the contracts can also be overridden at run
//! time (`KENTER_MINT`, `KENTER_ROSTER`), since testnet deployments come and
//! go. On mainnet they cannot: a wallet pointed at somebody else's mint is a
//! wallet that deposits into it. A build made without its contracts refuses
//! to start rather than guessing ([`NetworkConfig::resolve`]).

include!(concat!(env!("OUT_DIR"), "/relays.rs"));

use crate::rpc::SorobanRpcClient;

/// A network as compiled into a build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    pub name: &'static str,
    pub passphrase: &'static str,
    /// The RPC endpoint used when nothing overrides it.
    pub rpc: &'static str,
    /// The Horizon endpoint used when nothing overrides it.
    pub horizon: &'static str,
    pub mint: Option<&'static str>,
    pub roster: Option<&'static str>,
    /// Whether `KENTER_MINT` / `KENTER_ROSTER` may replace the ids above.
    pub contracts_overridable: bool,
    /// The relays a wallet will reach a selected node through. A node names
    /// its relay in its roster endpoint, and the operator could otherwise
    /// name a host of their own and learn every depositor's IP. Built in,
    /// like the contracts.
    pub relays: &'static [&'static str],
}

pub const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
pub const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";

/// Testnet. Its contracts and relays come from the build environment (or,
/// for the contracts, `KENTER_MINT` / `KENTER_ROSTER` at run time).
pub const TESTNET: Profile = Profile {
    name: "testnet",
    passphrase: TESTNET_PASSPHRASE,
    rpc: "https://soroban-testnet.stellar.org",
    horizon: "https://horizon-testnet.stellar.org",
    mint: option_env!("KENTER_TESTNET_MINT"),
    roster: option_env!("KENTER_TESTNET_ROSTER"),
    contracts_overridable: true,
    relays: TESTNET_RELAYS,
};

/// Mainnet.
///
/// SDF runs no public mainnet RPC. The default is Ankr's keyless public
/// endpoint, listed in Stellar's own provider directory. Every holder trusts
/// this one endpoint's answers, so it is overridable.
pub const MAINNET: Profile = Profile {
    name: "mainnet",
    passphrase: MAINNET_PASSPHRASE,
    rpc: "https://rpc.ankr.com/stellar_soroban",
    horizon: "https://horizon.stellar.org",
    mint: option_env!("KENTER_MAINNET_MINT"),
    roster: option_env!("KENTER_MAINNET_ROSTER"),
    contracts_overridable: false,
    // Empty means a mainnet wallet reaches no node, which fails closed.
    relays: MAINNET_RELAYS,
};

/// The network this binary was built for.
pub const fn built() -> &'static Profile {
    if cfg!(feature = "mainnet") {
        &MAINNET
    } else {
        &TESTNET
    }
}

/// Runtime choices of endpoint, and of contracts where the profile allows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overrides {
    pub rpc: Option<String>,
    pub horizon: Option<String>,
    pub mint: Option<String>,
    pub roster: Option<String>,
}

impl Overrides {
    /// `KENTER_RPC`, `KENTER_HORIZON`, `KENTER_MINT`, `KENTER_ROSTER`.
    /// Blank values count as unset.
    pub fn from_env() -> Self {
        fn var(k: &str) -> Option<String> {
            std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
        }
        Overrides {
            rpc: var("KENTER_RPC"),
            horizon: var("KENTER_HORIZON"),
            mint: var("KENTER_MINT"),
            roster: var("KENTER_ROSTER"),
        }
    }

    /// `self`, with any field it leaves unset taken from `fallback`.
    pub fn or(self, fallback: Overrides) -> Self {
        Overrides {
            rpc: self.rpc.or(fallback.rpc),
            horizon: self.horizon.or(fallback.horizon),
            mint: self.mint.or(fallback.mint),
            roster: self.roster.or(fallback.roster),
        }
    }
}

/// Everything a component needs to reach the network, resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConfig {
    pub profile: &'static Profile,
    pub rpc: String,
    pub horizon: String,
    pub mint: String,
    pub roster: String,
}

impl NetworkConfig {
    /// Apply `overrides` to `profile`.
    ///
    /// Refuses, rather than falls back, in the two cases where falling back
    /// would be wrong: a mainnet build with no baked-in contract ids, and a
    /// contract override on a profile that does not allow one.
    pub fn resolve(profile: &'static Profile, overrides: Overrides) -> Result<Self, String> {
        let contract = |what: &str, baked: Option<&'static str>, over: Option<String>, env: &str| {
            match over {
                Some(v) if profile.contracts_overridable => Ok(v),
                Some(v) if Some(v.as_str()) == baked => Ok(v),
                Some(_) => Err(format!(
                    "{env} is set, but this {} build's {what} is fixed when it is built; \
                     unset it",
                    profile.name
                )),
                None => baked.map(str::to_string).ok_or_else(|| {
                    format!(
                        "this {} build has no {what} contract: it was built without \
                         KENTER_{}_{}{}",
                        profile.name,
                        profile.name.to_uppercase(),
                        what.to_uppercase(),
                        if profile.contracts_overridable {
                            format!(" (or set {env} when running it)")
                        } else {
                            String::new()
                        }
                    )
                }),
            }
        };
        Ok(NetworkConfig {
            profile,
            rpc: overrides.rpc.unwrap_or_else(|| profile.rpc.to_string()),
            horizon: overrides.horizon.unwrap_or_else(|| profile.horizon.to_string()),
            mint: contract("mint", profile.mint, overrides.mint, "KENTER_MINT")?,
            roster: contract("roster", profile.roster, overrides.roster, "KENTER_ROSTER")?,
        })
    }

    /// The build's own network, with the environment's overrides.
    pub fn from_env() -> Result<Self, String> {
        Self::resolve(built(), Overrides::from_env())
    }

    pub fn passphrase(&self) -> &'static str {
        self.profile.passphrase
    }

    /// An RPC client for this network, with its Horizon set explicitly
    /// rather than guessed from the RPC url.
    pub fn rpc_client(&self) -> SorobanRpcClient {
        SorobanRpcClient::new(&self.rpc, self.profile.passphrase).with_horizon(&self.horizon)
    }
}

/// Ask `rpc_url` which network it serves, and refuse it unless that is
/// `profile`'s.
///
/// The check a custom endpoint has to pass before it is saved. A wrong
/// passphrase is not a connectivity problem: every transaction the client
/// signed would be for a network the endpoint does not serve, and every
/// read would describe somebody else's ledger.
pub async fn check_endpoint(profile: &Profile, rpc_url: &str) -> Result<(), String> {
    let client = SorobanRpcClient::new(rpc_url, profile.passphrase);
    let served = client
        .get_network_passphrase()
        .await
        .map_err(|e| format!("{} did not answer: {e}", client.host_only()))?;
    if served != profile.passphrase {
        return Err(format!(
            "{} serves \"{served}\", not {} (\"{}\")",
            client.host_only(),
            profile.name,
            profile.passphrase
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NO_IDS: Profile = Profile {
        mint: None,
        roster: None,
        ..MAINNET
    };
    const BAKED: Profile = Profile {
        mint: Some("CMINT"),
        roster: Some("CROSTER"),
        ..MAINNET
    };

    #[test]
    fn a_dev_build_is_testnet() {
        if !cfg!(feature = "mainnet") {
            assert_eq!(built().passphrase, TESTNET_PASSPHRASE);
        }
    }

    #[test]
    fn testnet_takes_every_override() {
        let o = Overrides {
            rpc: Some("https://r".into()),
            horizon: Some("https://h".into()),
            mint: Some("CM".into()),
            roster: Some("CR".into()),
        };
        let c = NetworkConfig::resolve(&TESTNET, o).unwrap();
        assert_eq!((c.rpc.as_str(), c.horizon.as_str()), ("https://r", "https://h"));
        assert_eq!((c.mint.as_str(), c.roster.as_str()), ("CM", "CR"));
    }

    #[test]
    fn defaults_come_from_the_profile() {
        const TESTNET_BAKED: Profile =
            Profile { mint: Some("CMINT"), roster: Some("CROSTER"), ..TESTNET };
        let c = NetworkConfig::resolve(&TESTNET_BAKED, Overrides::default()).unwrap();
        assert_eq!(c.rpc, TESTNET.rpc);
        assert_eq!(c.horizon, TESTNET.horizon);
        assert_eq!((c.mint.as_str(), c.roster.as_str()), ("CMINT", "CROSTER"));
    }

    /// A testnet build made without contracts names both ways to supply them.
    #[test]
    fn testnet_without_contracts_says_how_to_set_them() {
        const BARE: Profile = Profile { mint: None, roster: None, ..TESTNET };
        let e = NetworkConfig::resolve(&BARE, Overrides::default()).unwrap_err();
        assert!(e.contains("KENTER_TESTNET_MINT") && e.contains("KENTER_MINT"), "{e}");
    }

    /// A mainnet build made without its contract ids refuses to start.
    #[test]
    fn mainnet_without_baked_ids_refuses() {
        let e = NetworkConfig::resolve(&NO_IDS, Overrides::default()).unwrap_err();
        assert!(e.contains("KENTER_MAINNET_MINT"), "{e}");
    }

    /// Mainnet contracts cannot be swapped at runtime; endpoints can.
    #[test]
    fn mainnet_contracts_are_fixed_but_endpoints_are_not() {
        let e = NetworkConfig::resolve(
            &BAKED,
            Overrides { mint: Some("CEVIL".into()), ..Default::default() },
        )
        .unwrap_err();
        assert!(e.contains("fixed"), "{e}");

        // Restating the baked id is harmless.
        assert!(NetworkConfig::resolve(
            &BAKED,
            Overrides { mint: Some("CMINT".into()), ..Default::default() }
        )
        .is_ok());

        let c = NetworkConfig::resolve(
            &BAKED,
            Overrides { rpc: Some("https://mine".into()), ..Default::default() },
        )
        .unwrap();
        assert_eq!(c.rpc, "https://mine");
        assert_eq!(c.passphrase(), MAINNET_PASSPHRASE);
    }

    /// Live: the default mainnet endpoint serves mainnet, and is refused
    /// for a testnet build. `cargo test -p kenter-client -- --ignored live_`
    #[tokio::test]
    #[ignore = "needs the network"]
    async fn live_the_default_mainnet_endpoint_passes_its_own_check() {
        check_endpoint(&MAINNET, MAINNET.rpc).await.unwrap();
        let e = check_endpoint(&TESTNET, MAINNET.rpc).await.unwrap_err();
        assert!(e.contains("not testnet"), "{e}");
    }

    #[tokio::test]
    #[ignore = "needs the network"]
    async fn live_a_testnet_endpoint_is_refused_for_mainnet() {
        let e = check_endpoint(&MAINNET, TESTNET.rpc).await.unwrap_err();
        assert!(e.contains("not mainnet"), "{e}");
    }

    #[test]
    fn the_mainnet_default_endpoint_is_not_testnets() {
        assert_ne!(MAINNET.rpc, TESTNET.rpc);
        assert!(!MAINNET.rpc.contains("testnet"));
        assert_eq!(MAINNET.horizon, "https://horizon.stellar.org");
    }
}
