//! `node.json`: everything an installed node needs except its keys.

use serde::{Deserialize, Serialize};

use crate::home::{Home, write_atomic};

/// The relays a fresh install uses until the operator names others: the
/// ones built into this release (`kenter_client::network`), which are also
/// the only relays a wallet will reach a node through.
pub fn default_relays() -> Vec<Relay> {
    kenter_client::network::built().relays.iter().map(|h| Relay::new(h)).collect()
}

/// Longest node name accepted. The roster allows 256 bytes; the partner is
/// registered as `<name>-partner`, and a name is a label, not a document.
pub const MAX_NAME: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Relay {
    pub host: String,
    /// `wss://` when true. Only a local development relay runs without TLS.
    #[serde(default = "yes")]
    pub secure: bool,
}

fn yes() -> bool {
    true
}

impl Relay {
    /// A relay on this machine (`127.0.0.1`, `localhost`, `[::1]`) is a
    /// development relay and speaks plain `ws://`; anything else is TLS.
    /// Deciding from the host means a loopback relay works without the
    /// setup form's "plain ws://" box, which is easy to miss.
    pub fn new(host: &str) -> Self {
        let host = host.trim().to_string();
        let secure = !is_loopback(&host);
        Self { host, secure }
    }
}

/// `host[:port]` names this machine.
pub fn is_loopback(host: &str) -> bool {
    let name = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        host.rsplit_once(':').map_or(host, |(h, _)| h)
    };
    name.eq_ignore_ascii_case("localhost")
        || name.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeConfig {
    /// Roster label for the node; the partner is `<name>-partner`.
    pub name: String,
    /// Tried in order. The node binds to the first that answers and goes
    /// back to the top of the list whenever its connection drops.
    pub relays: Vec<Relay>,
    /// Join as a volunteer (fees burned, permanent for both addresses).
    #[serde(default)]
    pub volunteer: bool,
    /// RPC endpoint override. Contracts are not configurable here: they are
    /// the build's (`kenter_client::network`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub horizon: Option<String>,
    /// The operator has confirmed writing the recovery phrase down. Until
    /// then the tray stays amber: the phrase is the only way back to the
    /// stake.
    #[serde(default)]
    pub backup_confirmed: bool,
    /// Where the recovery phrase is kept (`keys`).
    #[serde(default)]
    pub key_store: KeyStore,
    /// The node's own address, recorded when the phrase moves to the OS
    /// keystore: it names the keystore entry, and the phrase cannot be
    /// read to work it out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

/// Where the recovery phrase lives.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyStore {
    /// `pair.phrase` in the home: owner-only, unlocked by nothing. The
    /// only choice for a headless node, which must restart unattended.
    #[default]
    File,
    /// The OS credential store: Windows Credential Manager or the macOS
    /// Keychain, protected by the user's login. No phrase file on disk.
    Os,
}

impl NodeConfig {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.trim().to_string(),
            relays: default_relays(),
            volunteer: false,
            rpc: None,
            horizon: None,
            backup_confirmed: false,
            key_store: KeyStore::File,
            key_id: None,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("the node needs a name".into());
        }
        if self.name.len() > MAX_NAME {
            return Err(format!("the node name is longer than {MAX_NAME} bytes"));
        }
        if self.relays.is_empty() {
            return Err("the node needs at least one relay".into());
        }
        for r in &self.relays {
            if r.host.is_empty() || r.host.contains(char::is_whitespace) || r.host.contains('/') {
                return Err(format!("{:?} is not a relay host (host[:port], no scheme)", r.host));
            }
        }
        Ok(())
    }

    pub fn load(home: &Home) -> Result<Self, String> {
        let path = home.config();
        let text = std::fs::read_to_string(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                format!("no node is set up in {} (run `kenter-node init`)", home.root().display())
            } else {
                format!("reading {}: {e}", path.display())
            }
        })?;
        let cfg: Self = serde_json::from_str(&text)
            .map_err(|e| format!("{} is not a valid node config: {e}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// `Ok(None)` when there is no `node.json`; an error when there is one
    /// that cannot be read or parsed.
    ///
    /// The distinction matters because `node.json` is the only pointer to
    /// a pair kept in the OS keystore: treating an unreadable file as
    /// "no node" would let Settings, `init` or a load quietly replace it
    /// and bury the pair.
    pub fn load_if_present(home: &Home) -> Result<Option<Self>, String> {
        if !home.config().exists() {
            return Ok(None);
        }
        Self::load(home).map(Some).map_err(|e| {
            format!(
                "{e}. node.json may be the only record of where this node's keys are \
                 kept; fix or restore it rather than setting the node up again"
            )
        })
    }

    pub fn save(&self, home: &Home) -> Result<(), String> {
        self.validate()?;
        home.ensure()?;
        let json = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        write_atomic(&home.config(), &json, false)
    }

    /// The build's network with this config's endpoint overrides, then the
    /// environment's.
    pub fn network(&self) -> Result<kenter_client::NetworkConfig, String> {
        let mine = kenter_client::Overrides {
            rpc: self.rpc.clone(),
            horizon: self.horizon.clone(),
            ..Default::default()
        };
        kenter_client::NetworkConfig::resolve(
            kenter_client::network::built(),
            mine.or(kenter_client::Overrides::from_env()),
        )
    }

    pub fn partner_name(&self) -> String {
        format!("{}-partner", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_config_is_valid_and_round_trips() {
        let dir = crate::testing::tempdir("config");
        let home = Home::at(&dir);
        let mut cfg = NodeConfig::new("pi-kitchen");
        cfg.relays.push(Relay { host: "127.0.0.1:8080".into(), secure: false });
        cfg.volunteer = true;
        cfg.save(&home).unwrap();
        assert_eq!(NodeConfig::load(&home).unwrap(), cfg);
    }

    #[test]
    fn bad_configs_are_refused() {
        assert!(NodeConfig::new("").validate().is_err());
        assert!(NodeConfig::new(&"x".repeat(MAX_NAME + 1)).validate().is_err());
        let mut c = NodeConfig::new("a");
        c.relays.clear();
        assert!(c.validate().is_err());
        c.relays.push(Relay::new("wss://relay.example/connect"));
        assert!(c.validate().is_err(), "a URL is not a host");
    }

    #[test]
    fn missing_config_says_how_to_fix_it() {
        let home = Home::at(crate::testing::tempdir("noconfig"));
        let e = NodeConfig::load(&home).unwrap_err();
        assert!(e.contains("kenter-node init"), "{e}");
    }

    #[test]
    fn a_loopback_relay_defaults_to_plain_ws() {
        assert!(!Relay::new("127.0.0.1:8000").secure);
        assert!(!Relay::new("localhost:8000").secure);
        assert!(!Relay::new("[::1]:8000").secure);
        assert!(Relay::new("relay.example.org").secure);
        assert!(Relay::new("10.0.0.5:8000").secure, "a LAN relay is not this machine");
    }

    #[test]
    fn secure_defaults_on_when_omitted() {
        let c: NodeConfig =
            serde_json::from_str(r#"{"name":"a","relays":[{"host":"r.example"}]}"#).unwrap();
        assert!(c.relays[0].secure);
        assert!(!c.volunteer);
    }
}
