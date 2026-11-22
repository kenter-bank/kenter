use stellar_strkey::ed25519::PublicKey as StellarPublic;
use stellar_xdr::curr::{
    ContractDataDurability, ContractId, Hash, LedgerKey, LedgerKeyContractData, PublicKey,
    AccountId, ScAddress, ScSymbol, ScVal, ScVec, Uint256, WriteXdr, Limits,
};
use tracing::debug;

/// Minimal Soroban RPC client for roster membership checks.
pub struct SorobanClient {
    http: reqwest::Client,
    rpc_url: String,
    contract_hash: [u8; 32],
}

impl SorobanClient {
    pub fn new(rpc_url: &str, contract_id: &str) -> Result<Self, String> {
        let contract_strkey = stellar_strkey::Contract::from_string(contract_id)
            .map_err(|e| format!("invalid roster contract ID: {e}"))?;

        Ok(Self {
            http: reqwest::Client::new(),
            rpc_url: rpc_url.to_string(),
            contract_hash: contract_strkey.0,
        })
    }

    /// Check if a node entry exists in the roster contract storage.
    ///
    /// Uses `getLedgerEntries` to look up `DataKey::Node(address)` directly —
    /// no transaction simulation needed.
    pub async fn is_node(&self, stellar_address: &str) -> Result<bool, String> {
        let ledger_key_xdr = self.build_node_ledger_key(stellar_address)?;
        let key_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &ledger_key_xdr,
        );

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLedgerEntries",
            "params": {
                "keys": [key_b64]
            }
        });

        debug!(address = %stellar_address, "querying roster contract");

        let response = self
            .http
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("RPC request failed: {e}"))?;

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| format!("RPC response parse failed: {e}"))?;

        if let Some(error) = body.get("error") {
            return Err(format!("RPC error: {error}"));
        }

        // If entries array exists and is non-empty, the node exists
        let entries = body
            .get("result")
            .and_then(|r| r.get("entries"))
            .and_then(|e| e.as_array());

        Ok(entries.map(|e| !e.is_empty()).unwrap_or(false))
    }

    /// Build the XDR-encoded LedgerKey for `DataKey::Node(address)`.
    ///
    /// The roster contract stores nodes as:
    ///   `storage.persistent().set(&DataKey::Node(address), &node)`
    ///
    /// In XDR, `DataKey::Node(address)` is encoded as:
    ///   `ScVal::Vec([ScVal::Symbol("Node"), ScVal::Address(account)])`
    fn build_node_ledger_key(&self, stellar_address: &str) -> Result<Vec<u8>, String> {
        let pub_key = StellarPublic::from_string(stellar_address)
            .map_err(|e| format!("invalid Stellar address: {e}"))?;

        // DataKey::Node(address) → ScVal::Vec(["Node", Address])
        let key = ScVal::Vec(Some(ScVec(
            vec![
                ScVal::Symbol(ScSymbol("Node".try_into().map_err(|_| "symbol encode")?)),
                ScVal::Address(ScAddress::Account(AccountId(
                    PublicKey::PublicKeyTypeEd25519(Uint256(pub_key.0)),
                ))),
            ]
            .try_into()
            .map_err(|_| "vec encode")?,
        )));

        let ledger_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(ContractId(Hash(self.contract_hash))),
            key,
            durability: ContractDataDurability::Persistent,
        });

        ledger_key
            .to_xdr(Limits::none())
            .map_err(|e| format!("XDR encode failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_node_ledger_key_deterministic() {
        let client = SorobanClient::new(
            "https://soroban-testnet.stellar.org",
            "CA26Y3TIFELNFJT2J2VPYGJO6PELJMEBERQWMJHRNBAJQKEM2QWLXHGZ",
        )
        .unwrap();

        let key1 = client
            .build_node_ledger_key("GD3GEVSYK6HEPGEGOGCRJZCBD7W2CDAIVIMYKOMWB3LKWONBQAD5EC5P")
            .unwrap();

        let key2 = client
            .build_node_ledger_key("GD3GEVSYK6HEPGEGOGCRJZCBD7W2CDAIVIMYKOMWB3LKWONBQAD5EC5P")
            .unwrap();

        assert_eq!(key1, key2);
        assert!(!key1.is_empty());
    }

    #[test]
    fn test_invalid_address_rejected() {
        let client = SorobanClient::new(
            "https://soroban-testnet.stellar.org",
            "CA26Y3TIFELNFJT2J2VPYGJO6PELJMEBERQWMJHRNBAJQKEM2QWLXHGZ",
        )
        .unwrap();

        assert!(client.build_node_ledger_key("not-a-stellar-address").is_err());
    }

    /// Integration test against a live testnet roster: `KENTER_TEST_ROSTER`
    /// and a node registered on it, `KENTER_TEST_ROSTER_NODE`.
    /// Run with: cargo test -p kenter-tunnler -- --ignored
    #[tokio::test]
    #[ignore]
    async fn test_is_node_live_testnet() {
        let (Ok(roster), Ok(node)) =
            (std::env::var("KENTER_TEST_ROSTER"), std::env::var("KENTER_TEST_ROSTER_NODE"))
        else {
            eprintln!("skipped: set KENTER_TEST_ROSTER and KENTER_TEST_ROSTER_NODE");
            return;
        };
        let client = SorobanClient::new("https://soroban-testnet.stellar.org", &roster).unwrap();

        let is_member = client.is_node(&node).await.unwrap();
        assert!(is_member, "{node} should be on the roster");

        // Random address is not registered
        let is_stranger = client
            .is_node("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF")
            .await
            .unwrap();
        assert!(!is_stranger, "random address should not be on the roster");
    }
}
