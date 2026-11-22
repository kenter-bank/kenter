//! Everything the harness does to, or reads from, the ledger.
//!
//! Provisioning and assertions share this module because they share the
//! question: what does the chain say right now. Balances come from the asset
//! contract rather than Horizon so that an account and the mint — which is a
//! contract and has no Horizon entry at all — can be read the same way.

use kenter_client::{MintClient, SorobanRpcClient, TxBuilder};
use kenter_crypto::keypair::StellarKeypair;

pub const RPC: &str = "https://soroban-testnet.stellar.org";
pub const PASSPHRASE: &str = "Test SDF Network ; September 2015";
pub const FRIENDBOT: &str = "https://friendbot.stellar.org";

/// One testnet identity the harness controls.
#[derive(Clone)]
pub struct Account {
    pub keypair: StellarKeypair,
    pub address: String,
    pub label: String,
}

impl Account {
    pub fn generate(label: &str) -> Account {
        let keypair = StellarKeypair::random();
        Account {
            address: keypair.stellar_address(),
            keypair,
            label: label.to_string(),
        }
    }

    pub fn tx(&self) -> TxBuilder {
        TxBuilder::new(SorobanRpcClient::new(RPC, PASSPHRASE), self.keypair.clone())
    }
}

/// Ask friendbot for 10 000 XLM. Idempotent in effect: an account that already
/// exists is reported as already funded rather than treated as a failure.
pub async fn fund(address: &str) -> Result<String, String> {
    let url = format!("{FRIENDBOT}?addr={address}");
    let resp = reqwest::get(&url)
        .await
        .map_err(|e| format!("friendbot {address}: {e}"))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if status.is_success() {
        return Ok("funded".into());
    }
    // Friendbot answers 400 for an account it has already created, which is
    // the normal state on a re-run and not an error.
    if body.contains("op_already_exists") || body.contains("createAccountAlreadyExist") {
        return Ok("already funded".into());
    }
    Err(format!("friendbot {address}: {status} {body}"))
}

/// Does this account exist on the ledger at all?
pub async fn exists(address: &str) -> bool {
    SorobanRpcClient::new(RPC, PASSPHRASE)
        .get_account_sequence(address)
        .await
        .is_ok()
}

/// A balance in the mint's asset, in stroops.
///
/// Reads the asset contract's own `balance`, which works for a classic account
/// and for a contract address alike — the mint's escrow is the latter and has
/// no Horizon entry to read.
pub async fn balance(source: &Account, sac: &str, holder: &str) -> Result<i128, String> {
    let mut tx = source.tx();
    let arg = kenter_client::tx::address_to_scval(holder)
        .map_err(|e| format!("address {holder}: {e}"))?;
    let out = tx
        .simulate_invoke(sac, "balance", vec![arg])
        .await
        .map_err(|e| format!("balance({holder}): {e}"))?;
    match out {
        Some(v) => kenter_client::tx::scval_to_i128(&v).map_err(|e| format!("balance: {e}")),
        None => Err("balance returned nothing".into()),
    }
}

/// Send a classic asset from one account to another through its SAC.
pub async fn pay(
    from: &Account,
    sac: &str,
    to: &str,
    amount: i128,
) -> Result<String, String> {
    let mut tx = from.tx();
    let args = vec![
        kenter_client::tx::address_to_scval(&from.address)
            .map_err(|e| format!("from: {e}"))?,
        kenter_client::tx::address_to_scval(to).map_err(|e| format!("to: {e}"))?,
        kenter_client::tx::i128_to_scval(amount),
    ];
    tx.invoke(sac, "transfer", args)
        .await
        .map(|r| r.tx_hash)
        .map_err(|e| format!("transfer {amount} to {to}: {e}"))
}

/// Add a trustline if the account does not have one. Returns what it did.
pub async fn ensure_trustline(
    account: &Account,
    code: &str,
    issuer: &str,
) -> Result<&'static str, String> {
    let mut tx = account.tx();
    if tx
        .has_trustline(code, issuer)
        .await
        .map_err(|e| format!("has_trustline {}: {e}", account.address))?
    {
        return Ok("already present");
    }
    // i64::MAX is the "no limit" limit; the harness has no reason to cap what
    // a test account may hold.
    tx.change_trust(code, issuer, i64::MAX)
        .await
        .map_err(|e| format!("change_trust {}: {e}", account.address))?;
    Ok("added")
}

/// A read-only mint client. Ledger-entry reads need no funded source, but
/// `simulate`-backed ones do, so this takes the account that pays for those.
pub fn mint(source: &Account, contract: &str) -> MintClient {
    MintClient::new(source.tx(), contract)
}

/// The slot a note was registered under -- what the mint keys its
/// records by, so what a status read or a redemption has to name.
pub fn slot_of(path: &std::path::Path) -> Result<u32, String> {
    Ok(parse_note(path)?.slot_id)
}

/// A note file, parsed.
pub fn parse_note(
    path: &std::path::Path,
) -> Result<kenter_crypto::token::BearerToken, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    kenter_crypto::container::deserialize_bearer_token(&bytes)
        .map_err(|e| format!("{} is not a container: {e}", path.display()))
}

/// The latest ledger the RPC has closed.
pub async fn latest_ledger() -> Result<u32, String> {
    let body = rpc_call("getLatestLedger", serde_json::json!({})).await?;
    body["sequence"]
        .as_u64()
        .map(|s| s as u32)
        .ok_or_else(|| format!("getLatestLedger: no sequence in {body}"))
}

/// One `FEE burned` event: a volunteer's fee destroyed instead of credited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeBurned {
    pub slot_id: u32,
    pub node: String,
    pub amount: i128,
    pub tx_hash: String,
}

/// Every `FEE burned` event `contract` emitted from `start_ledger` on, read
/// from the RPC's event store (`getEvents`), decoded from the XDR. Also
/// returns how many `FEE locked` events there were, which should be none.
pub async fn fee_burned_since(contract: &str, start_ledger: u32) -> Result<(Vec<FeeBurned>, usize), String> {
    use kenter_client::tx::{decode_scval, scval_to_address, scval_to_i128, scval_to_u32};
    use stellar_xdr::curr::ScVal;

    let body = rpc_call(
        "getEvents",
        serde_json::json!({
            "startLedger": start_ledger,
            "filters": [{ "type": "contract", "contractIds": [contract] }],
            "pagination": { "limit": 200 },
        }),
    )
    .await?;
    let sym = |v: &ScVal| match v {
        ScVal::Symbol(s) => Some(s.0.to_string()),
        _ => None,
    };
    let mut burned = Vec::new();
    let mut locked = 0;
    for ev in body["events"].as_array().into_iter().flatten() {
        let topics: Vec<ScVal> = ev["topic"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|t| t.as_str().and_then(|b| decode_scval(b).ok()))
            .collect();
        if topics.len() < 2 || sym(&topics[0]).as_deref() != Some("FEE") {
            continue;
        }
        match sym(&topics[1]).as_deref() {
            Some("locked") => locked += 1,
            Some("burned") => {
                let value = decode_scval(ev["value"].as_str().unwrap_or_default())
                    .map_err(|e| format!("FEE burned value: {e}"))?;
                let ScVal::Map(Some(map)) = &value else {
                    return Err(format!("FEE burned value is not a map: {value:?}"));
                };
                let field = |name: &str| {
                    map.0
                        .iter()
                        .find(|e| sym(&e.key).as_deref() == Some(name))
                        .map(|e| e.val.clone())
                        .ok_or_else(|| format!("FEE burned has no `{name}`"))
                };
                burned.push(FeeBurned {
                    slot_id: scval_to_u32(&field("slot_id")?).map_err(|e| e.to_string())?,
                    node: scval_to_address(&field("node")?).map_err(|e| e.to_string())?,
                    amount: scval_to_i128(&field("amount")?).map_err(|e| e.to_string())?,
                    tx_hash: ev["txHash"].as_str().unwrap_or_default().to_string(),
                });
            }
            _ => {}
        }
    }
    Ok((burned, locked))
}

/// One `PRINT skip` event: a selected pair replaced by a runner-up because
/// it did not serve (`docs/architecture/node-selection.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skip {
    pub slot_id: u32,
    pub position: u32,
    pub skipped: String,
    pub replacement: String,
    pub fee: i128,
}

/// Every `PRINT skip` event `contract` emitted from `start_ledger` on.
pub async fn skips_since(contract: &str, start_ledger: u32) -> Result<Vec<Skip>, String> {
    use kenter_client::tx::{decode_scval, scval_to_address, scval_to_i128, scval_to_u32};
    use stellar_xdr::curr::ScVal;

    let body = rpc_call(
        "getEvents",
        serde_json::json!({
            "startLedger": start_ledger,
            "filters": [{ "type": "contract", "contractIds": [contract] }],
            "pagination": { "limit": 200 },
        }),
    )
    .await?;
    let sym = |v: &ScVal| match v {
        ScVal::Symbol(s) => Some(s.0.to_string()),
        _ => None,
    };
    let field = |map: &stellar_xdr::curr::ScMap, name: &str| {
        map.0
            .iter()
            .find(|e| sym(&e.key).as_deref() == Some(name))
            .map(|e| e.val.clone())
            .ok_or_else(|| format!("PRINT skip has no `{name}`"))
    };
    let mut out = Vec::new();
    for ev in body["events"].as_array().into_iter().flatten() {
        let topics: Vec<ScVal> = ev["topic"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|t| t.as_str().and_then(|b| decode_scval(b).ok()))
            .collect();
        if topics.len() < 2
            || sym(&topics[0]).as_deref() != Some("PRINT")
            || sym(&topics[1]).as_deref() != Some("skip")
        {
            continue;
        }
        let value = decode_scval(ev["value"].as_str().unwrap_or_default())
            .map_err(|e| format!("PRINT skip value: {e}"))?;
        let ScVal::Map(Some(map)) = &value else {
            return Err(format!("PRINT skip value is not a map: {value:?}"));
        };
        let node_a = |v: ScVal| -> Result<String, String> {
            let ScVal::Map(Some(m)) = v else { return Err("pair is not a map".into()) };
            scval_to_address(&field(&m, "node_a")?).map_err(|e| e.to_string())
        };
        out.push(Skip {
            slot_id: scval_to_u32(&field(map, "slot_id")?).map_err(|e| e.to_string())?,
            position: scval_to_u32(&field(map, "position")?).map_err(|e| e.to_string())?,
            skipped: node_a(field(map, "skipped")?)?,
            replacement: node_a(field(map, "replacement")?)?,
            fee: scval_to_i128(&field(map, "fee")?).map_err(|e| e.to_string())?,
        });
    }
    Ok(out)
}

/// One print, as the mint's events tell it.
///
/// A registered print deletes its slot, so after the fact the events are
/// the only record of who requested it and which pairs built it.
#[derive(Debug, Clone, Default)]
pub struct PrintSeen {
    pub slot_id: u32,
    pub depositor: String,
    pub total_pairs: u32,
    pub amount: i128,
    pub first: (String, String),
    pub last: (String, String),
    /// The chain once selection closed (`PRINT selected`), with every
    /// `PRINT skip` applied. Empty if selection never closed.
    pub chain: Vec<(String, String)>,
    /// `TOKEN active` was emitted: the print was registered as a note.
    pub registered: bool,
}

/// Every print `contract` was asked for from `start_ledger` on.
pub async fn prints_since(contract: &str, start_ledger: u32) -> Result<Vec<PrintSeen>, String> {
    use kenter_client::tx::{decode_scval, scval_to_address, scval_to_i128, scval_to_u32};
    use stellar_xdr::curr::{ScMap, ScVal};

    let body = rpc_call(
        "getEvents",
        serde_json::json!({
            "startLedger": start_ledger,
            "filters": [{ "type": "contract", "contractIds": [contract] }],
            "pagination": { "limit": 1000 },
        }),
    )
    .await?;
    let sym = |v: &ScVal| match v {
        ScVal::Symbol(s) => Some(s.0.to_string()),
        _ => None,
    };
    let field = |map: &ScMap, name: &str| -> Result<ScVal, String> {
        map.0
            .iter()
            .find(|e| sym(&e.key).as_deref() == Some(name))
            .map(|e| e.val.clone())
            .ok_or_else(|| format!("event has no `{name}`"))
    };
    let pair = |v: ScVal| -> Result<(String, String), String> {
        let ScVal::Map(Some(m)) = v else { return Err("pair is not a map".into()) };
        Ok((
            scval_to_address(&field(&m, "node_a")?).map_err(|e| e.to_string())?,
            scval_to_address(&field(&m, "node_b")?).map_err(|e| e.to_string())?,
        ))
    };
    let mut prints: Vec<PrintSeen> = Vec::new();
    for ev in body["events"].as_array().into_iter().flatten() {
        let topics: Vec<ScVal> = ev["topic"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|t| t.as_str().and_then(|b| decode_scval(b).ok()))
            .collect();
        if topics.len() < 2 {
            continue;
        }
        let kind = (sym(&topics[0]).unwrap_or_default(), sym(&topics[1]).unwrap_or_default());
        let wanted = matches!(
            (kind.0.as_str(), kind.1.as_str()),
            ("PRINT", "request") | ("PRINT", "selected") | ("PRINT", "skip") | ("TOKEN", "active")
        );
        if !wanted {
            continue;
        }
        let value = decode_scval(ev["value"].as_str().unwrap_or_default())
            .map_err(|e| format!("{kind:?} value: {e}"))?;
        let ScVal::Map(Some(map)) = &value else {
            return Err(format!("{kind:?} value is not a map"));
        };
        let slot_id = scval_to_u32(&field(map, "slot_id")?).map_err(|e| e.to_string())?;
        if kind.1 == "request" {
            prints.push(PrintSeen {
                slot_id,
                depositor: scval_to_address(&field(map, "depositor")?).map_err(|e| e.to_string())?,
                total_pairs: scval_to_u32(&field(map, "total_pairs")?).map_err(|e| e.to_string())?,
                amount: scval_to_i128(&field(map, "amount")?).map_err(|e| e.to_string())?,
                first: pair(field(map, "first_pair")?)?,
                last: pair(field(map, "last_pair")?)?,
                ..Default::default()
            });
            continue;
        }
        // Events for prints requested before `start_ledger` are not ours.
        let Some(p) = prints.iter_mut().find(|p| p.slot_id == slot_id) else { continue };
        match kind.1.as_str() {
            "selected" => {
                let ScVal::Vec(Some(v)) = field(map, "pairs")? else {
                    return Err("PRINT selected pairs is not a vec".into());
                };
                p.chain = v.0.iter().cloned().map(pair).collect::<Result<_, _>>()?;
            }
            "skip" => {
                let at = scval_to_u32(&field(map, "position")?).map_err(|e| e.to_string())? as usize;
                let with = pair(field(map, "replacement")?)?;
                if let Some(slot) = p.chain.get_mut(at) {
                    *slot = with;
                }
            }
            _ => p.registered = true,
        }
    }
    Ok(prints)
}

async fn rpc_call(method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
    let req = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let resp: serde_json::Value = reqwest::Client::new()
        .post(RPC)
        .json(&req)
        .send()
        .await
        .map_err(|e| format!("{method}: {e}"))?
        .json()
        .await
        .map_err(|e| format!("{method}: {e}"))?;
    if let Some(err) = resp.get("error") {
        return Err(format!("{method}: {err}"));
    }
    Ok(resp["result"].clone())
}
