use std::time::Duration;

use base64::Engine;
use serde_json::Value;
use stellar_xdr::curr::{Limits, ReadXdr, TransactionMeta, WriteXdr};
use tracing::debug;

use crate::error::ClientError;

/// Thin Soroban JSON-RPC client.
///
/// Supports the four methods needed for contract invocation:
/// - `getAccount` (sequence numbers)
/// - `simulateTransaction` (dry-run for footprint + fees)
/// - `sendTransaction` (submit signed envelope)
/// - `getTransaction` (poll for result)
/// - `getLedgerEntries` (direct storage reads)
pub struct SorobanRpcClient {
    http: reqwest::Client,
    rpc_url: String,
    network_passphrase: String,
    /// Whether a non-loopback plaintext endpoint is allowed.
    ///
    /// Off by default. Everything the payee gates rest on arrives over this
    /// connection, so a plaintext hop is an invitation to answer for the
    /// ledger, and an `--rpc` flag takes whatever it is given.
    allow_plaintext: bool,
    /// Where account reads go, when the caller has somewhere better.
    ///
    /// Sequence numbers and balances come from Horizon, not from
    /// Soroban RPC. Without this the URL is guessed from whether the RPC
    /// URL contains "testnet", so pointing the wallet at your own
    /// infrastructure would still send your account address to SDF on
    /// every transaction. Someone running their own stack can say so here.
    horizon_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SimulateResult {
    /// The assembled transaction data (sorobanTransactionData XDR, base64).
    pub transaction_data: String,
    /// Minimum resource fee (in stroops).
    pub min_resource_fee: u64,
    /// Authorization entries to attach (base64 XDR).
    pub auth: Vec<String>,
    /// Return value from simulation (base64 XDR ScVal), if any.
    pub return_value: Option<String>,
    /// The ledger the simulation ran against. A co-signer's authorization
    /// expires a fixed number of ledgers after it (`TxBuilder::invoke_cosigned`).
    pub latest_ledger: u32,
}

#[derive(Debug)]
pub struct SendResult {
    pub hash: String,
    pub status: String,
}

#[derive(Debug)]
pub struct GetTransactionResult {
    pub status: String,
    /// Return value XDR (base64), present on SUCCESS.
    pub return_value: Option<String>,
    /// Ledger the tx was included in.
    pub ledger: Option<u64>,
    /// Full result XDR for deeper parsing if needed.
    pub result_xdr: Option<String>,
}

/// What an account holds, as Horizon reports it.
#[derive(Debug, Clone, Default)]
pub struct Holdings {
    /// XLM, in stroops. This pays fees and backs the reserve.
    pub native: i128,
    /// `(code, issuer, stroops)` for every trustline. A line with a zero
    /// balance still appears — its presence is the trustline.
    pub assets: Vec<(String, String, i128)>,
    /// Trustlines, offers and other subentries, which set the reserve.
    pub subentries: u32,
}

impl Holdings {
    /// Minimum balance this account must keep: `(2 + subentries) x 0.5 XLM`.
    pub fn reserve(&self) -> i128 {
        (2 + self.subentries as i128) * 5_000_000
    }

    /// XLM that can actually be spent on fees, never negative.
    pub fn spendable_native(&self) -> i128 {
        (self.native - self.reserve()).max(0)
    }

    /// Balance of one asset, and whether a trustline for it exists at all.
    /// A missing trustline and a zero balance are different problems.
    pub fn asset(&self, code: &str, issuer: &str) -> Option<i128> {
        self.assets
            .iter()
            .find(|(c, i, _)| c == code && i == issuer)
            .map(|(_, _, amount)| *amount)
    }
}

/// Horizon writes balances as decimal strings with seven places.
fn parse_stroops(s: &str) -> i128 {
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    let frac = format!("{frac:0<7}");
    let whole: i128 = whole.parse().unwrap_or(0);
    let frac: i128 = frac.get(..7).unwrap_or("0").parse().unwrap_or(0);
    whole * 10_000_000 + frac
}

impl SorobanRpcClient {
    pub fn new(rpc_url: &str, network_passphrase: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            rpc_url: rpc_url.to_string(),
            network_passphrase: network_passphrase.to_string(),
            allow_plaintext: false,
            horizon_url: None,
        }
    }

    /// Send account reads to this Horizon rather than the public one.
    ///
    /// Same reasoning as [`Self::allowing_plaintext`]: a deliberate call
    /// in the caller's source, not a string nobody looks at twice.
    pub fn with_horizon(mut self, url: &str) -> Self {
        self.horizon_url = Some(url.trim_end_matches('/').to_string());
        self
    }

    /// Permit a plaintext endpoint that is not loopback.
    ///
    /// For a proxy or a tunnel the operator controls and has reason to
    /// trust. It is deliberately a separate call, so it appears in the
    /// source of whoever decided to accept the risk rather than in a URL
    /// string nobody looks at twice.
    pub fn allowing_plaintext(mut self) -> Self {
        self.allow_plaintext = true;
        self
    }

    /// Reject a plaintext endpoint unless it is loopback or opted into.
    ///
    /// Checked per request rather than at construction: the constructor is
    /// called from a dozen places, and a check there is a check that can be
    /// skipped by adding a thirteenth.
    fn check_url(&self) -> Result<(), ClientError> {
        if self.allow_plaintext {
            return Ok(());
        }
        let Some(rest) = self.rpc_url.strip_prefix("http://") else {
            return Ok(()); // https, or a scheme reqwest will reject itself
        };
        let host = rest
            .split(['/', '?', '#'])
            .next()
            .unwrap_or("")
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or_else(|| rest.split(['/', '?', '#']).next().unwrap_or(""));
        let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
            || host.starts_with("127.");
        if loopback {
            Ok(())
        } else {
            Err(ClientError::InsecureRpcUrl(self.rpc_url.clone()))
        }
    }

    /// The endpoint's scheme and host, without path or query.
    ///
    /// Shown to a holder, so the path is dropped deliberately: an API key
    /// in a URL is a common arrangement and not a thing to render on a
    /// screen or paste into a bug report.
    pub fn host_only(&self) -> String {
        let (scheme, rest) = match self.rpc_url.split_once("://") {
            Some((s, r)) => (s, r),
            None => ("", self.rpc_url.as_str()),
        };
        let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        if scheme.is_empty() {
            host.to_string()
        } else {
            format!("{scheme}://{host}")
        }
    }

    pub fn network_passphrase(&self) -> &str {
        &self.network_passphrase
    }

    /// The passphrase of the network this endpoint serves (`getNetwork`).
    ///
    /// What [`crate::network::check_endpoint`] compares against the build's
    /// own before a custom endpoint is trusted.
    pub async fn get_network_passphrase(&self) -> Result<String, ClientError> {
        let body = self.rpc_call("getNetwork", serde_json::json!({})).await?;
        body.get("result")
            .and_then(|r| r.get("passphrase"))
            .and_then(|p| p.as_str())
            .map(str::to_string)
            .ok_or_else(|| ClientError::Other("getNetwork returned no passphrase".into()))
    }

    // ── getAccount ──

    /// Fetch an account's current sequence number.
    pub async fn get_account_sequence(&self, address: &str) -> Result<i64, ClientError> {
        // Soroban RPC doesn't have getAccount — use Horizon or the
        // stellar-xdr getAccount simulation trick. For testnet we can
        // use the Horizon API at the same host.
        //
        // Actually Soroban RPC *does* have getAccount via the JSON-RPC
        // method `getLedgerEntries` with an Account ledger key, but
        // it's simpler to just use Horizon for sequence numbers.
        let horizon_url = self.horizon_url();
        let url = format!("{}/accounts/{}", horizon_url, address);

        let resp = self.http.get(&url).send().await?;
        let body: Value = resp.json().await?;

        if let Some(seq_str) = body.get("sequence").and_then(|s| s.as_str()) {
            seq_str
                .parse::<i64>()
                .map_err(|e| ClientError::Other(format!("bad sequence: {e}")))
        } else if let Some(detail) = body.get("detail").and_then(|d| d.as_str()) {
            Err(ClientError::Other(format!("account not found: {detail}")))
        } else {
            Err(ClientError::Other("failed to fetch account sequence".into()))
        }
    }

    /// Everything one Horizon read says about an account's holdings.
    ///
    /// One call rather than several, and Horizon rather than the asset
    /// contract, for a reason that matters at first run: an account that does
    /// not exist yet cannot be a simulation source, so every `simulate`-based
    /// balance read fails exactly when the client most needs to say "nothing
    /// has arrived yet". Horizon answers 404 and that is a fact, not an
    /// error.
    ///
    /// `Ok(None)` means the account does not exist. It is the normal state of
    /// a key generated ten seconds ago.
    pub async fn get_holdings(&self, address: &str) -> Result<Option<Holdings>, ClientError> {
        let url = format!("{}/accounts/{}", self.horizon_url(), address);
        let body: Value = self.http.get(&url).send().await?.json().await?;

        if body.get("balances").is_none() {
            // `detail` is Horizon's not-found shape; anything else without
            // balances is a response we do not understand, and guessing
            // "empty" would read as "funded but broke".
            if body.get("detail").is_some() {
                return Ok(None);
            }
            return Err(ClientError::Other(format!("unexpected Horizon reply: {body}")));
        }

        let mut holdings = Holdings::default();
        for entry in body["balances"].as_array().into_iter().flatten() {
            let amount = entry
                .get("balance")
                .and_then(|b| b.as_str())
                .map(parse_stroops)
                .unwrap_or(0);
            match entry.get("asset_type").and_then(|t| t.as_str()) {
                Some("native") => holdings.native = amount,
                _ => {
                    let code = entry.get("asset_code").and_then(|c| c.as_str()).unwrap_or("");
                    let issuer = entry.get("asset_issuer").and_then(|c| c.as_str()).unwrap_or("");
                    holdings
                        .assets
                        .push((code.to_string(), issuer.to_string(), amount));
                }
            }
        }
        holdings.subentries = body
            .get("subentry_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        Ok(Some(holdings))
    }

    // ── simulateTransaction ──

    pub async fn simulate(&self, tx_xdr_b64: &str) -> Result<SimulateResult, ClientError> {
        let body = self
            .rpc_call(
                "simulateTransaction",
                serde_json::json!({
                    "transaction": tx_xdr_b64,
                }),
            )
            .await?;

        let result = body
            .get("result")
            .ok_or_else(|| ClientError::SimulationFailed("no result field".into()))?;

        // Check for simulation error
        if let Some(error) = result.get("error") {
            return Err(ClientError::SimulationFailed(
                error.as_str().unwrap_or("unknown").to_string(),
            ));
        }

        let transaction_data = result
            .get("transactionData")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let min_resource_fee = result
            .get("minResourceFee")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        // Extract auth from results[0].auth[]
        let auth = result
            .get("results")
            .and_then(|r| r.as_array())
            .and_then(|arr| arr.first())
            .and_then(|r| r.get("auth"))
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        // Extract return value from results[0].xdr
        let return_value = result
            .get("results")
            .and_then(|r| r.as_array())
            .and_then(|arr| arr.first())
            .and_then(|r| r.get("xdr"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(SimulateResult {
            latest_ledger: result
                .get("latestLedger")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32,
            transaction_data,
            min_resource_fee,
            auth,
            return_value,
        })
    }

    // ── sendTransaction ──

    pub async fn send_transaction(&self, tx_xdr_b64: &str) -> Result<SendResult, ClientError> {
        let body = self
            .rpc_call(
                "sendTransaction",
                serde_json::json!({
                    "transaction": tx_xdr_b64,
                }),
            )
            .await?;

        let result = body
            .get("result")
            .ok_or_else(|| ClientError::Other("no result field".into()))?;

        let hash = result
            .get("hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let status = result
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN")
            .to_string();

        if status == "ERROR" {
            let detail = result
                .get("errorResultXdr")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            return Err(ClientError::TransactionFailed { status, detail });
        }

        Ok(SendResult { hash, status })
    }

    // ── getTransaction ──

    pub async fn get_transaction(&self, hash: &str) -> Result<GetTransactionResult, ClientError> {
        let body = self
            .rpc_call(
                "getTransaction",
                serde_json::json!({
                    "hash": hash,
                }),
            )
            .await?;

        let result = body
            .get("result")
            .ok_or_else(|| ClientError::Other("no result field".into()))?;

        let status = result
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("NOT_FOUND")
            .to_string();

        // Some RPC versions surface a top-level `returnValue`; testnet (protocol
        // 23, TransactionMeta::V4) does not — the invocation result lives inside
        // `resultMetaXdr`. Prefer the top-level field, fall back to the meta.
        let return_value = result
            .get("returnValue")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                result
                    .get("resultMetaXdr")
                    .and_then(|v| v.as_str())
                    .and_then(return_value_from_meta)
            });

        // Full result XDR for deeper parsing if needed.
        let result_xdr = result
            .get("resultXdr")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let ledger = result
            .get("ledger")
            .and_then(|v| v.as_u64());

        Ok(GetTransactionResult {
            status,
            return_value,
            ledger,
            result_xdr,
        })
    }

    /// Poll `getTransaction` until a terminal status or timeout.
    pub async fn poll_transaction(
        &self,
        hash: &str,
        timeout: Duration,
    ) -> Result<GetTransactionResult, ClientError> {
        let start = tokio::time::Instant::now();
        let poll_interval = Duration::from_secs(2);

        loop {
            let result = self.get_transaction(hash).await?;

            match result.status.as_str() {
                "SUCCESS" | "FAILED" => return Ok(result),
                "NOT_FOUND" => {
                    if start.elapsed() > timeout {
                        return Err(ClientError::TransactionTimeout(timeout));
                    }
                    tokio::time::sleep(poll_interval).await;
                }
                _ => {
                    if start.elapsed() > timeout {
                        return Err(ClientError::TransactionTimeout(timeout));
                    }
                    tokio::time::sleep(poll_interval).await;
                }
            }
        }
    }

    // ── getLedgerEntries ──

    /// Read contract storage entries directly.
    /// `keys` are base64-encoded LedgerKey XDR.
    /// The latest ledger the RPC has closed.
    pub async fn get_latest_ledger(&self) -> Result<u32, ClientError> {
        let body = self.rpc_call("getLatestLedger", serde_json::json!({})).await?;
        body.get("result")
            .and_then(|r| r.get("sequence"))
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .ok_or_else(|| ClientError::Other(format!("getLatestLedger: no sequence in {body}")))
    }

    pub async fn get_ledger_entries(
        &self,
        keys: &[String],
    ) -> Result<Vec<Value>, ClientError> {
        let body = self
            .rpc_call(
                "getLedgerEntries",
                serde_json::json!({
                    "keys": keys,
                }),
            )
            .await?;

        let entries = body
            .get("result")
            .and_then(|r| r.get("entries"))
            .and_then(|e| e.as_array())
            .cloned()
            .unwrap_or_default();

        Ok(entries)
    }

    // ── Internal ──

    async fn rpc_call(&self, method: &str, params: Value) -> Result<Value, ClientError> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        self.check_url()?;

        debug!(method, "soroban RPC call");

        let response = self.http.post(&self.rpc_url).json(&request).send().await?;
        let body: Value = response.json().await?;

        if let Some(error) = body.get("error") {
            let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
            let message = error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown")
                .to_string();
            return Err(ClientError::RpcError { code, message });
        }

        Ok(body)
    }

    /// Where account reads go.
    ///
    /// An explicit [`Self::with_horizon`] if there is one; otherwise the
    /// public instance matching the network, guessed from the RPC URL.
    ///
    /// **The default is a privacy leak and should be named as one.**
    /// Soroban RPC has no `getAccount`, so sequence numbers and balances
    /// come from Horizon — and by default that is SDF's, whatever
    /// endpoint the user chose for everything else. SDF therefore learns
    /// every address this wallet touches and roughly when. The real fix
    /// is to read the account through `getLedgerEntries` on the
    /// configured RPC, which this client already does for contract data;
    /// that is a change to the path every transaction takes and is not
    /// made here. Until then, an operator with their own Horizon can at
    /// least point at it.
    fn horizon_url(&self) -> String {
        if let Some(url) = &self.horizon_url {
            return url.clone();
        }
        if self.rpc_url.contains("testnet") {
            "https://horizon-testnet.stellar.org".to_string()
        } else {
            "https://horizon.stellar.org".to_string()
        }
    }
}

/// Extract the Soroban invocation return value from a base64 `resultMetaXdr`,
/// re-encoded as base64 XDR `ScVal` (the shape [`decode_scval`] expects).
///
/// Testnet returns `TransactionMeta::V4` whose `soroban_meta.return_value` is
/// `Option<ScVal>`; older `V3` metas carry a non-optional `ScVal`. Returns
/// `None` for non-Soroban txs (no soroban_meta) or undecodable metas.
///
/// [`decode_scval`]: crate::tx::decode_scval
fn return_value_from_meta(meta_b64: &str) -> Option<String> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(meta_b64).ok()?;
    let meta = TransactionMeta::from_xdr(bytes, Limits::none()).ok()?;
    let rv = match meta {
        // V4's return_value is itself Option<ScVal>; V3's is a bare ScVal.
        TransactionMeta::V4(m) => m.soroban_meta.and_then(|s| s.return_value),
        TransactionMeta::V3(m) => m.soroban_meta.map(|s| s.return_value),
        _ => None,
    }?;
    let out = rv.to_xdr(Limits::none()).ok()?;
    Some(base64::engine::general_purpose::STANDARD.encode(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- L-3 / CS-C2 regression: plaintext endpoints --
    //
    // `--rpc http://...` was accepted without comment, and everything the
    // payee gates rest on arrives over that connection.

    fn client(url: &str) -> SorobanRpcClient {
        SorobanRpcClient::new(url, "Test SDF Network ; September 2015")
    }

    #[test]
    fn a_plaintext_remote_rpc_is_refused() {
        assert!(matches!(
            client("http://evil.example.com/soroban").check_url(),
            Err(ClientError::InsecureRpcUrl(_))
        ));
        assert!(matches!(
            client("http://192.0.2.10:8000").check_url(),
            Err(ClientError::InsecureRpcUrl(_))
        ));
    }

    /// Loopback over plaintext is how the local quickstart is reached, and
    /// has no hop to intercept.
    #[test]
    fn loopback_and_https_are_allowed() {
        for url in [
            "http://localhost:8000/soroban/rpc",
            "http://127.0.0.1:8000",
            "http://[::1]:8000",
            "https://soroban-testnet.stellar.org",
        ] {
            assert!(client(url).check_url().is_ok(), "{url} should be allowed");
        }
    }

    /// An operator who has a reason can still say so, in source.
    #[test]
    fn plaintext_can_be_opted_into_explicitly() {
        assert!(client("http://10.0.0.5:8000")
            .allowing_plaintext()
            .check_url()
            .is_ok());
    }

    #[test]
    fn return_value_extracted_from_v4_meta() {
        use stellar_xdr::curr::{
            ExtensionPoint, ScVal, SorobanTransactionMetaExt, SorobanTransactionMetaV2,
            TransactionMetaV4,
        };

        // A minimal V4 meta carrying a Soroban return value — the shape testnet
        // returns (top-level `returnValue` absent; result lives in the meta).
        let meta = TransactionMeta::V4(TransactionMetaV4 {
            ext: ExtensionPoint::V0,
            tx_changes_before: Default::default(),
            operations: Default::default(),
            tx_changes_after: Default::default(),
            soroban_meta: Some(SorobanTransactionMetaV2 {
                ext: SorobanTransactionMetaExt::V0,
                return_value: Some(ScVal::U32(42)),
            }),
            events: Default::default(),
            diagnostic_events: Default::default(),
        });
        let meta_b64 = base64::engine::general_purpose::STANDARD
            .encode(meta.to_xdr(Limits::none()).unwrap());

        let rv_b64 = return_value_from_meta(&meta_b64).expect("should extract a return value");
        let rv = ScVal::from_xdr(
            base64::engine::general_purpose::STANDARD.decode(&rv_b64).unwrap(),
            Limits::none(),
        )
        .unwrap();
        assert_eq!(rv, ScVal::U32(42));
    }

    #[test]
    fn no_return_value_for_non_soroban_meta() {
        use stellar_xdr::curr::{ExtensionPoint, TransactionMetaV4};
        // A V4 meta with no soroban_meta (a classic, non-contract tx) → None.
        let meta = TransactionMeta::V4(TransactionMetaV4 {
            ext: ExtensionPoint::V0,
            tx_changes_before: Default::default(),
            operations: Default::default(),
            tx_changes_after: Default::default(),
            soroban_meta: None,
            events: Default::default(),
            diagnostic_events: Default::default(),
        });
        let meta_b64 = base64::engine::general_purpose::STANDARD
            .encode(meta.to_xdr(Limits::none()).unwrap());
        assert!(return_value_from_meta(&meta_b64).is_none());
    }

    /// Horizon's decimal strings are the only place amounts arrive as text,
    /// and getting this wrong misreports every balance by a factor of ten.
    #[test]
    fn horizon_decimal_strings_become_stroops() {
        assert_eq!(parse_stroops("0.0000000"), 0);
        assert_eq!(parse_stroops("1.0000000"), 10_000_000);
        assert_eq!(parse_stroops("19.1500000"), 191_500_000);
        assert_eq!(parse_stroops("0.0000001"), 1);
        assert_eq!(parse_stroops("9999.9999900"), 99_999_999_900);
        // No decimal point at all is still a number of whole units.
        assert_eq!(parse_stroops("3"), 30_000_000);
    }

    /// The reserve is what makes "funded" more than "exists": an account
    /// holding exactly its reserve can pay for nothing.
    #[test]
    fn spendable_native_subtracts_the_reserve() {
        let h = |native, subentries| Holdings {
            native,
            assets: vec![],
            subentries,
        };
        // No subentries: 1 XLM reserve.
        assert_eq!(h(10_000_000, 0).reserve(), 10_000_000);
        assert_eq!(h(10_000_000, 0).spendable_native(), 0);
        // One trustline: 1.5 XLM.
        assert_eq!(h(30_000_000, 1).reserve(), 15_000_000);
        assert_eq!(h(30_000_000, 1).spendable_native(), 15_000_000);
        // Below the reserve reads as nothing spendable, not as a negative.
        assert_eq!(h(5_000_000, 1).spendable_native(), 0);
    }

    /// A trustline with no balance and no trustline at all are different
    /// problems with different fixes, so they must not both read as zero.
    #[test]
    fn a_zero_balance_is_not_a_missing_trustline() {
        let h = Holdings {
            native: 0,
            assets: vec![("USDC".into(), "GISSUER".into(), 0)],
            subentries: 1,
        };
        assert_eq!(h.asset("USDC", "GISSUER"), Some(0));
        assert_eq!(h.asset("EURC", "GISSUER"), None);
    }

    #[test]
    fn test_horizon_url_derivation() {
        let client = SorobanRpcClient::new(
            "https://soroban-testnet.stellar.org",
            "Test SDF Network ; September 2015",
        );
        assert_eq!(client.horizon_url(), "https://horizon-testnet.stellar.org");
    }

    /// Live testnet: fetch account sequence for a funded address.
    #[tokio::test]
    #[ignore]
    async fn test_get_account_sequence_live() {
        let client = SorobanRpcClient::new(
            "https://soroban-testnet.stellar.org",
            "Test SDF Network ; September 2015",
        );
        let Ok(account) = std::env::var("KENTER_TEST_ACCOUNT") else {
            eprintln!("skipped: set KENTER_TEST_ACCOUNT to a funded testnet address");
            return;
        };
        let seq = client.get_account_sequence(&account).await.unwrap();
        assert!(seq > 0, "sequence should be positive: {seq}");
    }
}

#[cfg(test)]
mod horizon_tests {
    use super::*;

    /// Pointing the wallet at your own stack must not leak the account
    /// address to SDF: an explicit Horizon overrides the one guessed from
    /// the RPC URL.
    #[test]
    fn an_explicit_horizon_is_used_instead_of_the_public_one() {
        let c = SorobanRpcClient::new("https://my-rpc.example", "Test SDF Network ; September 2015")
            .with_horizon("https://my-horizon.example/");
        assert_eq!(c.horizon_url(), "https://my-horizon.example");
    }

    /// Without one, the guess stands — and the default still reaches
    /// SDF, which is why the doc on `horizon_url` says so.
    #[test]
    fn without_one_the_public_instance_is_the_default() {
        let t = SorobanRpcClient::new("https://soroban-testnet.stellar.org", "x");
        assert_eq!(t.horizon_url(), "https://horizon-testnet.stellar.org");
        let m = SorobanRpcClient::new("https://soroban-rpc.mainnet.example", "x");
        assert_eq!(m.horizon_url(), "https://horizon.stellar.org");
    }
}
