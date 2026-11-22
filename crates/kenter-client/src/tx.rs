use std::time::Duration;

use base64::Engine;
use sha2::{Digest, Sha256};
use stellar_strkey::ed25519::PublicKey as StellarPublic;
use stellar_xdr::curr::{
    AlphaNum4, Asset, AssetCode4, ChangeTrustAsset, ChangeTrustOp, CreateAccountOp, LedgerKey,
    LedgerKeyTrustLine, PaymentOp, TrustLineAsset,
    AccountId, ContractId, DecoratedSignature, Hash, InvokeContractArgs,
    Limits, Memo, MuxedAccount, Operation, OperationBody, Preconditions, PublicKey,
    ReadXdr, ScAddress, ScBytes, ScString, ScSymbol, ScVal, SequenceNumber,
    Signature, SignatureHint, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation,
    SorobanCredentials, SorobanTransactionData, TimeBounds, TimePoint,
    Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256,
    WriteXdr, Int128Parts, HostFunction, InvokeHostFunctionOp, ScMap, ScMapEntry,
    HashIdPreimage, HashIdPreimageSorobanAuthorization, ScVec, LedgerFootprint,
};
use tracing::debug;

use crate::error::ClientError;
use crate::rpc::SorobanRpcClient;
use kenter_crypto::keypair::StellarKeypair;

const BASE_FEE: u32 = 100;

/// How many ledgers a co-signer's authorization stays valid after the
/// simulation that produced it: about five minutes, enough to re-simulate,
/// sign and submit, and short enough that a withheld entry is soon dead.
const COSIGN_LEDGERS: u32 = 60;

/// How much room a contested call declares beyond what its simulation saw.
///
/// Claims on one slot are simulated against the slot as it stands, and
/// several pairs claim within moments of each other. When another claim
/// lands first the slot's claim list is longer than simulated, so the
/// transaction writes more than it declared and fails with
/// `resource_limit_exceeded`, which is common with several pairs racing.
/// A claim simulated against `seen` claims can apply after up to
/// `2k - seen` more have landed, so the margin is per entry that could
/// arrive first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ContentionMargin {
    pub extra_bytes: u32,
    pub extra_instructions: u32,
}

/// One claim entry in a slot, in bytes: 260 measured on the wasm
/// (`a_claim_entry_and_its_growth_are_measured`), rounded up.
pub const CLAIM_ENTRY_BYTES: u32 = 300;
/// What each entry already in the list adds to a claim, in instructions:
/// about 34,000 measured, rounded up.
pub const CLAIM_ENTRY_INSTRUCTIONS: u32 = 40_000;
/// Slack on top, for everything else that can differ between simulation
/// and apply.
const CONTESTED_SLACK_BYTES: u32 = 512;
const CONTESTED_SLACK_INSTRUCTIONS: u32 = 100_000;

impl ContentionMargin {
    /// Room for `entries` claims landing before this one.
    pub fn for_claims(entries: u32) -> Self {
        ContentionMargin {
            extra_bytes: entries.saturating_mul(CLAIM_ENTRY_BYTES) + CONTESTED_SLACK_BYTES,
            extra_instructions: entries.saturating_mul(CLAIM_ENTRY_INSTRUCTIONS)
                + CONTESTED_SLACK_INSTRUCTIONS,
        }
    }
}
/// The resource fee raised to pay for the larger declaration: this
/// percentage, plus [`CONTESTED_FEE_FLAT`] stroops. The part not used is
/// refunded by the network.
const CONTESTED_FEE_PCT: i64 = 50;
const CONTESTED_FEE_FLAT: i64 = 20_000;

/// The largest resource fee this client will sign for, in stroops (5 XLM).
///
/// The fee came from the RPC's simulation and was attached unexamined, so
/// a lying or compromised endpoint could name any figure up to the u32
/// ceiling -- about 429 XLM -- and the client would sign it. A Soroban
/// invocation in this system costs a tiny fraction of this; the cap is set
/// well above anything legitimate so it never fires in normal use, and the
/// error says what was asked rather than silently paying it.
///
/// `as u32` was also a silent truncation: a fee above the u32 range
/// wrapped to a small one, which is the harmless direction but is not a
/// thing that should happen quietly either.
pub const DEFAULT_MAX_RESOURCE_FEE: u64 = 50_000_000;
const TX_TIMEOUT: Duration = Duration::from_secs(60);

/// What a simulation says a call would cost on the network.
///
/// The authoritative figure, and the only one that is. A contract test
/// meters a different host, and the difference does not go the
/// reassuring way: measured at 3 pairs on the deployed wasm, a Path-B
/// redemption costs 9,882,230 instructions in the test suite and
/// 13,052,010 here. The harness is not a ceiling on the network.
///
/// The cause is that cost parameters are a ledger entry, not a
/// compile-time table, so they differ per network and change by vote.
/// Testnet charges 706,689 + 4,229/byte for `VerifyEd25519Sig` where
/// mainnet charges 377,551 + 4,059. The ceiling these count against,
/// `tx_max_instructions`, is likewise on the ledger: 400,000,000 on
/// both networks when last fetched.
#[derive(Debug, Clone)]
pub struct SimResources {
    pub instructions: u32,
    pub disk_read_bytes: u32,
    pub write_bytes: u32,
    pub read_only_entries: usize,
    pub read_write_entries: usize,
    /// Stroops, as the RPC's `minResourceFee`.
    pub min_resource_fee: u64,
}

/// Builds, simulates, signs, and submits Soroban contract invocations.
pub struct TxBuilder {
    rpc: SorobanRpcClient,
    /// `None` for a read-only builder — see [`TxBuilder::read_only`].
    source_keypair: Option<StellarKeypair>,
    source_address: String,
    sequence: i64,
    /// The largest resource fee this builder will sign for, in stroops.
    max_resource_fee: u64,
}

pub struct InvokeResult {
    pub tx_hash: String,
    pub return_value: Option<ScVal>,
    pub ledger: Option<u64>,
}

impl TxBuilder {
    pub fn new(rpc: SorobanRpcClient, source_keypair: StellarKeypair) -> Self {
        let source_address = source_keypair.stellar_address();
        Self {
            rpc,
            source_keypair: Some(source_keypair),
            source_address,
            sequence: 0,
            max_resource_fee: DEFAULT_MAX_RESOURCE_FEE,
        }
    }

    /// A builder for reads, from an address whose secret is not available.
    ///
    /// `simulate_invoke` encodes the envelope **unsigned**, so a contract
    /// read needs the source account only for its sequence number — not for
    /// a signature. That matters because the obvious workaround, handing
    /// `new` a throwaway keypair, quietly breaks every such read: a random
    /// address has never been funded, has no sequence number, and
    /// `refresh_sequence` fails before the simulation is ever sent.
    ///
    /// So a caller that wants to read config from a contract while the
    /// user's key is locked away behind a passphrase uses this with the
    /// user's *address*. Signing is refused rather than faked.
    pub fn read_only(rpc: SorobanRpcClient, source_address: &str) -> Self {
        Self {
            rpc,
            source_keypair: None,
            source_address: source_address.to_string(),
            sequence: 0,
            max_resource_fee: DEFAULT_MAX_RESOURCE_FEE,
        }
    }

    /// Raise or lower the ceiling on the resource fee this builder signs.
    ///
    /// The default ([`DEFAULT_MAX_RESOURCE_FEE`]) is far above any
    /// legitimate invocation here. Raise it only where a caller has a
    /// reason, and can say what it is.
    pub fn with_max_resource_fee(mut self, stroops: u64) -> Self {
        self.max_resource_fee = stroops;
        self
    }

    pub fn max_resource_fee(&self) -> u64 {
        self.max_resource_fee
    }

    pub fn rpc(&self) -> &SorobanRpcClient {
        &self.rpc
    }

    pub fn source_address(&self) -> &str {
        &self.source_address
    }

    /// Fetch the current sequence number from the network.
    pub async fn refresh_sequence(&mut self) -> Result<(), ClientError> {
        self.sequence = self.rpc.get_account_sequence(&self.source_address).await?;
        debug!(sequence = self.sequence, "refreshed account sequence");
        Ok(())
    }

    /// Simulate a contract call without submitting. Returns the ScVal result.
    pub async fn simulate_invoke(
        &mut self,
        contract_id: &str,
        function: &str,
        args: Vec<ScVal>,
    ) -> Result<Option<ScVal>, ClientError> {
        if self.sequence == 0 {
            self.refresh_sequence().await?;
        }

        let tx = self.build_invoke_tx(contract_id, function, args)?;
        let tx_xdr = self.encode_envelope_unsigned(&tx)?;
        let sim = self.rpc.simulate(&tx_xdr).await?;

        match sim.return_value {
            Some(xdr_b64) => {
                let val = decode_scval(&xdr_b64)?;
                Ok(Some(val))
            }
            None => Ok(None),
        }
    }

    /// Simulate a read, without the sequence refresh.
    ///
    /// `simulate_invoke` takes `&mut self` only to cache a sequence number
    /// for a later submission. Simulation does not check one -- the RPC
    /// answers against current state whatever is in the field -- so a call
    /// that will never be submitted does not need it, and a `&self` read
    /// keeps `ChainRead` free of interior mutability.
    ///
    /// Worth having over a raw `getLedgerEntries` for one reason: the host
    /// restores archived entries before running the call, so this sees
    /// state that a direct read reports as absent.
    pub async fn simulate_invoke_ro(
        &self,
        contract_id: &str,
        function: &str,
        args: Vec<ScVal>,
    ) -> Result<Option<ScVal>, ClientError> {
        let tx = self.build_invoke_tx(contract_id, function, args)?;
        let tx_xdr = self.encode_envelope_unsigned(&tx)?;
        let sim = self.rpc.simulate(&tx_xdr).await?;
        match sim.return_value {
            Some(xdr_b64) => Ok(Some(decode_scval(&xdr_b64)?)),
            None => Ok(None),
        }
    }



    /// Simulate a call and report its resources, without submitting.
    ///
    /// The contract runs for real, against the live ledger, so a call
    /// that would fail fails here too. Nothing is submitted and no
    /// state moves, so the same call can be simulated again after a
    /// change and the two figures compared.
    ///
    /// About 0.69M instructions of what this reports is fixed
    /// per-transaction overhead, measured on no-argument calls to a
    /// deployed mint; the rest is the call.
    pub async fn simulate_resources(
        &self,
        contract_id: &str,
        function: &str,
        args: Vec<ScVal>,
    ) -> Result<SimResources, ClientError> {
        let tx = self.build_invoke_tx(contract_id, function, args)?;
        let tx_xdr = self.encode_envelope_unsigned(&tx)?;
        let sim = self.rpc.simulate(&tx_xdr).await?;

        let raw = base64::engine::general_purpose::STANDARD
            .decode(&sim.transaction_data)
            .map_err(|e| ClientError::XdrDecode(format!("sorobanData base64: {e}")))?;
        let data = SorobanTransactionData::from_xdr(raw, Limits::none())
            .map_err(|e| ClientError::XdrDecode(format!("sorobanData XDR: {e}")))?;
        let r = &data.resources;

        Ok(SimResources {
            instructions: r.instructions,
            disk_read_bytes: r.disk_read_bytes,
            write_bytes: r.write_bytes,
            read_only_entries: r.footprint.read_only.len(),
            read_write_entries: r.footprint.read_write.len(),
            min_resource_fee: sim.min_resource_fee,
        })
    }

    /// Full invoke cycle: build → simulate → assemble → sign → send → poll.
    ///
    /// On any error the cached sequence is forgotten, so the next call reads
    /// it from the ledger. Advancing it only on success is not enough: a
    /// transaction that was included and failed, or that landed after the
    /// poll gave up, consumes a sequence number too, and the cache would
    /// stay one behind, with every later call rejected as `txBadSeq` until
    /// the process restarted. A refresh costs one read and is right in
    /// every case, including the ones where nothing was sent.
    pub async fn invoke(
        &mut self,
        contract_id: &str,
        function: &str,
        args: Vec<ScVal>,
    ) -> Result<InvokeResult, ClientError> {
        let result = self.invoke_once(contract_id, function, args, None).await;
        if result.is_err() {
            self.sequence = 0;
        }
        result
    }

    /// [`Self::invoke`], declaring more storage than simulation saw.
    ///
    /// `widen` is shown the simulated footprint and returns keys to add to
    /// its read-write set. A call whose storage depends on a shared counter
    /// needs this: two calls simulated against the same counter declare the
    /// same keys, and the one applied second writes keys it never declared
    /// and traps (as `request_print` does). The resource fee rises by
    /// [`EXTRA_KEY_FEE`] per added key, and the declared fee and
    /// `minResourceFee` move together, so the consistency check in
    /// `assemble_transaction` still holds.
    pub async fn invoke_widened(
        &mut self,
        contract_id: &str,
        function: &str,
        args: Vec<ScVal>,
        widen: &(dyn Fn(&LedgerFootprint) -> Vec<LedgerKey> + Sync),
    ) -> Result<InvokeResult, ClientError> {
        let result = self.invoke_once(contract_id, function, args, Some(widen)).await;
        if result.is_err() {
            self.sequence = 0;
        }
        result
    }

    async fn invoke_once(
        &mut self,
        contract_id: &str,
        function: &str,
        args: Vec<ScVal>,
        widen: Option<&(dyn Fn(&LedgerFootprint) -> Vec<LedgerKey> + Sync)>,
    ) -> Result<InvokeResult, ClientError> {
        if self.sequence == 0 {
            self.refresh_sequence().await?;
        }

        // 1. Build the transaction
        let tx = self.build_invoke_tx(contract_id, function, args)?;
        let tx_xdr = self.encode_envelope_unsigned(&tx)?;

        debug!(%function, "simulating transaction");

        // 2. Simulate to get footprint + fees + auth
        let sim = self.rpc.simulate(&tx_xdr).await?;
        let sim = match widen {
            Some(widen) => with_extra_keys(&sim, widen)?,
            None => sim,
        };
        // A call whose path depends on the clock can take a longer branch
        // by the time it applies than when it was simulated: a cancel
        // simulated just before a print's beacon round is out applies
        // just after and burns the forfeit, a few dozen instructions over
        // what was simulated. A tenth more is nearly free.
        let sim = with_instruction_slack(&sim)?;

        // 3. Assemble: attach sorobanTransactionData + auth + updated fee
        let assembled = self.assemble_transaction(tx, &sim)?;

        // 4. Sign
        let signed_xdr = self.sign_transaction(&assembled)?;

        debug!(%function, "submitting transaction");

        // 5. Send
        let send_result = self.rpc.send_transaction(&signed_xdr).await?;

        debug!(hash = %send_result.hash, status = %send_result.status, "transaction sent");

        // 6. Poll for result
        let tx_result = self.rpc.poll_transaction(&send_result.hash, TX_TIMEOUT).await?;

        if tx_result.status != "SUCCESS" {
            return Err(ClientError::TransactionFailed {
                status: tx_result.status.clone(),
                detail: tx_result.result_xdr.clone().unwrap_or_default(),
            });
        }

        // Bump sequence for next call
        self.sequence += 1;

        // Parse return value
        let return_value = match tx_result.return_value {
            Some(ref xdr_b64) => Some(decode_scval(xdr_b64)?),
            None => None,
        };

        Ok(InvokeResult {
            tx_hash: send_result.hash,
            return_value,
            ledger: tx_result.ledger,
        })
    }

    /// Invoke a contract function that also needs `cosigner`'s
    /// authorization, as `claim_position` needs both members of a pair
    /// (see `docs/architecture/node-selection.md`).
    ///
    /// [`Self::invoke`] refuses any authorization entry for an address
    /// other than the source, and that rule stands for every other call.
    /// This is the one deliberate exception, and it is narrow:
    ///
    /// - **Exactly one** `Address` entry, and it must be the co-signer's.
    ///   An entry for anyone else, or a second one, is refused.
    /// - Its root must be **exactly the call being made** -- contract,
    ///   function and arguments -- with **nothing beneath it**. So the
    ///   co-signer authorises this one call and no transfer, unlike the
    ///   source, whose deposit or bond a call may move.
    /// - The source's own entries pass [`Self::check_auth_entry`] as usual.
    /// - The signature expires [`COSIGN_LEDGERS`] after the simulation's
    ///   ledger, so a signed entry withheld by an RPC is dead within
    ///   minutes.
    ///
    /// The transaction is then **simulated again with the signed entry in
    /// place**, which runs the network's own authorization check (enforcing
    /// mode) before anything is sent and gives resource figures that
    /// include verifying the signature.
    pub async fn invoke_cosigned(
        &mut self,
        contract_id: &str,
        function: &str,
        args: Vec<ScVal>,
        cosigner: &StellarKeypair,
        margin: ContentionMargin,
    ) -> Result<InvokeResult, ClientError> {
        let result = self
            .invoke_cosigned_once(contract_id, function, args, cosigner, margin)
            .await;
        if result.is_err() {
            self.sequence = 0;
        }
        result
    }

    async fn invoke_cosigned_once(
        &mut self,
        contract_id: &str,
        function: &str,
        args: Vec<ScVal>,
        cosigner: &StellarKeypair,
        margin: ContentionMargin,
    ) -> Result<InvokeResult, ClientError> {
        if self.sequence == 0 {
            self.refresh_sequence().await?;
        }
        let tx = self.build_invoke_tx(contract_id, function, args)?;
        let sim = self.rpc.simulate(&self.encode_envelope_unsigned(&tx)?).await?;

        let invoked = Self::invoked_args(&tx)?;
        let source = Self::source_scaddress(&self.source_address)?;
        let co_address = Self::source_scaddress(&cosigner.stellar_address())?;
        let expires = sim.latest_ledger.saturating_add(COSIGN_LEDGERS);

        let mut entries = Vec::new();
        let mut cosigned = false;
        for b64 in &sim.auth {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| ClientError::XdrDecode(format!("auth base64: {e}")))?;
            let mut entry = SorobanAuthorizationEntry::from_xdr(bytes, Limits::none())
                .map_err(|e| ClientError::XdrDecode(format!("auth XDR: {e}")))?;
            let is_cosigner = match &entry.credentials {
                SorobanCredentials::SourceAccount => false,
                SorobanCredentials::Address(c) if c.address == co_address && !cosigned => true,
                SorobanCredentials::Address(_) => {
                    return Err(ClientError::Other(
                        "simulation asked for an authorization from an address other than the                          co-signer, or for a second one; refusing to sign it"
                            .into(),
                    ));
                }
            };
            if !is_cosigner {
                Self::check_auth_entry(&entry, &invoked, &source)?;
                entries.push(entry);
                continue;
            }
            let root_ok = matches!(
                &entry.root_invocation.function,
                SorobanAuthorizedFunction::ContractFn(f) if f == &invoked
            );
            if !root_ok || !entry.root_invocation.sub_invocations.is_empty() {
                return Err(ClientError::Other(
                    "the co-signer was asked to authorise something other than exactly this                      call; refusing to sign it"
                        .into(),
                ));
            }
            self.sign_address_entry(&mut entry, cosigner, expires)?;
            cosigned = true;
            entries.push(entry);
        }
        if !cosigned {
            return Err(ClientError::Other(
                "simulation asked nothing of the co-signer; this call does not need one".into(),
            ));
        }

        // Re-simulate with the signed entries: enforcing mode, so the
        // network checks the signature before we pay to find out.
        let mut tx = tx;
        Self::set_auth(&mut tx, entries)?;
        let sim = self.rpc.simulate(&self.encode_envelope_unsigned(&tx)?).await?;
        // A claim writes to a slot other nodes are writing at the same
        // moment, so it declares room for them (`margin`).
        let sim = if margin == ContentionMargin::default() {
            sim
        } else {
            with_contention_margin(&sim, margin)?
        };
        let assembled = self.assemble_transaction(tx, &sim)?;
        let signed_xdr = self.sign_transaction(&assembled)?;
        let send_result = self.rpc.send_transaction(&signed_xdr).await?;
        let tx_result = self.rpc.poll_transaction(&send_result.hash, TX_TIMEOUT).await?;
        if tx_result.status != "SUCCESS" {
            return Err(ClientError::TransactionFailed {
                status: tx_result.status.clone(),
                detail: tx_result.result_xdr.clone().unwrap_or_default(),
            });
        }
        self.sequence += 1;
        let return_value = match tx_result.return_value {
            Some(ref xdr_b64) => Some(decode_scval(xdr_b64)?),
            None => None,
        };
        Ok(InvokeResult {
            tx_hash: send_result.hash,
            return_value,
            ledger: tx_result.ledger,
        })
    }

    /// Sign an `Address`-credential entry as `signer`: the Stellar account
    /// signature over `HashIdPreimage::SorobanAuthorization`, which binds the
    /// network, the entry's nonce, the expiry and the invocation.
    fn sign_address_entry(
        &self,
        entry: &mut SorobanAuthorizationEntry,
        signer: &StellarKeypair,
        expires: u32,
    ) -> Result<(), ClientError> {
        let SorobanCredentials::Address(ref mut creds) = entry.credentials else {
            return Err(ClientError::Other("not an address credential".into()));
        };
        let network_id = Hash(Sha256::digest(self.rpc.network_passphrase().as_bytes()).into());
        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id,
            nonce: creds.nonce,
            signature_expiration_ledger: expires,
            invocation: entry.root_invocation.clone(),
        });
        let payload = Sha256::digest(
            preimage
                .to_xdr(Limits::none())
                .map_err(|e| ClientError::XdrEncode(e.to_string()))?,
        );
        let sig = signer.sign(&payload).to_bytes();
        let public = signer.verifying_key().to_bytes();
        let bytes = |b: &[u8]| -> Result<ScVal, ClientError> {
            Ok(ScVal::Bytes(ScBytes(
                b.to_vec()
                    .try_into()
                    .map_err(|_| ClientError::XdrEncode("bytes".into()))?,
            )))
        };
        let sym = |s: &str| -> Result<ScVal, ClientError> {
            Ok(ScVal::Symbol(ScSymbol(
                s.try_into().map_err(|_| ClientError::XdrEncode("symbol".into()))?,
            )))
        };
        // An account's signature: a vec of `{public_key, signature}` maps,
        // keys in sorted order.
        let one = ScVal::Map(Some(ScMap(
            vec![
                ScMapEntry { key: sym("public_key")?, val: bytes(&public)? },
                ScMapEntry { key: sym("signature")?, val: bytes(&sig)? },
            ]
            .try_into()
            .map_err(|_| ClientError::XdrEncode("map".into()))?,
        )));
        creds.signature = ScVal::Vec(Some(ScVec(
            vec![one]
                .try_into()
                .map_err(|_| ClientError::XdrEncode("vec".into()))?,
        )));
        creds.signature_expiration_ledger = expires;
        Ok(())
    }

    /// The contract call a one-operation invoke transaction carries.
    fn invoked_args(tx: &Transaction) -> Result<InvokeContractArgs, ClientError> {
        match tx.operations.first().map(|o| &o.body) {
            Some(OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(args),
                ..
            })) => Ok(args.clone()),
            _ => Err(ClientError::Other("transaction calls no contract".into())),
        }
    }

    fn set_auth(tx: &mut Transaction, entries: Vec<SorobanAuthorizationEntry>) -> Result<(), ClientError> {
        let mut ops: Vec<Operation> = tx.operations.to_vec();
        if let Some(Operation {
            body: OperationBody::InvokeHostFunction(op),
            ..
        }) = ops.first_mut()
        {
            op.auth = entries
                .try_into()
                .map_err(|_| ClientError::Other("auth vec encode".into()))?;
        }
        tx.operations = ops
            .try_into()
            .map_err(|_| ClientError::Other("operations re-encode".into()))?;
        Ok(())
    }

    // ── Classic operations ──

    /// Does the source account already trust `code`/`issuer`?
    ///
    /// Read through `getLedgerEntries` rather than Horizon, so the client
    /// keeps one network dependency. A trustline is its own ledger entry, so
    /// its absence is simply an empty result.
    pub async fn has_trustline(&self, code: &str, issuer: &str) -> Result<bool, ClientError> {
        let key = self.trustline_ledger_key(code, issuer)?;
        Ok(!self.rpc.get_ledger_entries(&[key]).await?.is_empty())
    }

    /// Establish a trustline from the source account to `code`/`issuer`.
    ///
    /// Needed before the account can hold — or be *paid* — a classic asset.
    /// The second is what makes this more than a convenience: a redemption
    /// pays the holder, and a payout cannot reach an account with no
    /// trustline, so a holder without one can end up with good notes they
    /// cannot redeem.
    ///
    /// No simulation step: `ChangeTrust` is a classic operation, not a
    /// Soroban invocation, so there is no footprint to discover and no
    /// resource fee to add.
    ///
    /// `limit` is the maximum the account will hold, in stroops. `i64::MAX`
    /// means no limit, which is what a wallet wants — a limit exists to cap
    /// exposure to an issuer, and a holder who cannot receive their own
    /// redemption has been capped by accident.
    pub async fn change_trust(
        &mut self,
        code: &str,
        issuer: &str,
        limit: i64,
    ) -> Result<String, ClientError> {
        // Forget the sequence on failure, as `invoke` does and for the same
        // reason.
        let result = self.change_trust_once(code, issuer, limit).await;
        if result.is_err() {
            self.sequence = 0;
        }
        result
    }

    async fn change_trust_once(
        &mut self,
        code: &str,
        issuer: &str,
        limit: i64,
    ) -> Result<String, ClientError> {
        let op = Operation {
            source_account: None,
            body: OperationBody::ChangeTrust(ChangeTrustOp {
                line: ChangeTrustAsset::CreditAlphanum4(alpha_num4(code, issuer)?),
                limit,
            }),
        };
        self.submit_classic(op).await
    }

    /// Send `stroops` of XLM from the source account to `destination`.
    ///
    /// `create` makes it a `CreateAccount` (the destination does not exist
    /// yet, and `stroops` must cover its minimum balance); otherwise a
    /// plain native `Payment`. Like every submission here, the cached
    /// sequence is forgotten on failure.
    ///
    /// The node host uses this to fund a pair's partner from its own
    /// address, so an operator funds one address.
    pub async fn send_xlm(
        &mut self,
        destination: &str,
        stroops: i64,
        create: bool,
    ) -> Result<String, ClientError> {
        let dest = StellarPublic::from_string(destination)
            .map_err(|e| ClientError::InvalidAddress(format!("{destination}: {e}")))?;
        let account = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(dest.0)));
        let body = if create {
            OperationBody::CreateAccount(CreateAccountOp {
                destination: account,
                starting_balance: stroops,
            })
        } else {
            OperationBody::Payment(PaymentOp {
                destination: MuxedAccount::Ed25519(Uint256(dest.0)),
                asset: Asset::Native,
                amount: stroops,
            })
        };
        let result = self.submit_classic(Operation { source_account: None, body }).await;
        if result.is_err() {
            self.sequence = 0;
        }
        result
    }

    /// Build, sign, send and wait for a one-operation classic transaction.
    /// No simulation: classic operations have no footprint or resource fee.
    async fn submit_classic(&mut self, op: Operation) -> Result<String, ClientError> {
        if self.sequence == 0 {
            self.refresh_sequence().await?;
        }
        let source_pub = StellarPublic::from_string(&self.source_address)
            .map_err(|e| ClientError::InvalidAddress(format!("{e}")))?;
        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(source_pub.0)),
            fee: BASE_FEE,
            seq_num: SequenceNumber(self.sequence + 1),
            cond: Self::time_bounds(),
            memo: Memo::None,
            operations: vec![op]
                .try_into()
                .map_err(|_| ClientError::Other("operations encode".into()))?,
            ext: TransactionExt::V0,
        };

        let signed = self.sign_transaction(&tx)?;
        let sent = self.rpc.send_transaction(&signed).await?;
        let result = self.rpc.poll_transaction(&sent.hash, TX_TIMEOUT).await?;
        if result.status != "SUCCESS" {
            return Err(ClientError::TransactionFailed {
                status: result.status.clone(),
                detail: result.result_xdr.clone().unwrap_or_default(),
            });
        }
        self.sequence += 1;
        Ok(sent.hash)
    }

    fn trustline_ledger_key(&self, code: &str, issuer: &str) -> Result<String, ClientError> {
        let source_pub = StellarPublic::from_string(&self.source_address)
            .map_err(|e| ClientError::InvalidAddress(format!("{e}")))?;
        let an = alpha_num4(code, issuer)?;
        let key = LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(source_pub.0))),
            asset: TrustLineAsset::CreditAlphanum4(an),
        });
        let bytes = key
            .to_xdr(Limits::none())
            .map_err(|e| ClientError::XdrEncode(e.to_string()))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    // ── Internal: build transaction ──

    fn build_invoke_tx(
        &self,
        contract_id: &str,
        function: &str,
        args: Vec<ScVal>,
    ) -> Result<Transaction, ClientError> {
        let contract_hash = stellar_strkey::Contract::from_string(contract_id)
            .map_err(|e| ClientError::InvalidAddress(format!("bad contract ID: {e}")))?;

        let invoke_args = InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash(contract_hash.0))),
            function_name: ScSymbol(
                function
                    .try_into()
                    .map_err(|_| ClientError::Other("function name too long".into()))?,
            ),
            args: args
                .try_into()
                .map_err(|_| ClientError::Other("args encode".into()))?,
        };

        let source_pub = StellarPublic::from_string(&self.source_address)
            .map_err(|e| ClientError::InvalidAddress(format!("{e}")))?;

        let op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(invoke_args),
                auth: Default::default(),
            }),
        };

        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(source_pub.0)),
            fee: BASE_FEE,
            seq_num: SequenceNumber(self.sequence + 1),
            cond: Self::time_bounds(),
            memo: Memo::None,
            operations: vec![op]
                .try_into()
                .map_err(|_| ClientError::Other("operations encode".into()))?,
            ext: TransactionExt::V0,
        };

        Ok(tx)
    }

    /// How long a signed transaction stays submittable.
    ///
    /// `Preconditions::None` would mean forever -- or until the sequence
    /// number was used by something else, which may be never. A signed
    /// envelope handed to an RPC that simply withholds it could be
    /// submitted at any later moment of that RPC's choosing, against a
    /// ledger the signer never saw.
    ///
    /// The window has to cover build, sign and submit. On the card path
    /// signing means a PIN and a round trip to the reader, so a minute
    /// is uncomfortably tight; two is still short enough that "later"
    /// is not a strategy.
    const VALIDITY_SECONDS: u64 = 120;

    fn time_bounds() -> Preconditions {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Preconditions::Time(TimeBounds {
            // No lower bound: the point is an expiry, not a delay, and
            // a `min_time` in a clock-skewed future would reject the
            // signer's own transaction.
            min_time: TimePoint(0),
            max_time: TimePoint(now.saturating_add(Self::VALIDITY_SECONDS)),
        })
    }

    /// Whether an authorization entry from `simulateTransaction` is one
    /// this client is willing to sign for.
    ///
    /// Attaching entries exactly as the RPC returned them would let the
    /// RPC decide what the signature covers. Soroban's own semantics
    /// bound the damage -- an entry only satisfies a `require_auth` the
    /// contract actually makes -- but that is not a reason to sign
    /// whatever comes back.
    ///
    /// Two rules, both of which hold for every call Kenter makes:
    ///
    /// - **Source-account credentials only.** Every `require_auth` in
    ///   the mint and the roster is on the transaction source. An entry
    ///   with `Address` credentials carries its own signature and
    ///   authorises somebody else; this client never needs one and
    ///   should not pass one along unexamined.
    /// - **Contract calls only.** A `CreateContract` root invocation
    ///   would be authorising a deployment. Kenter deploys nothing from
    ///   a client.
    ///
    /// - **The call being made, and nothing else.** The root must be
    ///   exactly the invocation this transaction carries -- contract,
    ///   function and arguments. Beneath it, the only thing a Kenter call
    ///   ever authorises is a token `transfer` from this account to the
    ///   contract being called: the deposit in `request_print`, the bond
    ///   in `join`. Anything else is refused.
    ///
    /// The third rule does not reject the honest case: a SAC transfer is
    /// not rooted at itself. Recorded testnet simulations show
    /// `request_print` as the root with `transfer(depositor, mint, amount)`
    /// beneath it, and `join` as the root with
    /// `transfer(node, roster, min_stake)` beneath it. Without the rule, a
    /// simulation could hand back an entry for another contract's
    /// `transfer(signer, stranger, i128::MAX)` and the client would sign it.
    /// Soroban only consumes an entry a contract `require_auth`s, so that
    /// needed a contract that asks, which the reviewed mint and roster do
    /// not; this is what protects a client pointed at one that does.
    fn check_auth_entry(
        entry: &SorobanAuthorizationEntry,
        invoked: &InvokeContractArgs,
        source: &ScAddress,
    ) -> Result<(), ClientError> {
        match entry.credentials {
            SorobanCredentials::SourceAccount => {}
            SorobanCredentials::Address(_) => {
                return Err(ClientError::Other(
                    "simulation returned an authorization entry for another address; \
                     this client only signs for its own source account"
                        .into(),
                ));
            }
        }
        let root = match &entry.root_invocation.function {
            SorobanAuthorizedFunction::ContractFn(f) => f,
            _ => {
                return Err(ClientError::Other(
                    "simulation returned an authorization entry for a contract deployment; \
                     refusing to sign it"
                        .into(),
                ))
            }
        };
        if root != invoked {
            return Err(ClientError::Other(format!(
                "simulation returned an authorization entry for `{}` on another call \
                 than the one being made; refusing to sign it",
                root.function_name.0.to_utf8_string_lossy()
            )));
        }
        for sub in entry.root_invocation.sub_invocations.iter() {
            Self::check_sub_invocation(sub, &invoked.contract_address, source)?;
        }
        Ok(())
    }

    /// A sub-invocation this client will authorise: `transfer(source,
    /// called contract, amount)` on some token, with nothing beneath it.
    fn check_sub_invocation(
        sub: &SorobanAuthorizedInvocation,
        called: &ScAddress,
        source: &ScAddress,
    ) -> Result<(), ClientError> {
        let refuse = |why: &str| {
            Err(ClientError::Other(format!(
                "simulation asked this account to authorise {why}; refusing to sign it"
            )))
        };
        let SorobanAuthorizedFunction::ContractFn(f) = &sub.function else {
            return refuse("a contract deployment");
        };
        if f.function_name.0.as_slice() != b"transfer" {
            return refuse(&format!(
                "`{}` beneath the call",
                f.function_name.0.to_utf8_string_lossy()
            ));
        }
        let ok = matches!(
            f.args.as_slice(),
            [ScVal::Address(from), ScVal::Address(to), ScVal::I128(_)]
                if from == source && to == called
        );
        if !ok {
            return refuse("a transfer other than from itself to the contract it is calling");
        }
        if !sub.sub_invocations.is_empty() {
            return refuse("calls nested beneath a transfer");
        }
        Ok(())
    }

    fn assemble_transaction(
        &self,
        mut tx: Transaction,
        sim: &crate::rpc::SimulateResult,
    ) -> Result<Transaction, ClientError> {
        // Parse sorobanTransactionData
        let soroban_data_bytes = base64::engine::general_purpose::STANDARD
            .decode(&sim.transaction_data)
            .map_err(|e| ClientError::XdrDecode(format!("sorobanData base64: {e}")))?;
        let soroban_data = SorobanTransactionData::from_xdr(soroban_data_bytes, Limits::none())
            .map_err(|e| ClientError::XdrDecode(format!("sorobanData XDR: {e}")))?;

        // Attach soroban data
        // Read before the move: this is the figure the signature will
        // actually commit to.
        let committed = soroban_data.resource_fee;
        tx.ext = TransactionExt::V1(soroban_data);

        // Update fee: base_fee + resource_fee, but only up to what this
        // client agreed to sign. The figure is the RPC's, not ours.
        let asked = sim.min_resource_fee;
        if asked > self.max_resource_fee {
            return Err(ClientError::FeeTooHigh { asked, cap: self.max_resource_fee });
        }

        // The two numbers the RPC sent have to agree with each other.
        //
        // `minResourceFee` is what we are told the call costs;
        // `sorobanData.resourceFee` is what the signed envelope actually
        // commits to paying, and only the second one is covered by the
        // signature. Checking one and signing the other is not a check.
        if committed < 0 || committed as u64 != asked {
            return Err(ClientError::Other(format!(
                "simulation disagrees with itself: minResourceFee is {asked} but the \
                 transaction data commits to {committed}"
            )));
        }

        // Truncation would be silent otherwise: the cap is a u64 and the
        // field is a u32, so a large enough fee could wrap into a small
        // one and sail past a check it never really passed.
        let fee = u32::try_from(asked)
            .ok()
            .and_then(|f| BASE_FEE.checked_add(f))
            .ok_or_else(|| ClientError::Other(format!(
                "resource fee {asked} does not fit in a transaction fee field"
            )))?;
        tx.fee = fee;

        // Attach auth entries to the operation -- unless the transaction
        // already carries its own, which `invoke_cosigned` checked and
        // signed before re-simulating. Those are what the signatures cover;
        // replacing them with the RPC's would undo the check.
        let has_auth = matches!(
            tx.operations.first().map(|o| &o.body),
            Some(OperationBody::InvokeHostFunction(op)) if !op.auth.is_empty()
        );
        if !sim.auth.is_empty() && !has_auth {
            let mut ops: Vec<Operation> = tx.operations.to_vec();
            // What this transaction calls, and who signs it: an entry is
            // checked against these, never against itself.
            let invoked = match &ops[0].body {
                OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                    host_function: HostFunction::InvokeContract(args),
                    ..
                }) => args.clone(),
                _ => {
                    return Err(ClientError::Other(
                        "simulation returned authorization for a transaction that calls no contract"
                            .into(),
                    ))
                }
            };
            let source = Self::source_scaddress(&self.source_address)?;
            if let OperationBody::InvokeHostFunction(ref mut op) = ops[0].body {
                let mut auth_entries = Vec::new();
                for auth_b64 in &sim.auth {
                    let auth_bytes = base64::engine::general_purpose::STANDARD
                        .decode(auth_b64)
                        .map_err(|e| ClientError::XdrDecode(format!("auth base64: {e}")))?;
                    let entry =
                        SorobanAuthorizationEntry::from_xdr(auth_bytes, Limits::none())
                            .map_err(|e| ClientError::XdrDecode(format!("auth XDR: {e}")))?;
                    Self::check_auth_entry(&entry, &invoked, &source)?;
                    auth_entries.push(entry);
                }
                op.auth = auth_entries
                    .try_into()
                    .map_err(|_| ClientError::Other("auth vec encode".into()))?;
            }
            tx.operations = ops
                .try_into()
                .map_err(|_| ClientError::Other("operations re-encode".into()))?;
        }

        Ok(tx)
    }

    fn source_scaddress(address: &str) -> Result<ScAddress, ClientError> {
        let pk = StellarPublic::from_string(address)
            .map_err(|e| ClientError::InvalidAddress(format!("{e}")))?;
        Ok(ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk.0)))))
    }

    fn encode_envelope_unsigned(&self, tx: &Transaction) -> Result<String, ClientError> {
        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: tx.clone(),
            signatures: Default::default(),
        });
        let xdr_bytes = envelope
            .to_xdr(Limits::none())
            .map_err(|e| ClientError::XdrEncode(format!("{e}")))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&xdr_bytes))
    }

    fn sign_transaction(&self, tx: &Transaction) -> Result<String, ClientError> {
        // Hash the transaction for signing: SHA256(network_passphrase_hash + ENVELOPE_TYPE_TX + tx_xdr)
        let network_hash = Sha256::digest(self.rpc.network_passphrase().as_bytes());

        let tx_xdr = tx
            .to_xdr(Limits::none())
            .map_err(|e| ClientError::XdrEncode(format!("{e}")))?;

        let mut preimage = Vec::new();
        preimage.extend_from_slice(&network_hash);
        // ENVELOPE_TYPE_TX = 2
        preimage.extend_from_slice(&2u32.to_be_bytes());
        preimage.extend_from_slice(&tx_xdr);

        let tx_hash = Sha256::digest(&preimage);

        // Sign with Ed25519
        let keypair = self.source_keypair.as_ref().ok_or_else(|| {
            ClientError::InvalidAddress(
                "this TxBuilder is read-only and cannot sign — build it with `new`".into(),
            )
        })?;
        let sig_bytes = keypair.sign(&tx_hash);

        // Build decorated signature
        let source_pub = StellarPublic::from_string(&self.source_address)
            .map_err(|e| ClientError::InvalidAddress(format!("{e}")))?;
        let hint_bytes: [u8; 4] = source_pub.0[28..32].try_into().unwrap();

        let decorated = DecoratedSignature {
            hint: SignatureHint(hint_bytes),
            signature: Signature(
                sig_bytes
                    .to_vec()
                    .try_into()
                    .map_err(|_| ClientError::Other("signature encode".into()))?,
            ),
        };

        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: tx.clone(),
            signatures: vec![decorated]
                .try_into()
                .map_err(|_| ClientError::Other("signatures encode".into()))?,
        });

        let xdr_bytes = envelope
            .to_xdr(Limits::none())
            .map_err(|e| ClientError::XdrEncode(format!("{e}")))?;

        Ok(base64::engine::general_purpose::STANDARD.encode(&xdr_bytes))
    }
}

// ── ScVal conversion helpers ──

/// A 4-character asset code with its issuer.
///
/// Only Alphanum4 for now: USDC, EURC and every stablecoin this is likely to
/// escrow fit. A longer code needs Alphanum12 and is refused rather than
/// silently truncated, because a truncated code names a *different asset*.
fn alpha_num4(code: &str, issuer: &str) -> Result<AlphaNum4, ClientError> {
    if code.is_empty() || code.len() > 4 {
        return Err(ClientError::Other(format!(
            "asset code {code:?} is not 1-4 characters; Alphanum12 is not supported yet"
        )));
    }
    let mut bytes = [0u8; 4];
    bytes[..code.len()].copy_from_slice(code.as_bytes());
    let issuer_pub = StellarPublic::from_string(issuer)
        .map_err(|e| ClientError::InvalidAddress(format!("bad issuer: {e}")))?;
    Ok(AlphaNum4 {
        asset_code: AssetCode4(bytes),
        issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(issuer_pub.0))),
    })
}

/// The exact bytes the mint hashes when binding a redemption's recipient.
///
/// `soroban_sdk::Address::to_xdr` serializes the address as an `ScVal`, so
/// this is that same XDR. It has to match byte for byte: the owner's
/// signature covers these bytes, and a mismatch would not surface until a
/// real spend-mode redemption failed on a live ledger. The mint pins the
/// same constant in its own tests.
pub fn address_xdr(stellar_address: &str) -> Result<Vec<u8>, ClientError> {
    address_to_scval(stellar_address)?
        .to_xdr(Limits::none())
        .map_err(|e| ClientError::XdrEncode(e.to_string()))
}

pub fn address_to_scval(stellar_address: &str) -> Result<ScVal, ClientError> {
    // Detect contract address (C...) vs account address (G...)
    if stellar_address.starts_with('C') {
        let contract = stellar_strkey::Contract::from_string(stellar_address)
            .map_err(|e| ClientError::InvalidAddress(format!("{e}")))?;
        Ok(ScVal::Address(ScAddress::Contract(ContractId(Hash(
            contract.0,
        )))))
    } else {
        let pub_key = StellarPublic::from_string(stellar_address)
            .map_err(|e| ClientError::InvalidAddress(format!("{e}")))?;
        Ok(ScVal::Address(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256(pub_key.0)),
        ))))
    }
}

pub fn bytes32_to_scval(bytes: [u8; 32]) -> ScVal {
    ScVal::Bytes(ScBytes(bytes.to_vec().try_into().unwrap()))
}

/// `sim` with the margin a contested write needs: more write and read bytes
/// and instructions than simulation saw, and a resource fee raised to pay
/// for them. The declared figures and the fee move together, so
/// `assemble_transaction`'s consistency check still holds.
pub(crate) fn with_contention_margin(
    sim: &crate::rpc::SimulateResult,
    margin: ContentionMargin,
) -> Result<crate::rpc::SimulateResult, ClientError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&sim.transaction_data)
        .map_err(|e| ClientError::XdrDecode(format!("sorobanData base64: {e}")))?;
    let mut data = SorobanTransactionData::from_xdr(raw, Limits::none())
        .map_err(|e| ClientError::XdrDecode(format!("sorobanData XDR: {e}")))?;
    let r = &mut data.resources;
    r.write_bytes = r.write_bytes.saturating_add(margin.extra_bytes);
    r.disk_read_bytes = r.disk_read_bytes.saturating_add(margin.extra_bytes);
    r.instructions = r.instructions.saturating_add(margin.extra_instructions);
    data.resource_fee = data
        .resource_fee
        .saturating_mul(100 + CONTESTED_FEE_PCT)
        / 100
        + CONTESTED_FEE_FLAT;
    let fee = data.resource_fee;
    let encoded = data
        .to_xdr(Limits::none())
        .map_err(|e| ClientError::XdrEncode(e.to_string()))?;
    let mut out = sim.clone();
    out.transaction_data = base64::engine::general_purpose::STANDARD.encode(encoded);
    out.min_resource_fee = fee.max(0) as u64;
    Ok(out)
}

/// What each storage key added by [`TxBuilder::invoke_widened`] adds to the
/// resource fee, in stroops: a declared read-write entry is charged a write
/// (1,250) and a read (781) whether or not it is touched, its key's bytes in
/// the transaction, and the write-byte margin below at 437 a kilobyte.
/// Rounded up; the unused part is refunded only where the network refunds
/// it.
pub const EXTRA_KEY_FEE: i64 = 3_000;

/// What each added key adds to the declared instructions. Loading a
/// footprint entry costs host work the simulation, run without it, never
/// saw, and an entry that **exists** by the time the call applies -- a
/// neighbouring slot another request wrote earlier in the same ledger --
/// costs far more than an absent one, since it is read and decoded.
/// Measured on testnet: 8 absent keys added about 102,700 instructions to
/// a `request_print`; with neighbours already written, 200,000 of margin
/// was still short. Compute is nearly free (10,000 instructions cost 3
/// stroops, 400M is the per-transaction limit), so this is generous.
pub const EXTRA_KEY_INSTRUCTIONS: u32 = 150_000;

/// What each added key adds to the declared write bytes.
/// The network counts every read-write entry that exists when the call
/// applies as written, changed or not, so a request landing after another
/// in the same ledger is charged for that request's slot (an 868-byte core
/// and a 500-byte draw): measured on testnet, 2,808 bytes written against
/// 1,940 declared. One kilobyte a key covers either.
pub const EXTRA_KEY_WRITE_BYTES: u32 = 1_000;

/// The share of simulated instructions added to every ordinary call.
pub const INSTRUCTION_SLACK_PCT: u32 = 10;

/// `sim` with [`INSTRUCTION_SLACK_PCT`] more instructions declared and the
/// fee raised to cover them (3 stroops per 10,000, rounded up, plus one).
pub(crate) fn with_instruction_slack(
    sim: &crate::rpc::SimulateResult,
) -> Result<crate::rpc::SimulateResult, ClientError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&sim.transaction_data)
        .map_err(|e| ClientError::XdrDecode(format!("sorobanData base64: {e}")))?;
    let mut data = SorobanTransactionData::from_xdr(raw, Limits::none())
        .map_err(|e| ClientError::XdrDecode(format!("sorobanData XDR: {e}")))?;
    // Never past the network's per-transaction limit (400M on both networks
    // today), or a call simulated near it would be refused outright.
    const TX_MAX_INSTRUCTIONS: u32 = 400_000_000;
    let extra = (data.resources.instructions / 100 * INSTRUCTION_SLACK_PCT)
        .min(TX_MAX_INSTRUCTIONS.saturating_sub(data.resources.instructions));
    if extra == 0 {
        return Ok(sim.clone());
    }
    data.resources.instructions = data.resources.instructions.saturating_add(extra);
    data.resource_fee = data.resource_fee.saturating_add(i64::from(extra) * 3 / 10_000 + 1);
    let fee = data.resource_fee;
    let encoded = data
        .to_xdr(Limits::none())
        .map_err(|e| ClientError::XdrEncode(e.to_string()))?;
    let mut out = sim.clone();
    out.transaction_data = base64::engine::general_purpose::STANDARD.encode(encoded);
    out.min_resource_fee = fee.max(0) as u64;
    Ok(out)
}

/// `sim` with `widen`'s keys added to the read-write footprint (those not
/// already declared), and the resource fee raised to pay for them.
pub(crate) fn with_extra_keys(
    sim: &crate::rpc::SimulateResult,
    widen: &(dyn Fn(&LedgerFootprint) -> Vec<LedgerKey> + Sync),
) -> Result<crate::rpc::SimulateResult, ClientError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&sim.transaction_data)
        .map_err(|e| ClientError::XdrDecode(format!("sorobanData base64: {e}")))?;
    let mut data = SorobanTransactionData::from_xdr(raw, Limits::none())
        .map_err(|e| ClientError::XdrDecode(format!("sorobanData XDR: {e}")))?;
    let fp = &data.resources.footprint;
    let mut rw: Vec<LedgerKey> = fp.read_write.to_vec();
    let mut added = 0i64;
    for key in widen(fp) {
        if !rw.contains(&key) && !fp.read_only.contains(&key) {
            rw.push(key);
            added += 1;
        }
    }
    if added == 0 {
        return Ok(sim.clone());
    }
    data.resources.footprint.read_write = rw
        .try_into()
        .map_err(|_| ClientError::XdrEncode("footprint too large".into()))?;
    data.resources.instructions = data
        .resources
        .instructions
        .saturating_add(added as u32 * EXTRA_KEY_INSTRUCTIONS);
    data.resources.write_bytes = data
        .resources
        .write_bytes
        .saturating_add(added as u32 * EXTRA_KEY_WRITE_BYTES);
    data.resource_fee = data.resource_fee.saturating_add(added * EXTRA_KEY_FEE);
    let fee = data.resource_fee;
    let encoded = data
        .to_xdr(Limits::none())
        .map_err(|e| ClientError::XdrEncode(e.to_string()))?;
    let mut out = sim.clone();
    out.transaction_data = base64::engine::general_purpose::STANDARD.encode(encoded);
    out.min_resource_fee = fee.max(0) as u64;
    Ok(out)
}

/// Encode a 64-byte value (e.g. an Ed25519 signature `BytesN<64>`) as `ScVal::Bytes`.
pub fn bytes64_to_scval(bytes: [u8; 64]) -> ScVal {
    ScVal::Bytes(ScBytes(bytes.to_vec().try_into().unwrap()))
}

pub fn bytes_to_scval(bytes: &[u8]) -> ScVal {
    ScVal::Bytes(ScBytes(bytes.to_vec().try_into().unwrap()))
}

pub fn i128_to_scval(val: i128) -> ScVal {
    ScVal::I128(Int128Parts {
        hi: (val >> 64) as i64,
        lo: val as u64,
    })
}

pub fn u32_to_scval(val: u32) -> ScVal {
    ScVal::U32(val)
}

pub fn string_to_scval(s: &str) -> Result<ScVal, ClientError> {
    Ok(ScVal::String(ScString(
        s.try_into()
            .map_err(|_| ClientError::Other("string too long".into()))?,
    )))
}

pub fn bool_to_scval(val: bool) -> ScVal {
    ScVal::Bool(val)
}

/// Encode a Soroban `Option<T>` argument: `None` is `Void`, `Some(v)` is
/// `v` itself.
///
/// Not `Vec([v])` / `Vec([])`: the host refuses to convert those to
/// `Option<T>`, so every call through such an encoding traps
/// (`Error(WasmVm, InvalidAction)`). Its one caller is `update_node`.
pub fn option_to_scval(val: Option<ScVal>) -> ScVal {
    val.unwrap_or(ScVal::Void)
}

/// Build a PairEntry struct value for the mint contract.
pub fn pair_entry_to_scval(node_a: &str, node_b: &str) -> Result<ScVal, ClientError> {
    let entries = vec![
        ScMapEntry {
            key: ScVal::Symbol(ScSymbol("node_a".try_into().unwrap())),
            val: address_to_scval(node_a)?,
        },
        ScMapEntry {
            key: ScVal::Symbol(ScSymbol("node_b".try_into().unwrap())),
            val: address_to_scval(node_b)?,
        },
    ];
    Ok(ScVal::Map(Some(ScMap(entries.try_into().unwrap()))))
}

// ── ScVal decoding helpers ──

/// Decode a contract or account address back to its strkey form.
///
/// The inverse of [`address_to_scval`], needed because reading a contract's
/// configuration gets `Address` values back — `pay_token` and `roster` both.
pub fn scval_to_address(val: &ScVal) -> Result<String, ClientError> {
    match val {
        ScVal::Address(ScAddress::Contract(ContractId(Hash(h)))) => {
            Ok(stellar_strkey::Contract(*h).to_string().to_string())
        }
        ScVal::Address(ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(
            Uint256(k),
        )))) => Ok(StellarPublic(*k).to_string().to_string()),
        other => Err(ClientError::XdrDecode(format!(
            "expected an address, got {other:?}"
        ))),
    }
}

pub fn scval_to_u32(val: &ScVal) -> Result<u32, ClientError> {
    match val {
        ScVal::U32(v) => Ok(*v),
        _ => Err(ClientError::XdrDecode(format!("expected U32, got {val:?}"))),
    }
}

pub fn scval_to_i128(val: &ScVal) -> Result<i128, ClientError> {
    match val {
        ScVal::I128(parts) => Ok(((parts.hi as i128) << 64) | (parts.lo as i128)),
        _ => Err(ClientError::XdrDecode(format!(
            "expected I128, got {val:?}"
        ))),
    }
}

pub fn scval_to_bool(val: &ScVal) -> Result<bool, ClientError> {
    match val {
        ScVal::Bool(v) => Ok(*v),
        _ => Err(ClientError::XdrDecode(format!(
            "expected Bool, got {val:?}"
        ))),
    }
}

pub fn scval_to_bytes32(val: &ScVal) -> Result<[u8; 32], ClientError> {
    match val {
        ScVal::Bytes(b) => {
            let slice: &[u8] = b.as_ref();
            slice.try_into().map_err(|_| {
                ClientError::XdrDecode(format!("expected 32 bytes, got {}", slice.len()))
            })
        }
        _ => Err(ClientError::XdrDecode(format!(
            "expected Bytes, got {val:?}"
        ))),
    }
}

/// Decode base64 XDR to ScVal.
pub fn decode_scval(xdr_b64: &str) -> Result<ScVal, ClientError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(xdr_b64)
        .map_err(|e| ClientError::XdrDecode(format!("base64: {e}")))?;
    ScVal::from_xdr(bytes, Limits::none())
        .map_err(|e| ClientError::XdrDecode(format!("ScVal XDR: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_to_scval_account() {
        let val =
            address_to_scval("GD3GEVSYK6HEPGEGOGCRJZCBD7W2CDAIVIMYKOMWB3LKWONBQAD5EC5P")
                .unwrap();
        assert!(matches!(val, ScVal::Address(ScAddress::Account(_))));
    }

    #[test]
    fn test_address_to_scval_contract() {
        let val =
            address_to_scval("CA26Y3TIFELNFJT2J2VPYGJO6PELJMEBERQWMJHRNBAJQKEM2QWLXHGZ")
                .unwrap();
        assert!(matches!(val, ScVal::Address(ScAddress::Contract(_))));
    }

    #[test]
    fn test_i128_roundtrip() {
        let val = 1_000_000_i128;
        let sc = i128_to_scval(val);
        assert_eq!(scval_to_i128(&sc).unwrap(), val);
    }

    #[test]
    fn test_pair_entry_encoding() {
        let val = pair_entry_to_scval(
            "GD3GEVSYK6HEPGEGOGCRJZCBD7W2CDAIVIMYKOMWB3LKWONBQAD5EC5P",
            "GCXHFH6CDOP4UKKZJPFAVT3A6BYHZHFADDJBOZUUB3NMO2FWZJ55N5GL",
        )
        .unwrap();
        assert!(matches!(val, ScVal::Map(_)));
    }

    /// Pinned against the mint's own test. If these diverge, every
    /// spend-mode redemption would fail on a live ledger and nowhere else.
    #[test]
    fn address_xdr_matches_what_the_mint_hashes() {
        let got = hex::encode(address_xdr("GALMHEXVYCGR3DIEJJGVF7DRP2Y5HSXAI7RTV6FBQIXW7LQ2YOKWP5LR").unwrap());
        assert_eq!(got, "00000012000000000000000016c392f5c08d1d8d044a4d52fc717eb1d3cae047e33af8a1822f6fae1ac39567");
    }
}

#[cfg(test)]
mod precondition_tests {
    use super::*;
    use stellar_xdr::curr::{
        ContractExecutable, ContractIdPreimage, ContractIdPreimageFromAddress,
        CreateContractArgs, SorobanAddressCredentials, SorobanAuthorizedInvocation,
    };

    fn mint_call() -> InvokeContractArgs {
        InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash([7u8; 32]))),
            function_name: ScSymbol("spend".try_into().unwrap()),
            args: Default::default(),
        }
    }

    fn me() -> ScAddress {
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([5u8; 32]))))
    }

    fn contract_fn_entry(creds: SorobanCredentials) -> SorobanAuthorizationEntry {
        SorobanAuthorizationEntry {
            credentials: creds,
            root_invocation: SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(mint_call()),
                sub_invocations: Default::default(),
            },
        }
    }

    fn transfer(token: u8, from: ScAddress, to: ScAddress, amount: i128) -> SorobanAuthorizedInvocation {
        SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([token; 32]))),
                function_name: ScSymbol("transfer".try_into().unwrap()),
                args: vec![ScVal::Address(from), ScVal::Address(to), i128_to_scval(amount)]
                    .try_into()
                    .unwrap(),
            }),
            sub_invocations: Default::default(),
        }
    }

    fn with_subs(subs: Vec<SorobanAuthorizedInvocation>) -> SorobanAuthorizationEntry {
        let mut e = contract_fn_entry(SorobanCredentials::SourceAccount);
        e.root_invocation.sub_invocations = subs.try_into().unwrap();
        e
    }

    fn check(e: &SorobanAuthorizationEntry) -> Result<(), ClientError> {
        TxBuilder::check_auth_entry(e, &mint_call(), &me())
    }

    /// The honest shape, as recorded from testnet for `request_print` and
    /// `join`: the call at the root, the deposit beneath it.
    #[test]
    fn the_call_with_its_own_deposit_beneath_it_is_accepted() {
        let e = with_subs(vec![transfer(1, me(), mint_call().contract_address, 1_000_000)]);
        assert!(check(&e).is_ok());
    }

    /// An entry rooted at another contract's
    /// `transfer(signer, stranger, i128::MAX)`.
    #[test]
    fn an_entry_for_another_call_is_refused() {
        let stranger = ScAddress::Contract(ContractId(Hash([0xEE; 32])));
        let SorobanAuthorizedFunction::ContractFn(f) = transfer(1, me(), stranger, i128::MAX).function
        else {
            unreachable!()
        };
        let mut e = contract_fn_entry(SorobanCredentials::SourceAccount);
        e.root_invocation.function = SorobanAuthorizedFunction::ContractFn(f);
        assert!(check(&e).is_err());
    }

    /// The right function on the right contract with other arguments is
    /// another call.
    #[test]
    fn the_same_function_with_other_arguments_is_refused() {
        let mut call = mint_call();
        call.args = vec![ScVal::U32(1)].try_into().unwrap();
        let mut e = contract_fn_entry(SorobanCredentials::SourceAccount);
        e.root_invocation.function = SorobanAuthorizedFunction::ContractFn(call);
        assert!(check(&e).is_err());
    }

    /// Beneath the call, a transfer anywhere but to the contract being
    /// called, a call that is not a transfer, or anything nested under the
    /// transfer, is refused.
    #[test]
    fn a_sub_invocation_other_than_the_deposit_is_refused() {
        let stranger = ScAddress::Contract(ContractId(Hash([0xEE; 32])));
        assert!(check(&with_subs(vec![transfer(1, me(), stranger, 5)])).is_err());

        let mut not_transfer = transfer(1, me(), mint_call().contract_address, 5);
        if let SorobanAuthorizedFunction::ContractFn(f) = &mut not_transfer.function {
            f.function_name = ScSymbol("approve".try_into().unwrap());
        }
        assert!(check(&with_subs(vec![not_transfer])).is_err());

        let mut nested = transfer(1, me(), mint_call().contract_address, 5);
        nested.sub_invocations = vec![transfer(2, me(), mint_call().contract_address, 5)]
            .try_into()
            .unwrap();
        assert!(check(&with_subs(vec![nested])).is_err());
    }

    /// **Custody R1.** A transaction stops being submittable.
    ///
    /// `Preconditions::None` meant a signed envelope stayed valid until
    /// its sequence number was consumed — which may be never — so an
    /// RPC that simply withheld it could submit it whenever suited.
    #[test]
    fn a_built_transaction_expires() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        match TxBuilder::time_bounds() {
            Preconditions::Time(tb) => {
                assert_eq!(tb.min_time.0, 0, "an expiry, not a delay");
                assert!(tb.max_time.0 > now, "already expired");
                assert!(
                    tb.max_time.0 <= now + TxBuilder::VALIDITY_SECONDS + 2,
                    "the window must stay short"
                );
            }
            other => panic!("expected time bounds, got {other:?}"),
        }
    }

    /// Source-account credentials are what every Kenter call needs.
    #[test]
    fn a_source_account_entry_is_accepted() {
        let e = contract_fn_entry(SorobanCredentials::SourceAccount);
        assert!(check(&e).is_ok());
    }

    /// **Custody R1.** An entry authorising some other address is not
    /// something this client passes along unexamined.
    #[test]
    fn an_address_credential_entry_is_refused() {
        let e = contract_fn_entry(SorobanCredentials::Address(SorobanAddressCredentials {
            address: ScAddress::Contract(ContractId(Hash([9u8; 32]))),
            nonce: 1,
            signature_expiration_ledger: 100,
            signature: ScVal::Void,
        }));
        assert!(check(&e).is_err());
    }

    /// Nor one that would authorise deploying a contract. A client
    /// deploys nothing.
    #[test]
    fn a_contract_creation_entry_is_refused() {
        let e = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::SourceAccount,
            root_invocation: SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::CreateContractHostFn(CreateContractArgs {
                    contract_id_preimage: ContractIdPreimage::Address(
                        ContractIdPreimageFromAddress {
                            address: ScAddress::Contract(ContractId(Hash([1u8; 32]))),
                            salt: Uint256([2u8; 32]),
                        },
                    ),
                    executable: ContractExecutable::Wasm(Hash([3u8; 32])),
                }),
                sub_invocations: Default::default(),
            },
        };
        assert!(check(&e).is_err());
    }
}

#[cfg(test)]
mod contention_tests {
    use super::*;
    use stellar_xdr::curr::{ExtensionPoint, LedgerFootprint, SorobanResources, SorobanTransactionDataExt};

    fn sim(fee: i64) -> crate::rpc::SimulateResult {
        let data = SorobanTransactionData {
            ext: SorobanTransactionDataExt::V0,
            resources: SorobanResources {
                footprint: LedgerFootprint { read_only: Default::default(), read_write: Default::default() },
                instructions: 2_000_000,
                disk_read_bytes: 0,
                write_bytes: 1_500,
            },
            resource_fee: fee,
        };
        let _ = ExtensionPoint::V0;
        crate::rpc::SimulateResult {
            transaction_data: base64::engine::general_purpose::STANDARD
                .encode(data.to_xdr(Limits::none()).unwrap()),
            min_resource_fee: fee as u64,
            auth: vec![],
            return_value: None,
            latest_ledger: 1,
        }
    }

    /// A contested claim declares room for the claims that land before it,
    /// and pays for it -- and the figure signed is the figure declared, so
    /// `assemble_transaction`'s check still passes.
    #[test]
    fn a_contested_call_declares_room_and_pays_for_it() {
        // The worst case at the contract's ceiling: k = 10, nothing seen,
        // so 2k = 20 claims could land first.
        let m = ContentionMargin::for_claims(20);
        let out = with_contention_margin(&sim(60_000), m).unwrap();
        let raw = base64::engine::general_purpose::STANDARD.decode(&out.transaction_data).unwrap();
        let d = SorobanTransactionData::from_xdr(raw, Limits::none()).unwrap();
        assert_eq!(d.resources.write_bytes, 1_500 + 20 * CLAIM_ENTRY_BYTES + 512);
        assert_eq!(d.resources.disk_read_bytes, 20 * CLAIM_ENTRY_BYTES + 512);
        assert_eq!(d.resources.instructions, 2_000_000 + 20 * CLAIM_ENTRY_INSTRUCTIONS + 100_000);
        assert_eq!(d.resource_fee, 60_000 * 3 / 2 + CONTESTED_FEE_FLAT);
        assert_eq!(out.min_resource_fee, d.resource_fee as u64, "declared and signed agree");
    }

    fn key(n: u32) -> LedgerKey {
        LedgerKey::ContractData(stellar_xdr::curr::LedgerKeyContractData {
            contract: ScAddress::Contract(ContractId(Hash([7; 32]))),
            key: ScVal::U32(n),
            durability: stellar_xdr::curr::ContractDataDurability::Persistent,
        })
    }

    /// A widened call declares the extra keys once each, pays for exactly
    /// those it added, and still signs the fee it declares.
    #[test]
    fn a_widened_call_declares_its_extra_keys_and_pays_for_them() {
        let widen = |_: &LedgerFootprint| vec![key(1), key(2), key(1)];
        let out = with_extra_keys(&sim(100_000), &widen).unwrap();
        let raw = base64::engine::general_purpose::STANDARD.decode(&out.transaction_data).unwrap();
        let d = SorobanTransactionData::from_xdr(raw, Limits::none()).unwrap();
        assert_eq!(d.resources.footprint.read_write.to_vec(), vec![key(1), key(2)], "no duplicate");
        assert_eq!(d.resource_fee, 100_000 + 2 * EXTRA_KEY_FEE);
        assert_eq!(d.resources.instructions, 2_000_000 + 2 * EXTRA_KEY_INSTRUCTIONS);
        assert_eq!(d.resources.write_bytes, 1_500 + 2 * EXTRA_KEY_WRITE_BYTES);
        assert_eq!(out.min_resource_fee, d.resource_fee as u64, "declared and signed agree");
        // Nothing new to add: the simulation is passed through untouched.
        let none = |_: &LedgerFootprint| Vec::new();
        assert_eq!(with_extra_keys(&sim(100_000), &none).unwrap().min_resource_fee, 100_000);
    }

    /// Every ordinary call declares a tenth more instructions than it was
    /// simulated with, and pays for them.
    #[test]
    fn an_ordinary_call_has_instruction_slack() {
        let out = with_instruction_slack(&sim(100_000)).unwrap();
        let raw = base64::engine::general_purpose::STANDARD.decode(&out.transaction_data).unwrap();
        let d = SorobanTransactionData::from_xdr(raw, Limits::none()).unwrap();
        assert_eq!(d.resources.instructions, 2_200_000);
        assert_eq!(d.resource_fee, 100_000 + 200_000 * 3 / 10_000 + 1);
        assert_eq!(out.min_resource_fee, d.resource_fee as u64, "declared and signed agree");
    }
}
