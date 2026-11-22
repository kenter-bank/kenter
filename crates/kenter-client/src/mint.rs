use base64::Engine;
use stellar_xdr::curr::{
    ContractDataDurability, ContractId, Hash, LedgerEntryData, LedgerKey, LedgerKeyContractData,
    Limits, ReadXdr, ScAddress, ScMap, ScSymbol, ScVal, ScVec, WriteXdr,
};
use tracing::debug;

use crate::error::ClientError;
use crate::tx::{
    TxBuilder, address_to_scval, bytes32_to_scval, bytes64_to_scval, bytes_to_scval,
    i128_to_scval, pair_entry_to_scval, scval_to_bool, scval_to_bytes32, scval_to_i128,
    scval_to_u32, u32_to_scval, scval_to_address,
};
use kenter_crypto::keypair::StellarKeypair;

/// Client for the kenter-mint Soroban contract.
pub struct MintClient {
    tx: TxBuilder,
    contract_id: String,
}

impl MintClient {
    /// The mint's contract address.
    ///
    /// Callers need it to build a claim signature, which binds the proof
    /// to one deployment.
    pub fn contract_id(&self) -> &str {
        &self.contract_id
    }

    pub fn new(tx: TxBuilder, contract_id: &str) -> Self {
        Self {
            tx,
            contract_id: contract_id.to_string(),
        }
    }

    pub fn tx(&self) -> &TxBuilder {
        &self.tx
    }

    pub fn tx_mut(&mut self) -> &mut TxBuilder {
        &mut self.tx
    }

    // ── State-changing methods ──

    /// Deposit `amount` and open a print slot of `total_pairs`, naming only
    /// the depositor's own end pairs `(node_a, node_b)`. The interior is
    /// chosen by the draw (`docs/architecture/node-selection.md`):
    /// [`Self::seed_print`], then
    /// pairs [`Self::claim_position`]. Returns the slot_id.
    pub async fn request_print(
        &mut self,
        event_id: [u8; 32],
        amount: i128,
        total_pairs: u32,
        first_pair: (&str, &str),
        last_pair: (&str, &str),
    ) -> Result<u32, ClientError> {
        let caller = address_to_scval(self.tx.source_address())?;

        let args = vec![
            caller,
            bytes32_to_scval(event_id),
            i128_to_scval(amount),
            u32_to_scval(total_pairs),
            pair_entry_to_scval(first_pair.0, first_pair.1)?,
            pair_entry_to_scval(last_pair.0, last_pair.1)?,
        ];

        // The slot id comes from a shared counter, so two requests in one
        // ledger simulate against the same id and declare the same `Slot`
        // and `Draw` keys; the second applied is given the next id and
        // traps on keys it never declared. Declaring the next
        // few ids as well lets that many land in one ledger. A request that
        // fails on chain is rolled back whole -- no deposit moves, the event
        // id stays unused -- so it is simulated afresh and sent once more.
        let widen = |fp: &stellar_xdr::curr::LedgerFootprint| neighbour_slot_keys(fp, NEIGHBOUR_SLOTS);
        debug!("request_print: submitting");
        let result = match self
            .tx
            .invoke_widened(&self.contract_id, "request_print", args.clone(), &widen)
            .await
        {
            Err(ClientError::TransactionFailed { status, .. }) => {
                debug!(%status, "request_print failed on chain; simulating again and resending once");
                self.tx
                    .invoke_widened(&self.contract_id, "request_print", args, &widen)
                    .await?
            }
            other => other?,
        };

        let slot_id = result
            .return_value
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_u32)?;

        debug!(slot_id, "request_print: success");
        Ok(slot_id)
    }

    /// Seed `slot_id` with its beacon round's signature: drand quicknet's
    /// G1 signature, **uncompressed** (96 bytes). Anyone may submit it.
    /// Returns the seed.
    pub async fn seed_print(&mut self, slot_id: u32, signature: [u8; 96]) -> Result<[u8; 32], ClientError> {
        let args = vec![u32_to_scval(slot_id), bytes_to_scval(&signature)];
        let result = self.tx.invoke(&self.contract_id, "seed_print", args).await?;
        result
            .return_value
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_bytes32)
    }

    /// Claim an interior position on `slot_id` for this client's pair: the
    /// source account is `node_a` and `partner` is `node_b`, and both sign
    /// (`TxBuilder::invoke_cosigned`). Returns the claim's rank, 0 lowest.
    ///
    /// `may_land_first` is how many other claims could land between this
    /// one's simulation and its application: `2k` less the claims already
    /// seen. The transaction declares room for them (`ContentionMargin`).
    pub async fn claim_position(
        &mut self,
        slot_id: u32,
        partner: &StellarKeypair,
        may_land_first: u32,
    ) -> Result<u32, ClientError> {
        let args = vec![
            u32_to_scval(slot_id),
            address_to_scval(self.tx.source_address())?,
            address_to_scval(&partner.stellar_address())?,
        ];
        let result = self
            .tx
            .invoke_cosigned(
                &self.contract_id,
                "claim_position",
                args,
                partner,
                crate::tx::ContentionMargin::for_claims(may_land_first),
            )
            .await?;
        result
            .return_value
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_u32)
    }

    /// Register this client's pair -- the source account as `node_a`,
    /// `partner` as `node_b`, both signing -- so it may claim on prints
    /// requested from the next ledger on.
    /// Returns the registration ledger.
    pub async fn register_pair(&mut self, partner: &StellarKeypair) -> Result<u32, ClientError> {
        let args = vec![
            address_to_scval(self.tx.source_address())?,
            address_to_scval(&partner.stellar_address())?,
        ];
        let result = self
            .tx
            // Registration writes only the pair's own records: nobody else
            // is writing them, so no margin.
            .invoke_cosigned(
                &self.contract_id,
                "register_pair",
                args,
                partner,
                crate::tx::ContentionMargin::default(),
            )
            .await?;
        result
            .return_value
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_u32)
    }

    /// Dissolve this client's registered pair. Returns the former partner.
    pub async fn unpair(&mut self) -> Result<String, ClientError> {
        let caller = address_to_scval(self.tx.source_address())?;
        let result = self.tx.invoke(&self.contract_id, "unpair", vec![caller]).await?;
        result
            .return_value
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_address)
    }

    /// The pair `node` is registered in: `(partner, registered_at)`.
    pub async fn pair_of(&mut self, node: &str) -> Result<Option<(String, u32)>, ClientError> {
        let result = self
            .tx
            .simulate_invoke(&self.contract_id, "pair_of", vec![address_to_scval(node)?])
            .await?;
        match result {
            None | Some(ScVal::Void) => Ok(None),
            Some(ScVal::Map(Some(m))) => Ok(Some((
                scval_to_address(field(&m, "partner")?)?,
                scval_to_u32(field(&m, "registered_at")?)?,
            ))),
            Some(other) => Err(ClientError::XdrDecode(format!("pair_of: {other:?}"))),
        }
    }

    /// Skip the selected pair at the next position, which has not
    /// confirmed within the serve timeout; the depositor pays one pair's
    /// fee, burned. Returns the position skipped.
    pub async fn skip_position(&mut self, slot_id: u32) -> Result<u32, ClientError> {
        let caller = address_to_scval(self.tx.source_address())?;
        let result = self
            .tx
            .invoke(&self.contract_id, "skip_position", vec![caller, u32_to_scval(slot_id)])
            .await?;
        result
            .return_value
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_u32)
    }

    /// The mint's selection parameters.
    pub async fn selection(&mut self) -> Result<SelectionInfo, ClientError> {
        let result = self
            .tx
            .simulate_invoke(&self.contract_id, "selection", vec![])
            .await?;
        let val = result.ok_or(ClientError::MissingReturnValue)?;
        let ScVal::Map(Some(map)) = &val else {
            return Err(ClientError::XdrDecode(format!("selection: expected Map, got {val:?}")));
        };
        Ok(SelectionInfo {
            beacon_genesis: scval_to_u64(field(map, "beacon_genesis")?)?,
            beacon_period: scval_to_u64(field(map, "beacon_period")?)?,
            beacon_lead: scval_to_u64(field(map, "beacon_lead")?)?,
            claim_window: scval_to_u32(field(map, "claim_window")?)?,
            serve_timeout: scval_to_u32(field(map, "serve_timeout")?)?,
            min_node_age: scval_to_u32(field(map, "min_node_age")?)?,
        })
    }

    /// Cancel a print slot and get a refund. Only the depositor can cancel.
    /// Returns the refund amount.
    pub async fn cancel_print(&mut self, slot_id: u32) -> Result<i128, ClientError> {
        let caller = address_to_scval(self.tx.source_address())?;
        let args = vec![caller, u32_to_scval(slot_id)];

        let result = self.tx.invoke(&self.contract_id, "cancel_print", args).await?;

        result
            .return_value
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_i128)
    }

    /// Confirm a link in a print slot.
    /// Must be called by one of the assigned pair nodes.
    /// Returns the number of completed links.
    pub async fn confirm_link(
        &mut self,
        slot_id: u32,
        link_index: u32,
        partial_public_key: [u8; 32],
    ) -> Result<u32, ClientError> {
        let caller = address_to_scval(self.tx.source_address())?;
        let args = vec![
            caller,
            u32_to_scval(slot_id),
            u32_to_scval(link_index),
            bytes32_to_scval(partial_public_key),
        ];

        debug!(slot_id, link_index, "confirm_link: submitting");
        let result = self.tx.invoke(&self.contract_id, "confirm_link", args).await?;

        let completed = result
            .return_value
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_u32)?;

        debug!(slot_id, link_index, completed, "confirm_link: success");
        Ok(completed)
    }

    /// Register the assembled token's ephemeral public key.
    /// Only the depositor can register. All links must be confirmed first.
    /// Transitions the slot from Printing → Active.
    ///
    /// `mode` selects pure-bearer vs spend mode; `initial_owner_commitment` is the
    /// first owner's commitment (`kenter_crypto::spend::owner_commitment`) and is
    /// ignored for `PureBearer` (pass zeros). See
    /// `docs/architecture/spend-mode.md`.
    ///
    /// `claim_pubkey` is [`BearerToken::claim_public_key`]. Its secret half
    /// stays in the container and is what Path B redemption signs with, so
    /// publishing the chain is not enough to take the note. Register
    /// the wrong key and the note cannot be redeemed by chain at all.
    pub async fn register_token(
        &mut self,
        slot_id: u32,
        ephemeral_key: [u8; 32],
        chain_hash: [u8; 32],
        mode: TokenMode,
        initial_owner_commitment: [u8; 32],
        claim_pubkey: [u8; 32],
    ) -> Result<bool, ClientError> {
        let caller = address_to_scval(self.tx.source_address())?;
        let args = vec![
            caller,
            u32_to_scval(slot_id),
            bytes32_to_scval(ephemeral_key),
            bytes32_to_scval(chain_hash),
            u32_to_scval(mode as u32),
            bytes32_to_scval(initial_owner_commitment),
            bytes32_to_scval(claim_pubkey),
        ];

        debug!(slot_id, "register_token: submitting");
        let result = self.tx.invoke(&self.contract_id, "register_token", args).await?;

        let ok = result
            .return_value
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_bool)?;

        debug!(slot_id, "register_token: success");
        Ok(ok)
    }

    /// Transfer ownership of a spend-mode token (Realization A). Moves the
    /// on-ledger owner pointer to `new_owner_commitment`, burning the current
    /// owner's claim. The tx source pays fees; `signature` is the current owner's
    /// Ed25519 authorization (`kenter_crypto::spend::authorize_spend`) over
    /// `SHA-256(SPEND_AUTH || contract_xdr || slot_id (u32 BE) ||
    /// ephemeral_key || current_commitment || new_owner_commitment ||
    /// spend_nonce (u32 BE))`. See `docs/architecture/spend-mode.md` (what
    /// the owner signs) for what each field is for; keep the two in sync.
    pub async fn spend(
        &mut self,
        slot_id: u32,
        current_owner_pubkey: [u8; 32],
        new_owner_commitment: [u8; 32],
        signature: [u8; 64],
    ) -> Result<(), ClientError> {
        let caller = address_to_scval(self.tx.source_address())?;
        let args = vec![
            caller,
            u32_to_scval(slot_id),
            bytes32_to_scval(current_owner_pubkey),
            bytes32_to_scval(new_owner_commitment),
            bytes64_to_scval(signature),
        ];

        debug!("spend: submitting");
        // Returns (); success is signalled by the tx landing (invoke errors otherwise).
        self.tx.invoke(&self.contract_id, "spend", args).await?;
        debug!("spend: success");
        Ok(())
    }

    /// Path A (pure bearer): redeem by proving knowledge of the composed
    /// ephemeral key **and** holding the note.
    ///
    /// `signature` is Ed25519 by the composed secret over
    /// `SHA-256(domain_tag ‖ contract_xdr ‖ slot_id (u32 BE) ‖
    /// ephemeral_key ‖ recipient_xdr)`, and
    /// proves the note was constructed. `claim_signature` is by the
    /// note's claim key over the Path B claim digest, and proves it is
    /// held.
    ///
    /// Both, because the ephemeral secret is not held only by the note:
    /// each shard is derivable by either node of its pair, so colluding
    /// nodes — or a single node of a one-pair print — can compose it.
    /// Construction is not possession.
    ///
    /// Returns the holder's payout amount (after node fees).
    pub async fn redeem_by_key(
        &mut self,
        recipient: &str,
        slot_id: u32,
        signature: [u8; 64],
        claim_signature: [u8; 64],
    ) -> Result<i128, ClientError> {
        let holder = address_to_scval(self.tx.source_address())?;
        let args = vec![
            holder,
            address_to_scval(recipient)?,
            ScVal::U32(slot_id),
            // Signatures are BytesN<64> on-chain
            ScVal::Bytes(stellar_xdr::curr::ScBytes(
                signature.to_vec().try_into().unwrap(),
            )),
            ScVal::Bytes(stellar_xdr::curr::ScBytes(
                claim_signature.to_vec().try_into().unwrap(),
            )),
        ];

        debug!("redeem_by_key: submitting");
        let result = self.tx.invoke(&self.contract_id, "redeem_by_key", args).await?;

        let amount = result
            .return_value
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_i128)?;

        debug!(amount, "redeem_by_key: success");
        Ok(amount)
    }

    /// Path A for spend-mode tokens: [`redeem_by_key`](Self::redeem_by_key) plus
    /// the current owner's proof. `owner_signature` is
    /// `kenter_crypto::spend::authorize_redeem` over
    /// `SHA-256(SPEND_REDEEM || contract_xdr || slot_id (u32 BE) ||
    /// ephemeral_key || owner_commitment || spend_nonce (u32 BE) ||
    /// recipient_xdr)`.
    pub async fn redeem_by_key_owned(
        &mut self,
        recipient: &str,
        slot_id: u32,
        signature: [u8; 64],
        owner_pubkey: [u8; 32],
        owner_signature: [u8; 64],
    ) -> Result<i128, ClientError> {
        let holder = address_to_scval(self.tx.source_address())?;
        let args = vec![
            holder,
            address_to_scval(recipient)?,
            ScVal::U32(slot_id),
            bytes64_to_scval(signature),
            bytes32_to_scval(owner_pubkey),
            bytes64_to_scval(owner_signature),
        ];

        debug!("redeem_by_key_owned: submitting");
        let result = self
            .tx
            .invoke(&self.contract_id, "redeem_by_key_owned", args)
            .await?;

        result
            .return_value
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_i128)
    }

    /// Path B: Redeem by submitting the full signature chain for on-chain verification.
    /// `chain_data` is the canonical blob from
    /// [`kenter_crypto::chain_data::serialize_chain_data`] — its SHA-256 must equal
    /// the `chain_hash` committed at [`register_token`](Self::register_token).
    /// Returns the holder's payout. Node fees are accrued to the construction
    /// participants (claimable via [`claim_fees`](Self::claim_fees)), not burned.
    /// `claim_signature` comes from [`BearerToken::sign_claim`] and binds
    /// this redemption to `recipient`. Without it the chain alone would be
    /// the proof, and any transaction carrying it -- including one that
    /// fails on-chain and leaves the note live -- would hand the note to
    /// whoever read it.
    pub async fn redeem_by_chain(
        &mut self,
        recipient: &str,
        slot_id: u32,
        chain_data: Vec<u8>,
        claim_signature: [u8; 64],
    ) -> Result<i128, ClientError> {
        let holder = address_to_scval(self.tx.source_address())?;
        let args = vec![
            holder,
            address_to_scval(recipient)?,
            ScVal::U32(slot_id),
            bytes_to_scval(&chain_data),
            bytes64_to_scval(claim_signature),
        ];

        debug!("redeem_by_chain: submitting");
        let result = self.tx.invoke(&self.contract_id, "redeem_by_chain", args).await?;

        let amount = result
            .return_value
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_i128)?;

        debug!(amount, "redeem_by_chain: success");
        Ok(amount)
    }

    /// Path B for spend-mode tokens: [`redeem_by_chain`](Self::redeem_by_chain)
    /// plus the current owner's proof (`kenter_crypto::spend::authorize_redeem`
    /// over `SHA-256(SPEND_REDEEM || contract_xdr || slot_id (u32 BE) ||
    /// ephemeral_key || owner_commitment || spend_nonce (u32 BE) ||
    /// recipient_xdr)`). The recipient is in the digest, so the proof
    /// authorises a payout to one address rather than a redemption to
    /// anywhere.
    pub async fn redeem_by_chain_owned(
        &mut self,
        recipient: &str,
        slot_id: u32,
        chain_data: Vec<u8>,
        owner_pubkey: [u8; 32],
        owner_signature: [u8; 64],
    ) -> Result<i128, ClientError> {
        let holder = address_to_scval(self.tx.source_address())?;
        let args = vec![
            holder,
            address_to_scval(recipient)?,
            ScVal::U32(slot_id),
            bytes_to_scval(&chain_data),
            bytes32_to_scval(owner_pubkey),
            bytes64_to_scval(owner_signature),
        ];

        debug!("redeem_by_chain_owned: submitting");
        let result = self
            .tx
            .invoke(&self.contract_id, "redeem_by_chain_owned", args)
            .await?;

        result
            .return_value
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_i128)
    }

    /// What a Path-B redemption would cost, without doing it.
    ///
    /// Same arguments as the real call, and the contract runs for real
    /// inside the simulation -- so a token that could not be redeemed
    /// errors here too. Nothing is submitted: the slot stays live, so
    /// the same measurement can be taken again after a change and the
    /// two compared.
    ///
    /// This is the authoritative cost, and nothing else is. The
    /// contract test suite meters a different host and reads lower --
    /// 9,882,230 against 13,052,010 here, at 3 pairs on the same wasm
    /// and the same 904-byte chain -- because cost parameters live on
    /// the ledger and testnet charges 1.87x the host default for
    /// `VerifyEd25519Sig`. Compare the result against
    /// `tx_max_instructions` from the target network's
    /// `contract_compute_v0` entry, not against a compiled-in
    /// constant.
    pub async fn simulate_redeem_by_chain(
        &self,
        recipient: &str,
        slot_id: u32,
        chain_data: Vec<u8>,
        claim_signature: [u8; 64],
    ) -> Result<crate::tx::SimResources, ClientError> {
        let args = vec![
            address_to_scval(self.tx.source_address())?,
            address_to_scval(recipient)?,
            ScVal::U32(slot_id),
            bytes_to_scval(&chain_data),
            bytes64_to_scval(claim_signature),
        ];
        self.tx
            .simulate_resources(&self.contract_id, "redeem_by_chain", args)
            .await
    }

    /// The same, for the spend-mode path -- the dearer of the two, and
    /// the one the contract's CPU-budget assertions are held against.
    pub async fn simulate_redeem_by_chain_owned(
        &self,
        recipient: &str,
        slot_id: u32,
        chain_data: Vec<u8>,
        owner_pubkey: [u8; 32],
        owner_signature: [u8; 64],
    ) -> Result<crate::tx::SimResources, ClientError> {
        let args = vec![
            address_to_scval(self.tx.source_address())?,
            address_to_scval(recipient)?,
            ScVal::U32(slot_id),
            bytes_to_scval(&chain_data),
            bytes32_to_scval(owner_pubkey),
            bytes64_to_scval(owner_signature),
        ];
        self.tx
            .simulate_resources(&self.contract_id, "redeem_by_chain_owned", args)
            .await
    }

    /// Claim accrued node fees for the source address. Earnings are decoupled
    /// from the redemption moment, so a node that was offline when its tokens
    /// were redeemed still collects here (churn-tolerant).
    /// Returns the amount claimed. Fails with `NothingToClaim` if the balance is 0.
    pub async fn claim_fees(&mut self) -> Result<i128, ClientError> {
        let node = address_to_scval(self.tx.source_address())?;
        let args = vec![node];

        debug!("claim_fees: submitting");
        let result = self.tx.invoke(&self.contract_id, "claim_fees", args).await?;

        let amount = result
            .return_value
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_i128)?;

        debug!(amount, "claim_fees: success");
        Ok(amount)
    }

    /// Clear an expired print slot (anyone can call). Returns refund amount.
    pub async fn clear_expired_slot(&mut self, slot_id: u32) -> Result<i128, ClientError> {
        let args = vec![u32_to_scval(slot_id)];

        let result = self
            .tx
            .invoke(&self.contract_id, "clear_expired_slot", args)
            .await?;

        result
            .return_value
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_i128)
    }

    // ── Read-only queries (simulate only, no submission) ──

    /// Get the node_fee configuration value.
    pub async fn node_fee(&mut self) -> Result<u32, ClientError> {
        let result = self
            .tx
            .simulate_invoke(&self.contract_id, "node_fee", vec![])
            .await?;

        result
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_u32)
    }

    /// How many ledgers a print slot stays open after its request
    /// (immutable constructor config). Past it, anyone may settle the slot
    /// with [`Self::clear_expired_slot`].
    pub async fn max_print_ledgers(&self) -> Result<u32, ClientError> {
        let result = self
            .tx
            .simulate_invoke_ro(&self.contract_id, "max_print_ledgers", vec![])
            .await?;
        result
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_u32)
    }

    /// The asset this mint escrows, as a SAC contract id.
    ///
    /// Immutable constructor config: a mint escrows one asset for its whole
    /// life, so a client that wants to know what a note is a claim on has to
    /// ask, and a client that assumes is wrong as soon as a second mint
    /// exists.
    pub async fn pay_token(&mut self) -> Result<String, ClientError> {
        let result = self
            .tx
            .simulate_invoke(&self.contract_id, "pay_token", vec![])
            .await?;
        scval_to_address(result.as_ref().ok_or(ClientError::MissingReturnValue)?)
    }

    /// Get min_pairs configuration value.
    pub async fn min_pairs(&mut self) -> Result<u32, ClientError> {
        let result = self
            .tx
            .simulate_invoke(&self.contract_id, "min_pairs", vec![])
            .await?;

        result
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_u32)
    }

    /// Get max_pairs configuration value.
    pub async fn max_pairs(&mut self) -> Result<u32, ClientError> {
        let result = self
            .tx
            .simulate_invoke(&self.contract_id, "max_pairs", vec![])
            .await?;

        result
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_u32)
    }

    /// Query a node's accrued, unclaimed fee balance (0 if none).
    pub async fn accrued_fees(&mut self, node: &str) -> Result<i128, ClientError> {
        let args = vec![address_to_scval(node)?];
        let result = self
            .tx
            .simulate_invoke(&self.contract_id, "accrued_fees", args)
            .await?;

        result
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_i128)
    }

    /// Check if a token has been redeemed.
    pub async fn is_redeemed(&mut self, slot_id: u32) -> Result<bool, ClientError> {
        let args = vec![u32_to_scval(slot_id)];
        let result = self
            .tx
            .simulate_invoke(&self.contract_id, "is_redeemed", args)
            .await?;

        result
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_bool)
    }

    /// Read a token's on-chain record by ephemeral key, or `None` if no record
    /// exists. Reads `DataKey::Token(key)` directly via `getLedgerEntries` (no
    /// simulate). Unlike [`Self::is_redeemed`], this distinguishes not-found from
    /// active and returns the on-chain amount and state.
    pub async fn get_token(&self, slot_id: u32) -> Result<Option<TokenInfo>, ClientError> {
        let want = Self::token_data_key(slot_id);
        match self.read_contract_data(&want).await? {
            None => Ok(None),
            Some(val) => Ok(Some(TokenInfo::from_scval(&val)?)),
        }
    }

    /// What the ledger says about a slot: the note, the fact it was
    /// redeemed, or nothing.
    ///
    /// Redemption removes `Token(slot_id)` and writes `Redeemed(slot_id)`,
    /// so a reader that asks only for the token sees the same `None` for a
    /// note that was paid out and a slot that never existed. Both keys go
    /// in one `getLedgerEntries` call, because asking separately invites
    /// the two answers to come from different ledgers.
    ///
    /// An absent pair is not conclusive on its own — a record that merely
    /// archived is also absent from `getLedgerEntries` — so that case is
    /// settled by simulating `get_token_state`, which restores archived
    /// entries and is therefore authoritative. The simulate costs a round
    /// trip and only happens when both keys are missing, which for a
    /// wallet reconciling its own notes is the rare branch.
    pub async fn token_or_marker(
        &self,
        slot_id: u32,
    ) -> Result<SlotRecord, ClientError> {
        let token_key = Self::token_data_key(slot_id);
        let marker_key = Self::redeemed_data_key(slot_id);
        let found = self
            .read_contract_data_many(&[
                (token_key.clone(), ContractDataDurability::Persistent),
                (marker_key.clone(), ContractDataDurability::Persistent),
            ])
            .await?;

        if let Some(val) = found.get(&Self::key_ident(&token_key)) {
            return Ok(SlotRecord::Token(Box::new(TokenInfo::from_scval(val)?)));
        }
        if let Some(val) = found.get(&Self::key_ident(&marker_key)) {
            return Ok(SlotRecord::Redeemed(scval_to_u32(val).ok()));
        }

        // Absent from the live state. Ask the contract, which sees through
        // archival.
        match self.get_token_state(slot_id).await? {
            Some(TokenState::Redeemed) => Ok(SlotRecord::Redeemed(None)),
            Some(_) => Ok(SlotRecord::Archived),
            None => Ok(SlotRecord::NotFound),
        }
    }

    /// `get_token_state(slot_id)`, by simulation rather than a raw read.
    ///
    /// Slower than `get_token`, and authoritative where that is not:
    /// simulation restores an archived entry before answering.
    pub async fn get_token_state(
        &self,
        slot_id: u32,
    ) -> Result<Option<TokenState>, ClientError> {
        let args = vec![u32_to_scval(slot_id)];
        let result = self
            .tx
            .simulate_invoke_ro(&self.contract_id, "get_token_state", args)
            .await?;
        match result.as_ref() {
            None | Some(ScVal::Void) => Ok(None),
            Some(v) => Ok(Some(TokenState::from_u32(scval_to_u32(v)?))),
        }
    }

    /// Read a print slot's on-chain record, or `None` if there is no such
    /// slot. Like [`Self::get_token`], a direct `getLedgerEntries` read rather
    /// than a simulate, so it works from an unfunded account.
    ///
    /// This is how an observer checks *who* built a chain. `confirm_link`
    /// accepts a caller only if it is a member of the pair assigned to that
    /// link, so a slot whose `pairs[i]` is a node's pair and whose
    /// `completed_links` covers `i` is proof that node confirmed it — no
    /// transaction-source archaeology required.
    ///
    /// A slot is two entries: the persistent core (`Slot`) and the
    /// temporary draw (`Draw`; see `docs/architecture/node-selection.md`,
    /// where a slot lives). Both are read in one round trip and
    /// assembled; a core with no draw is a slot
    /// whose draw lapsed ([`SlotInfo::lapsed`]).
    pub async fn get_slot(&self, slot_id: u32) -> Result<Option<SlotInfo>, ClientError> {
        Ok(self.get_slots(&[slot_id]).await?.remove(&slot_id))
    }

    /// Read several slots in one round trip. Slots with no entry (never
    /// printed, or already registered, cancelled or expired) are absent.
    ///
    /// This is how a node daemon watches for prints to claim: it notes
    /// [`Self::next_slot_id`] and reads the slots it has not finished with,
    /// rather than following events, so it depends on nothing the RPC
    /// retains beyond live state.
    pub async fn get_slots(&self, ids: &[u32]) -> Result<std::collections::HashMap<u32, SlotInfo>, ClientError> {
        let mut out = std::collections::HashMap::new();
        // getLedgerEntries takes at most 200 keys, and each slot is two.
        for chunk in ids.chunks(100) {
            let mut keys = Vec::with_capacity(chunk.len() * 2);
            for &id in chunk {
                keys.push((Self::slot_data_key(id), ContractDataDurability::Persistent));
                keys.push((Self::draw_data_key(id), ContractDataDurability::Temporary));
            }
            let found = self.read_contract_data_many(&keys).await?;
            for &id in chunk {
                let core = found.get(&Self::key_ident(&Self::slot_data_key(id)));
                let draw = found.get(&Self::key_ident(&Self::draw_data_key(id)));
                if let Some(core) = core {
                    out.insert(id, SlotInfo::from_parts(core, draw)?);
                }
            }
        }
        Ok(out)
    }

    /// The next slot id the mint will hand out — i.e. one past the last slot
    /// allocated. Zero on a mint that has never printed.
    ///
    /// An observer's only handle on "what just happened": slots carry no
    /// index by depositor, so the way to find a print is to note this before
    /// and read the slots that appeared after.
    pub async fn next_slot_id(&self) -> Result<u32, ClientError> {
        let want = Self::unit_data_key("NextSlotId")?;
        match self.read_contract_data(&want).await? {
            None => Ok(0), // never printed
            Some(val) => scval_to_u32(&val),
        }
    }

    /// A `DataKey` variant that carries no payload. Soroban encodes those
    /// as a one-element vec holding the variant symbol.
    fn unit_data_key(variant: &str) -> Result<ScVal, ClientError> {
        Ok(ScVal::Vec(Some(ScVec(
            vec![ScVal::Symbol(ScSymbol(
                variant.try_into().map_err(|_| ClientError::XdrEncode("symbol".into()))?,
            ))]
            .try_into()
            .map_err(|_| ClientError::XdrEncode("vec".into()))?,
        ))))
    }

    /// The base64 `LedgerKey` for one of this mint's persistent `DataKey`s.
    fn ledger_key_b64(&self, data_key: &ScVal) -> Result<String, ClientError> {
        self.ledger_key_b64_at(data_key, ContractDataDurability::Persistent)
    }

    /// The base64 `LedgerKey` for one of this mint's `DataKey`s, at the
    /// given durability (`Draw` is temporary).
    fn ledger_key_b64_at(
        &self,
        data_key: &ScVal,
        durability: ContractDataDurability,
    ) -> Result<String, ClientError> {
        let ledger_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: self.contract_scaddress()?,
            key: data_key.clone(),
            durability,
        });
        let bytes = ledger_key
            .to_xdr(Limits::none())
            .map_err(|e| ClientError::XdrEncode(e.to_string()))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    fn contract_scaddress(&self) -> Result<ScAddress, ClientError> {
        let contract = stellar_strkey::Contract::from_string(&self.contract_id)
            .map_err(|e| ClientError::InvalidAddress(e.to_string()))?;
        Ok(ScAddress::Contract(ContractId(Hash(contract.0))))
    }

    /// Read one of this mint's persistent entries, and confirm the answer
    /// is about the question.
    ///
    /// Taking `entries[0]` and decoding it is not enough. The decoded
    /// `ContractDataEntry` carries the contract and the key it belongs to,
    /// and unless they are compared against what was asked, an RPC could
    /// answer a question about one note with another note's record -- or
    /// with an entry from an entirely different contract that happened to
    /// decode. The payee's G2/G3 gates are self-certifying only
    /// if the record they certify is the record they asked for.
    ///
    /// This does not make a dishonest RPC honest: it can still answer
    /// "no entry" about a note that exists, or serve a stale one. It
    /// removes the free substitution.
    /// A stable identity for a `DataKey`, for matching responses to
    /// requests. `getLedgerEntries` returns only the keys that exist and
    /// in no guaranteed order, so a two-key read has to say which came
    /// back.
    fn key_ident(data_key: &ScVal) -> String {
        format!("{data_key:?}")
    }

    /// Read several of this mint's `DataKey`s in one round trip.
    ///
    /// Keys with no entry are simply absent from the result, as they are
    /// from the RPC response. Every entry returned is checked against the
    /// contract address, the key asked for and persistent durability,
    /// exactly as the single-key read does -- an endpoint that answers a
    /// question about one note with another note's record is the failure
    /// this guards.
    ///
    /// Each key names its durability, and an entry must come back at the
    /// durability it was asked for.
    async fn read_contract_data_many(
        &self,
        data_keys: &[(ScVal, ContractDataDurability)],
    ) -> Result<std::collections::HashMap<String, ScVal>, ClientError> {
        let mut out = std::collections::HashMap::new();
        if data_keys.is_empty() {
            return Ok(out);
        }
        let b64: Vec<String> = data_keys
            .iter()
            .map(|(k, d)| self.ledger_key_b64_at(k, *d))
            .collect::<Result<_, _>>()?;
        let entries = self.tx.rpc().get_ledger_entries(&b64).await?;
        let want_contract = self.contract_scaddress()?;

        for entry in entries {
            let xdr = entry
                .get("xdr")
                .and_then(|x| x.as_str())
                .ok_or_else(|| ClientError::XdrDecode("ledger entry missing `xdr`".into()))?;
            let raw = base64::engine::general_purpose::STANDARD
                .decode(xdr)
                .map_err(|e| ClientError::XdrDecode(e.to_string()))?;
            let data = LedgerEntryData::from_xdr(raw.as_slice(), Limits::none())
                .map_err(|e| ClientError::XdrDecode(e.to_string()))?;
            let cd = match data {
                LedgerEntryData::ContractData(cd) => cd,
                other => {
                    return Err(ClientError::XdrDecode(format!(
                        "expected ContractData, got {other:?}"
                    )));
                }
            };
            if cd.contract != want_contract {
                return Err(ClientError::WrongLedgerEntry(format!(
                    "entry belongs to {:?}, not to the mint at {}",
                    cd.contract, self.contract_id
                )));
            }
            if !data_keys.iter().any(|(k, d)| k == &cd.key && *d == cd.durability) {
                return Err(ClientError::WrongLedgerEntry(format!(
                    "entry is keyed {:?}, which was not asked for",
                    cd.key
                )));
            }
            out.insert(Self::key_ident(&cd.key), cd.val);
        }
        Ok(out)
    }

    async fn read_contract_data(
        &self,
        data_key: &ScVal,
    ) -> Result<Option<ScVal>, ClientError> {
        let key_b64 = self.ledger_key_b64(data_key)?;
        let entries = self.tx.rpc().get_ledger_entries(&[key_b64]).await?;

        let Some(entry) = entries.first() else {
            return Ok(None); // getLedgerEntries omits keys with no entry
        };
        let xdr = entry
            .get("xdr")
            .and_then(|x| x.as_str())
            .ok_or_else(|| ClientError::XdrDecode("ledger entry missing `xdr`".into()))?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(xdr)
            .map_err(|e| ClientError::XdrDecode(e.to_string()))?;
        let data = LedgerEntryData::from_xdr(raw.as_slice(), Limits::none())
            .map_err(|e| ClientError::XdrDecode(e.to_string()))?;
        let cd = match data {
            LedgerEntryData::ContractData(cd) => cd,
            other => {
                return Err(ClientError::XdrDecode(format!(
                    "expected ContractData, got {other:?}"
                )));
            }
        };

        let want_contract = self.contract_scaddress()?;
        if cd.contract != want_contract {
            return Err(ClientError::WrongLedgerEntry(format!(
                "entry belongs to {:?}, not to the mint at {}",
                cd.contract, self.contract_id
            )));
        }
        if &cd.key != data_key {
            return Err(ClientError::WrongLedgerEntry(format!(
                "entry is keyed {:?}, not {data_key:?}",
                cd.key
            )));
        }
        if cd.durability != ContractDataDurability::Persistent {
            return Err(ClientError::WrongLedgerEntry(
                "entry is not persistent storage".into(),
            ));
        }

        Ok(Some(cd.val))
    }

    /// Build the `DataKey::Redeemed(slot_id)` `ScVal`.
    fn redeemed_data_key(slot_id: u32) -> ScVal {
        ScVal::Vec(Some(ScVec(
            vec![
                ScVal::Symbol(ScSymbol("Redeemed".try_into().expect("literal symbol"))),
                ScVal::U32(slot_id),
            ]
            .try_into()
            .expect("two-element vec"),
        )))
    }

    /// Build the `DataKey::Slot(slot_id)` `ScVal`.
    fn slot_data_key(slot_id: u32) -> ScVal {
        ScVal::Vec(Some(ScVec(
            vec![
                ScVal::Symbol(ScSymbol("Slot".try_into().expect("literal symbol"))),
                ScVal::U32(slot_id),
            ]
            .try_into()
            .expect("two-element vec"),
        )))
    }

    /// The slot id `request_print` was simulated against, read off its
    /// footprint (the one `Slot(n)` it writes).
    fn simulated_slot(fp: &stellar_xdr::curr::LedgerFootprint) -> Option<(ScAddress, u32)> {
        fp.read_write.iter().find_map(|k| match k {
            LedgerKey::ContractData(cd) => match &cd.key {
                ScVal::Vec(Some(v)) => match v.0.as_slice() {
                    [ScVal::Symbol(s), ScVal::U32(n)] if s.0.as_slice() == b"Slot" => {
                        Some((cd.contract.clone(), *n))
                    }
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        })
    }

    /// Build the `DataKey::Draw(slot_id)` `ScVal`: a slot's growing half,
    /// in temporary storage.
    fn draw_data_key(slot_id: u32) -> ScVal {
        ScVal::Vec(Some(ScVec(
            vec![
                ScVal::Symbol(ScSymbol("Draw".try_into().expect("literal symbol"))),
                ScVal::U32(slot_id),
            ]
            .try_into()
            .expect("two-element vec"),
        )))
    }

    /// Build the `DataKey::Token(slot_id)` `ScVal`.
    ///
    /// `ScVal::Vec([Symbol("Token"), U32(slot_id)])` — the same shape the
    /// contract stores, read back at persistent durability.
    ///
    /// Keyed by the slot, not the ephemeral key: a caller-named key is one
    /// anyone can claim first.
    fn token_data_key(slot_id: u32) -> ScVal {
        ScVal::Vec(Some(ScVec(
            vec![
                ScVal::Symbol(ScSymbol("Token".try_into().expect("literal symbol"))),
                ScVal::U32(slot_id),
            ]
            .try_into()
            .expect("two-element vec"),
        )))
    }
}

/// Per-token spend mode (mirrors the contract's `TokenMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenMode {
    PureBearer = 0,
    Spend = 1,
}

impl TokenMode {
    /// Decode a mode discriminant, refusing one we do not recognise.
    ///
    /// Never falls back to `PureBearer`, which is the dangerous
    /// direction: pure bearer is the mode with *no* owner check, so a
    /// spend-mode record misread as pure bearer tells a payee to skip the
    /// G3 ownership gate entirely. A record whose mode cannot be read is a
    /// record that should not be acted on.
    fn from_u32(v: u32) -> Result<Self, ClientError> {
        match v {
            0 => Ok(TokenMode::PureBearer),
            1 => Ok(TokenMode::Spend),
            other => Err(ClientError::XdrDecode(format!(
                "unknown token mode {other}; refusing to guess"
            ))),
        }
    }
}

/// What the ledger holds for a slot.
///
/// A mint record does not outlive its use: `register_token` retires the
/// print slot, and redemption removes the token record and leaves a
/// `Redeemed` marker. So "no token entry" is three different facts, and
/// a reader that collapses them reports a note it was paid for as one
/// that never existed.
#[derive(Debug, Clone)]
pub enum SlotRecord {
    /// A live note.
    Token(Box<TokenInfo>),
    /// Redeemed. The ledger it happened on, where the marker was still
    /// live enough to say.
    Redeemed(Option<u32>),
    /// The contract reports a record the live state does not hold, i.e.
    /// it archived. Restorable, and the next transaction to name it will
    /// restore it.
    Archived,
    /// No such slot, by the contract's own answer and not merely by
    /// absence from `getLedgerEntries`.
    NotFound,
}

/// On-chain token state (mirrors the contract's `TokenState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenState {
    Printing,
    Active,
    Redeemed,
    Cancelled,
    /// An unrecognized discriminant (forward-compat).
    Unknown(u32),
}

impl TokenState {
    fn from_u32(v: u32) -> Self {
        match v {
            0 => TokenState::Printing,
            1 => TokenState::Active,
            2 => TokenState::Redeemed,
            3 => TokenState::Cancelled,
            other => TokenState::Unknown(other),
        }
    }
}

/// The on-chain `TokenRecord` fields the client decodes.
#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub amount: i128,
    pub node_fee: u32,
    pub slot_id: u32,
    pub state: TokenState,
    pub mode: TokenMode,
    /// The chain commitment recorded at registration.
    ///
    /// Read back so a payee can check that the ledger's record describes
    /// the chain they were actually handed. Without this comparison a
    /// note assembled from public ledger data alone passes the receive
    /// gates, because nothing else ties the record to the container.
    pub chain_hash: [u8; 32],
    /// The event id the mint recorded. `verify_chain` requires the
    /// chain's first 32 bytes to equal it, so a payee can tell before
    /// accepting whether Path B will ever succeed.
    pub event_id: [u8; 32],
    /// How many addresses the record names. `verify_chain` requires the
    /// chain to carry exactly `participants / 2` links.
    pub participants_len: u32,
    /// The live owner commitment (spend mode). All-zero / meaningless for
    /// `PureBearer`. The payee's G3 gate compares this against their own
    /// commitment to confirm ownership transferred (the receive gates in
    /// `docs/architecture/spend-mode.md`).
    pub owner_commitment: [u8; 32],
    /// How many times this note has been spent on.
    ///
    /// Both owner digests cover it, so a signature is good for exactly one
    /// transfer. Read fresh immediately before signing: a stale nonce
    /// produces a signature the mint rejects, and a cached one would be a
    /// replay window rather than a mistake.
    pub spend_nonce: u32,
    /// Public half of the note's claim key, as registered.
    ///
    /// A pure-bearer container can be handed over with a claim secret
    /// that is not the registered one: the container is self-signed by
    /// whoever assembled it, so swapping the key inside leaves every
    /// other check passing. The payee then cannot redeem by chain at
    /// all, and the payer can, at leisure.
    pub claim_pubkey: [u8; 32],
    /// The ephemeral key the depositor registered for this slot.
    ///
    /// Worth reading even though the lookup is by slot -- in fact
    /// *because* it is. The record is not fetched **by** the key, so the
    /// two do not agree by construction: the key is just another field
    /// the depositor chose, and a record can carry the note's real
    /// `chain_hash` and `claim_pubkey` beside a different one. Every other
    /// gate passes, Path B still redeems, and Path A quietly does not.
    pub ephemeral_key: [u8; 32],
}

impl TokenInfo {
    /// Decode from the stored `TokenRecord` `ScVal::Map` (contract-struct layout:
    /// field-name symbol → value).
    fn from_scval(val: &ScVal) -> Result<Self, ClientError> {
        let map = match val {
            ScVal::Map(Some(m)) => m,
            _ => return Err(ClientError::XdrDecode(format!("expected Map, got {val:?}"))),
        };
        Ok(TokenInfo {
            amount: scval_to_i128(field(map, "amount")?)?,
            node_fee: scval_to_u32(field(map, "node_fee")?)?,
            slot_id: scval_to_u32(field(map, "slot_id")?)?,
            state: TokenState::from_u32(scval_to_u32(field(map, "state")?)?),
            mode: TokenMode::from_u32(scval_to_u32(field(map, "mode")?)?)?,
            chain_hash: scval_to_bytes32(field(map, "chain_hash")?)?,
            owner_commitment: scval_to_bytes32(field(map, "owner_commitment")?)?,
            spend_nonce: scval_to_u32(field(map, "spend_nonce")?)?,
            claim_pubkey: scval_to_bytes32(field(map, "claim_pubkey")?)?,
            ephemeral_key: scval_to_bytes32(field(map, "ephemeral_key")?)?,
            event_id: scval_to_bytes32(field(map, "event_id")?)?,
            participants_len: match field(map, "participants")? {
                ScVal::Vec(Some(v)) => v.len() as u32,
                other => {
                    return Err(ClientError::XdrDecode(format!(
                        "participants: expected Vec, got {other:?}"
                    )))
                }
            },
        })
    }
}

/// How many slot ids past the simulated one a `request_print` also
/// declares, so that many other requests can land in the same ledger first.
pub const NEIGHBOUR_SLOTS: u32 = 4;

/// The `Slot` (persistent) and `Draw` (temporary) keys of the `n` slot ids
/// after the one `fp` writes; none if it writes no slot.
pub fn neighbour_slot_keys(fp: &stellar_xdr::curr::LedgerFootprint, n: u32) -> Vec<LedgerKey> {
    let Some((contract, at)) = MintClient::simulated_slot(fp) else { return Vec::new() };
    let mut out = Vec::new();
    for id in (at.saturating_add(1)..=at.saturating_add(n)).filter(|&id| id > at) {
        for (key, durability) in [
            (MintClient::slot_data_key(id), ContractDataDurability::Persistent),
            (MintClient::draw_data_key(id), ContractDataDurability::Temporary),
        ] {
            out.push(LedgerKey::ContractData(LedgerKeyContractData {
                contract: contract.clone(),
                key,
                durability,
            }));
        }
    }
    out
}

/// A print slot as the ledger holds it (mirrors the contract's `PrintSlot`).
///
/// `partial_keys` is left out: it is the chain being assembled, which the
/// holder already has in the container and an observer has no use for.
#[derive(Debug, Clone)]
pub struct SlotInfo {
    pub slot_id: u32,
    pub depositor: String,
    pub amount: i128,
    pub total_pairs: u32,
    /// `(node_a, node_b)` per pair, in chain order. Pair `i` is the only
    /// party that can confirm link `i`.
    pub pairs: Vec<(String, String)>,
    pub completed_links: u32,
    pub state: TokenState,
    /// The event id `request_print` was called with: the only chain this
    /// slot accepts.
    pub event_id: [u8; 32],
    /// The partial public key of every link confirmed so far, in order.
    pub partial_keys: Vec<[u8; 32]>,
    /// The beacon round that seeds the slot.
    pub beacon_round: u64,
    /// The selection seed, once `seed_print` has run.
    pub seed: Option<[u8; 32]>,
    /// Last ledger of the claim window; 0 until seeded.
    pub claim_deadline: u32,
    /// Competitive claims, lowest score first, until closed; the
    /// runners-up after.
    pub claims: Vec<ClaimInfo>,
    /// Whether `pairs` is the whole chain yet.
    pub closed: bool,
    /// When the current position became current; a skip is allowed
    /// `serve_timeout` ledgers later.
    pub last_progress: u32,
    /// The ledger `request_print` ran in. A pair may claim only if it was
    /// registered before it.
    pub created_at: u32,
    /// Whether the claim list ever held one claim per position.
    pub filled: bool,
    /// Which participants volunteer: bit `2i` is pair `i`'s `node_a`, bit
    /// `2i + 1` its `node_b`. A volunteer's fees are burned, not paid.
    pub volunteers: u32,
    /// The slot's draw has lapsed: `pairs` is only the end pairs and the
    /// seed, claims and partial keys are gone. Only cancelling or clearing
    /// works on it.
    pub lapsed: bool,
}

/// One claim on a print (mirrors the contract's `Claim`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimInfo {
    pub score: [u8; 32],
    pub pair: (String, String),
    pub volunteer_a: bool,
    pub volunteer_b: bool,
}

/// The mint's selection parameters (mirrors `SelectionConfig`, less the key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionInfo {
    pub beacon_genesis: u64,
    pub beacon_period: u64,
    pub beacon_lead: u64,
    pub claim_window: u32,
    pub serve_timeout: u32,
    pub min_node_age: u32,
}

impl SelectionInfo {
    /// The unix time at which `round` is published.
    pub fn round_time(&self, round: u64) -> u64 {
        self.beacon_genesis + round.saturating_sub(1) * self.beacon_period
    }
}

/// A slot's selection seed, exactly as `seed_print` computes it:
/// `sha256("kenter:select:v1" || mint || slot_id || sha256(sig))`, where
/// `mint` is the contract address's `ScVal` XDR, `slot_id` big-endian and
/// `sig` the uncompressed signature as submitted.
///
/// A daemon computes it from the beacon round before the slot is seeded,
/// so it can tell whether it would claim -- and seed only then.
pub fn selection_seed(mint_id: &str, slot_id: u32, signature: &[u8; 96]) -> Result<[u8; 32], ClientError> {
    use sha2::{Digest, Sha256};
    let contract = stellar_strkey::Contract::from_string(mint_id)
        .map_err(|e| ClientError::InvalidAddress(e.to_string()))?;
    let mint_xdr = ScVal::Address(ScAddress::Contract(ContractId(Hash(contract.0))))
        .to_xdr(Limits::none())
        .map_err(|e| ClientError::XdrEncode(e.to_string()))?;
    let mut h = Sha256::new();
    h.update(b"kenter:select:v1");
    h.update(mint_xdr);
    h.update(slot_id.to_be_bytes());
    h.update(Sha256::digest(signature));
    Ok(h.finalize().into())
}

/// A pair's selection score, exactly as the mint computes it:
/// `sha256(seed || lo || hi)` over the two addresses' `ScVal` XDR in
/// bytewise order.
///
/// A daemon uses it to decide whether claiming is worth a transaction; the
/// mint computes its own and never takes this one.
pub fn selection_score(seed: [u8; 32], a: &str, b: &str) -> Result<[u8; 32], ClientError> {
    use sha2::{Digest, Sha256};
    let xdr = |addr: &str| -> Result<Vec<u8>, ClientError> {
        address_to_scval(addr)?
            .to_xdr(Limits::none())
            .map_err(|e| ClientError::XdrEncode(e.to_string()))
    };
    let (xa, xb) = (xdr(a)?, xdr(b)?);
    let (lo, hi) = if xa <= xb { (xa, xb) } else { (xb, xa) };
    let mut h = Sha256::new();
    h.update(seed);
    h.update(lo);
    h.update(hi);
    Ok(h.finalize().into())
}

impl SlotInfo {
    /// Interior positions to fill.
    pub fn positions(&self) -> u32 {
        self.total_pairs.saturating_sub(2)
    }

    /// Whether the interior positions can no longer change at `ledger`:
    /// selection has closed, or the window has passed with every position
    /// claimed, after which the mint takes no claim.
    pub fn positions_fixed(&self, ledger: u32) -> bool {
        self.closed
            || (self.seed.is_some()
                && ledger > self.claim_deadline
                && self.claims.len() as u32 >= self.positions())
    }

    /// The whole chain in order, end pairs included, once positions are
    /// fixed (see [`Self::positions_fixed`]); `None` before.
    pub fn chain(&self, ledger: u32) -> Option<Vec<(String, String)>> {
        if self.closed {
            return Some(self.pairs.clone());
        }
        if !self.positions_fixed(ledger) {
            return None;
        }
        let k = self.positions() as usize;
        let mut out = vec![self.pairs.first()?.clone()];
        out.extend(self.claims.iter().take(k).map(|c| c.pair.clone()));
        out.push(self.pairs.last()?.clone());
        Some(out)
    }

    /// Whether `me` should extend this print next, given the chain it was
    /// handed: the slot still printing, for that chain's event id, with
    /// exactly the chain's links confirmed so far, each signed by the pair
    /// the slot assigns it, and naming `me` for the next link.
    ///
    /// `prior_links` is `(partial_public_key, node_a_public, node_b_public)`
    /// per link, in order. The signer check is load-bearing: event id and
    /// partial keys are public once confirmed and nothing binds a partial key
    /// to its signers, so without it a stranger copies both onto throwaway
    /// keys. With it, every earlier link carries signatures from the slot's
    /// own pairs, which a stranger cannot make. Pair members are compared as
    /// a set, since both must sign either way.
    ///
    /// A node asks this before extending: the extend
    /// endpoint is reachable by anyone and the chain it carries proves only
    /// its own consistency. Here, in the library, so that a node and any
    /// harness that stands in for one run the same check.
    ///
    /// The chain's pairs are read from the claims until selection closes
    /// ([`Self::chain`]): position 1 is asked to extend before its own
    /// confirmation closes selection. `ledger` is the current ledger, and
    /// a slot whose positions can still change admits nobody.
    pub fn admits_next(
        &self,
        me: &str,
        event_id: [u8; 32],
        prior_links: &[([u8; 32], [u8; 32], [u8; 32])],
        ledger: u32,
    ) -> Result<(), String> {
        let id = self.slot_id;
        if self.state != TokenState::Printing {
            return Err(format!("slot {id} is not printing"));
        }
        let pairs = self
            .chain(ledger)
            .ok_or_else(|| format!("slot {id}'s positions are not fixed yet"))?;
        if self.event_id != event_id {
            return Err(format!("chain is not for slot {id}: event id differs"));
        }
        let keys: Vec<[u8; 32]> = prior_links.iter().map(|l| l.0).collect();
        if self.partial_keys != keys {
            return Err(format!(
                "chain is not slot {id}'s: its {} link(s) are not the {} confirmed on-chain",
                keys.len(),
                self.partial_keys.len()
            ));
        }
        let raw = |addr: &str| {
            stellar_strkey::ed25519::PublicKey::from_string(addr)
                .map(|k| k.0)
                .map_err(|e| format!("slot {id} names {addr}: {e}"))
        };
        for (i, (_, a, b)) in prior_links.iter().enumerate() {
            let (pa, pb) = pairs
                .get(i)
                .ok_or_else(|| format!("slot {id} has no pair for link {i}"))?;
            let (pa, pb) = (raw(pa)?, raw(pb)?);
            if !((*a == pa && *b == pb) || (*a == pb && *b == pa)) {
                return Err(format!(
                    "chain is not slot {id}'s: link {i} is not signed by the pair it assigns"
                ));
            }
        }
        match pairs.get(prior_links.len()) {
            Some((a, b)) if a == me || b == me => Ok(()),
            _ => Err(format!("slot {id} does not assign link {} to this node", prior_links.len())),
        }
    }

    pub fn participants(&self) -> Vec<String> {
        self.pairs
            .iter()
            .flat_map(|(a, b)| [a.clone(), b.clone()])
            .collect()
    }

    /// Assemble a slot from its persistent core (`SlotCore`) and, if it is
    /// still there, its temporary draw (`SlotDraw`).
    fn from_parts(core: &ScVal, draw: Option<&ScVal>) -> Result<Self, ClientError> {
        let map = match core {
            ScVal::Map(Some(m)) => m,
            _ => return Err(ClientError::XdrDecode(format!("expected Map, got {core:?}"))),
        };
        let draw = match draw {
            None => None,
            Some(ScVal::Map(Some(m))) => Some(m),
            Some(other) => {
                return Err(ClientError::XdrDecode(format!("expected a draw Map, got {other:?}")));
            }
        };
        let lapsed = draw.is_none();
        let pair_of = |v: &ScVal| -> Result<(String, String), ClientError> {
            match v {
                ScVal::Map(Some(m)) => Ok((
                    scval_to_address(field(m, "node_a")?)?,
                    scval_to_address(field(m, "node_b")?)?,
                )),
                other => Err(ClientError::XdrDecode(format!("expected a pair Map, got {other:?}"))),
            }
        };
        let Some(dm) = draw else {
            let pairs = vec![pair_of(field(map, "first_pair")?)?, pair_of(field(map, "last_pair")?)?];
            return Self::assemble(map, pairs, Vec::new(), None, Vec::new(), lapsed);
        };
        let pairs = match field(dm, "pairs")? {
            ScVal::Vec(Some(v)) => v.0.iter().map(pair_of).collect::<Result<Vec<_>, _>>()?,
            other => {
                return Err(ClientError::XdrDecode(format!("expected pairs Vec, got {other:?}")));
            }
        };
        let claims = match field(dm, "claims")? {
            ScVal::Vec(Some(v)) => v
                .0
                .iter()
                .map(|c| match c {
                    ScVal::Map(Some(m)) => Ok(ClaimInfo {
                        score: scval_to_bytes32(field(m, "score")?)?,
                        pair: pair_of(field(m, "pair")?)?,
                        volunteer_a: scval_to_bool(field(m, "volunteer_a")?)?,
                        volunteer_b: scval_to_bool(field(m, "volunteer_b")?)?,
                    }),
                    other => Err(ClientError::XdrDecode(format!("expected a claim Map, got {other:?}"))),
                })
                .collect::<Result<Vec<_>, _>>()?,
            other => {
                return Err(ClientError::XdrDecode(format!("expected claims Vec, got {other:?}")));
            }
        };
        let seed = match field(dm, "seed")? {
            ScVal::Void => None,
            v => Some(scval_to_bytes32(v)?),
        };
        let partial_keys = match field(dm, "partial_keys")? {
            ScVal::Vec(Some(v)) => v.0.iter().map(scval_to_bytes32).collect::<Result<Vec<_>, _>>()?,
            other => {
                return Err(ClientError::XdrDecode(format!(
                    "expected partial_keys Vec, got {other:?}"
                )));
            }
        };
        Self::assemble(map, pairs, partial_keys, seed, claims, lapsed)
    }

    /// The core's fields, with the draw's parts already decoded.
    fn assemble(
        map: &ScMap,
        pairs: Vec<(String, String)>,
        partial_keys: Vec<[u8; 32]>,
        seed: Option<[u8; 32]>,
        claims: Vec<ClaimInfo>,
        lapsed: bool,
    ) -> Result<Self, ClientError> {
        Ok(SlotInfo {
            slot_id: scval_to_u32(field(map, "slot_id")?)?,
            depositor: scval_to_address(field(map, "depositor")?)?,
            amount: scval_to_i128(field(map, "amount")?)?,
            total_pairs: scval_to_u32(field(map, "total_pairs")?)?,
            pairs,
            completed_links: scval_to_u32(field(map, "completed_links")?)?,
            state: TokenState::from_u32(scval_to_u32(field(map, "state")?)?),
            event_id: scval_to_bytes32(field(map, "event_id")?)?,
            partial_keys,
            beacon_round: scval_to_u64(field(map, "beacon_round")?)?,
            seed,
            claim_deadline: scval_to_u32(field(map, "claim_deadline")?)?,
            claims,
            closed: scval_to_bool(field(map, "closed")?)?,
            last_progress: scval_to_u32(field(map, "last_progress")?)?,
            created_at: scval_to_u32(field(map, "created_at")?)?,
            filled: scval_to_bool(field(map, "filled")?)?,
            volunteers: scval_to_u32(field(map, "volunteers")?)?,
            lapsed,
        })
    }
}

fn scval_to_u64(v: &ScVal) -> Result<u64, ClientError> {
    match v {
        ScVal::U64(n) => Ok(*n),
        other => Err(ClientError::XdrDecode(format!("expected U64, got {other:?}"))),
    }
}

/// Find a field by symbol name in a contract-struct `ScMap`.
pub(crate) fn field<'a>(map: &'a ScMap, name: &str) -> Result<&'a ScVal, ClientError> {
    map.0
        .iter()
        .find(|e| matches!(&e.key, ScVal::Symbol(s) if s.0.to_string() == name))
        .map(|e| &e.val)
        .ok_or_else(|| ClientError::XdrDecode(format!("record missing field `{name}`")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::SorobanRpcClient;
    use kenter_crypto::keypair::StellarKeypair;

    fn test_client() -> MintClient {
        let rpc = SorobanRpcClient::new(
            "https://soroban-testnet.stellar.org",
            "Test SDF Network ; September 2015",
        );
        let tx = TxBuilder::new(rpc, StellarKeypair::random());
        MintClient::new(tx, "CAGAYH64V6RYB2TQDT2IMMIJUWOPX67RZN5KCG7EBNZ5U6J4G3ZCBAUB")
    }

    // -- The answer must be about the question --
    //
    // A direct ledger read must not just take `entries[0]` and decode it:
    // the entry's own contract and key are compared against what was
    // asked for. The payee's G2/G3 gates are self-certifying only if the
    // record they certify is the record they asked about.

    use stellar_xdr::curr::{
        ContractDataEntry, ExtensionPoint, LedgerEntryData, Limits, WriteXdr,
    };

    /// A `ContractData` entry as the RPC would return it, base64-XDR.
    fn entry_xdr(contract: ScAddress, key: ScVal, val: ScVal) -> String {
        let data = LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract,
            key,
            durability: ContractDataDurability::Persistent,
            val,
        });
        base64::engine::general_purpose::STANDARD
            .encode(data.to_xdr(Limits::none()).unwrap())
        }

    /// The check itself, run against a decoded entry rather than a live
    /// RPC: `read_contract_data` is one `get_ledger_entries` away from
    /// being testable offline, and the comparison is the part worth
    /// pinning.
    fn validate(c: &MintClient, want: &ScVal, entry_b64: &str) -> Result<ScVal, ClientError> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(entry_b64)
            .unwrap();
        let data = LedgerEntryData::from_xdr(raw.as_slice(), Limits::none()).unwrap();
        let LedgerEntryData::ContractData(cd) = data else { panic!("not ContractData") };
        if cd.contract != c.contract_scaddress()? {
            return Err(ClientError::WrongLedgerEntry("contract".into()));
        }
        if &cd.key != want {
            return Err(ClientError::WrongLedgerEntry("key".into()));
        }
        Ok(cd.val)
    }

    /// An entry for a different note must not answer for this one.
    #[test]
    fn a_record_for_another_token_is_refused() {
        let c = test_client();
        let want = MintClient::token_data_key(7);
        let other = MintClient::token_data_key(8);
        let e = entry_xdr(c.contract_scaddress().unwrap(), other, ScVal::U32(1));
        assert!(matches!(
            validate(&c, &want, &e),
            Err(ClientError::WrongLedgerEntry(_))
        ));
    }

    /// Nor must an entry from another contract entirely.
    #[test]
    fn a_record_from_another_contract_is_refused() {
        let c = test_client();
        let want = MintClient::token_data_key(7);
        let elsewhere = ScAddress::Contract(ContractId(Hash([0x99u8; 32])));
        let e = entry_xdr(elsewhere, want.clone(), ScVal::U32(1));
        assert!(matches!(
            validate(&c, &want, &e),
            Err(ClientError::WrongLedgerEntry(_))
        ));
    }

    /// A slot entry must not answer a question about a token, even though
    /// both are `ContractData` under the same contract.
    #[test]
    fn a_slot_record_is_refused_for_a_token_read() {
        let c = test_client();
        let want = MintClient::token_data_key(7);
        let slot = MintClient::slot_data_key(7);
        let e = entry_xdr(c.contract_scaddress().unwrap(), slot, ScVal::U32(1));
        assert!(matches!(
            validate(&c, &want, &e),
            Err(ClientError::WrongLedgerEntry(_))
        ));
    }

    /// And the honest answer still goes through.
    #[test]
    fn the_right_record_is_accepted() {
        let c = test_client();
        let want = MintClient::token_data_key(7);
        let e = entry_xdr(c.contract_scaddress().unwrap(), want.clone(), ScVal::U32(42));
        assert_eq!(validate(&c, &want, &e).unwrap(), ScVal::U32(42));
    }

    /// An unreadable mode must not be read as the mode with no owner check.
    ///
    /// `from_u32` fell back to `PureBearer`, which tells a payee to skip
    /// the G3 ownership gate — exactly backwards for a value nobody could
    /// parse.
    #[test]
    fn an_unknown_token_mode_is_refused_rather_than_read_as_bearer() {
        assert_eq!(TokenMode::from_u32(0).unwrap(), TokenMode::PureBearer);
        assert_eq!(TokenMode::from_u32(1).unwrap(), TokenMode::Spend);
        assert!(TokenMode::from_u32(2).is_err(), "an unknown mode must not decode");
        assert!(TokenMode::from_u32(99).is_err());
    }

    /// Build a ledger key the way `token_or_marker` does.
    fn token_key(c: &MintClient, slot: u32) -> String {
        c.ledger_key_b64(&MintClient::token_data_key(slot)).unwrap()
    }

    fn slot_key(c: &MintClient, slot: u32) -> String {
        c.ledger_key_b64(&MintClient::slot_data_key(slot)).unwrap()
    }

    #[test]
    fn token_ledger_key_is_deterministic() {
        let c = test_client();
        let k1 = token_key(&c, 7);
        assert_eq!(k1, token_key(&c, 7));
        assert!(!k1.is_empty());
        // Different slots → different ledger keys.
        assert_ne!(k1, token_key(&c, 8));
    }

    #[test]
    fn slot_ledger_key_is_deterministic_and_distinct_per_slot() {
        let c = test_client();
        assert_eq!(slot_key(&c, 7), slot_key(&c, 7));
        assert_ne!(slot_key(&c, 7), slot_key(&c, 8));
        // A slot key and a token key must never collide: both are
        // ContractData under the same contract, separated only by the symbol.
        assert_ne!(slot_key(&c, 7), token_key(&c, 7));
    }

    /// Decoding `PrintSlot` is guesswork until a real one has been read: the
    /// struct is nested (a `Vec` of two-field maps) and a wrong field name
    /// fails at runtime, not at compile time. Slot 0 of the XLM mint is a
    /// self-print from the GUI and will not change.
    #[tokio::test]
    #[ignore = "network"]
    async fn a_live_slot_decodes() {
        let c = test_client();
        let slot = c.get_slot(0).await.expect("read").expect("slot 0 exists");
        assert_eq!(slot.slot_id, 0);
        assert!(slot.amount > 0);
        assert_eq!(slot.pairs.len(), slot.total_pairs as usize);
        assert_eq!(slot.participants().len(), slot.pairs.len() * 2);
        assert!(slot.depositor.starts_with('G'), "{}", slot.depositor);
        for (a, b) in &slot.pairs {
            assert!(a.starts_with('G') && b.starts_with('G'), "{a} {b}");
        }
        // A slot that never existed reads as absent rather than erroring.
        assert!(c.get_slot(u32::MAX).await.expect("read").is_none());

        // And the counter agrees that slot 0 is in range.
        let next = c.next_slot_id().await.expect("next_slot_id");
        assert!(next > 0, "the XLM mint has printed at least once");
        assert!(c.get_slot(next).await.expect("read").is_none(), "next is one past the end");
    }

    #[test]
    fn token_state_from_u32() {
        assert_eq!(TokenState::from_u32(1), TokenState::Active);
        assert_eq!(TokenState::from_u32(2), TokenState::Redeemed);
        assert_eq!(TokenState::from_u32(9), TokenState::Unknown(9));
    }
}

#[cfg(test)]
mod admits_next_tests {
    use super::{ClaimInfo, SlotInfo, TokenState};

    /// A ledger after the rig's claim deadline.
    const LEDGER: u32 = 20;

    /// Real-shaped addresses, since the signer check decodes them.
    fn addr(seed: u8) -> (String, [u8; 32]) {
        let raw = [seed; 32];
        (stellar_strkey::ed25519::PublicKey(raw).to_string().as_str().to_owned(), raw)
    }

    struct Rig {
        slot: SlotInfo,
        me: String,
        partner: String,
        link0: ([u8; 32], [u8; 32], [u8; 32]),
    }

    fn rig() -> Rig {
        let (d1, d1r) = addr(1);
        let (d2, d2r) = addr(2);
        let (me, _) = addr(3);
        let (partner, _) = addr(4);
        Rig {
            slot: SlotInfo {
                slot_id: 4,
                depositor: d1.clone(),
                amount: 1_000_000,
                total_pairs: 3,
                pairs: vec![(d1.clone(), d2.clone()), (me.clone(), partner.clone()), (d1, d2)],
                completed_links: 1,
                state: TokenState::Printing,
                event_id: [7; 32],
                partial_keys: vec![[9; 32]],
                beacon_round: 1,
                seed: Some([5; 32]),
                claim_deadline: 10,
                claims: vec![],
                closed: true,
                last_progress: 11,
                created_at: 1,
                filled: true,
                volunteers: 0,
                lapsed: false,
            },
            me,
            partner,
            link0: ([9; 32], d1r, d2r),
        }
    }

    #[test]
    fn the_real_next_link_is_admitted() {
        let r = rig();
        r.slot.admits_next(&r.me, [7; 32], &[r.link0], LEDGER).unwrap();
        r.slot.admits_next(&r.partner, [7; 32], &[r.link0], LEDGER).unwrap();
        // Pair members in either order.
        let swapped = (r.link0.0, r.link0.2, r.link0.1);
        r.slot.admits_next(&r.me, [7; 32], &[swapped], LEDGER).unwrap();
    }

    /// An unrelated chain carrying a real slot's id.
    #[test]
    fn a_chain_for_another_event_is_refused() {
        let r = rig();
        assert!(r.slot.admits_next(&r.me, [8; 32], &[r.link0], LEDGER).is_err());
    }

    /// The real event id and the real on-chain
    /// partial keys, copied onto links signed by throwaway keys.
    #[test]
    fn a_look_alike_chain_signed_by_strangers_is_refused() {
        let r = rig();
        let (_, x) = addr(50);
        let (_, y) = addr(51);
        let e = r.slot.admits_next(&r.me, [7; 32], &[([9; 32], x, y)], LEDGER).unwrap_err();
        assert!(e.contains("not signed by the pair"), "{e}");
        // One real signer is not enough either.
        let half = (r.link0.0, r.link0.1, y);
        assert!(r.slot.admits_next(&r.me, [7; 32], &[half], LEDGER).is_err());
    }

    #[test]
    fn links_that_are_not_the_confirmed_ones_are_refused() {
        let r = rig();
        let wrong = ([2; 32], r.link0.1, r.link0.2);
        assert!(r.slot.admits_next(&r.me, [7; 32], &[wrong], LEDGER).is_err());
        assert!(r.slot.admits_next(&r.me, [7; 32], &[], LEDGER).is_err());
        assert!(r.slot.admits_next(&r.me, [7; 32], &[r.link0, r.link0], LEDGER).is_err());
    }

    #[test]
    fn a_node_not_assigned_the_next_link_is_refused() {
        let r = rig();
        let (other, _) = addr(1);
        assert!(r.slot.admits_next(&other, [7; 32], &[r.link0], LEDGER).is_err());
    }

    /// Before closing: position 1 is read off the claims, but only once
    /// they can no longer change.
    fn open_rig() -> Rig {
        let mut r = rig();
        let (d1, d2) = r.slot.pairs[0].clone();
        r.slot.pairs = vec![(d1.clone(), d2.clone()), (d1, d2)];
        r.slot.closed = false;
        r.slot.claims = vec![ClaimInfo {
            score: [1; 32],
            pair: (r.me.clone(), r.partner.clone()),
            volunteer_a: false,
            volunteer_b: false,
        }];
        r
    }

    #[test]
    fn position_one_is_admitted_from_fixed_claims_before_closing() {
        let r = open_rig();
        r.slot.admits_next(&r.me, [7; 32], &[r.link0], LEDGER).unwrap();
    }

    #[test]
    fn nobody_is_admitted_while_claims_can_still_change() {
        let r = open_rig();
        // Inside the window: a lower score could still displace this pair.
        let e = r.slot.admits_next(&r.me, [7; 32], &[r.link0], 5).unwrap_err();
        assert!(e.contains("not fixed"), "{e}");
        // After it, but short of every position being claimed.
        let mut short = open_rig();
        short.slot.total_pairs = 4;
        assert!(short.slot.admits_next(&short.me, [7; 32], &[short.link0], LEDGER).is_err());
    }

    #[test]
    fn a_slot_that_is_not_printing_is_refused() {
        let mut r = rig();
        r.slot.state = TokenState::Active;
        assert!(r.slot.admits_next(&r.me, [7; 32], &[r.link0], LEDGER).is_err());
    }
}

#[cfg(test)]
mod score_tests {
    /// The same vector the mint's suite pins
    /// (`the_score_matches_its_published_vector`): this function and the
    /// contract must agree byte for byte.
    /// The vector `the_seed_matches_its_published_vector` pins in the
    /// mint's suite, for the quicknet fixture round.
    #[test]
    fn the_seed_matches_the_mints() {
        let sig: [u8; 96] = hex::decode(
            "0414a8586cf92eaca970d9d177ff4a323506c409e65a2862df44dfb5a0959073bb989d31a2844fdb69043a918a2a0d6e0104bf3a1d2f71367e0d31e654fb0cce3d75cb50f22204c8c52c7aa741faedf428f8bbf151be33a8ad846a787a22d5fe",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let seed = super::selection_seed("CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAITA4", 0, &sig).unwrap();
        assert_eq!(hex::encode(seed), "082624f288319fb4b4aee6f05d5d8cecbaa76623b2592c2a3c5c5a6e892b2950");
    }

    #[test]
    fn the_score_matches_the_mints() {
        let s = super::selection_score(
            [7u8; 32],
            "GABQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQHGPC",
            "GACAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAJJHP",
        )
        .unwrap();
        let hex: String = s.iter().map(|x| format!("{x:02x}")).collect();
        assert_eq!(hex, "8d48c89eb1f7b0c75abd5db8bf365430f266ce2341d9d8997eae8cbcc0a8110f");
        // Unordered.
        let r = super::selection_score(
            [7u8; 32],
            "GACAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAJJHP",
            "GABQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQHGPC",
        )
        .unwrap();
        assert_eq!(s, r);
    }
}

#[cfg(test)]
mod neighbour_tests {
    use super::*;
    use stellar_xdr::curr::LedgerFootprint;

    fn data_key(key: ScVal, durability: ContractDataDurability) -> LedgerKey {
        LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(ContractId(Hash([9; 32]))),
            key,
            durability,
        })
    }

    /// Two requests in one ledger simulate the same slot id; the one applied
    /// second needs the next id's keys declared, or it traps.
    #[test]
    fn a_request_declares_the_next_slots_too() {
        let fp = LedgerFootprint {
            read_only: Default::default(),
            read_write: vec![
                data_key(MintClient::unit_data_key("NextSlotId").unwrap(), ContractDataDurability::Persistent),
                data_key(MintClient::slot_data_key(8), ContractDataDurability::Persistent),
                data_key(MintClient::draw_data_key(8), ContractDataDurability::Temporary),
            ]
            .try_into()
            .unwrap(),
        };
        let keys = neighbour_slot_keys(&fp, 2);
        assert_eq!(
            keys,
            vec![
                data_key(MintClient::slot_data_key(9), ContractDataDurability::Persistent),
                data_key(MintClient::draw_data_key(9), ContractDataDurability::Temporary),
                data_key(MintClient::slot_data_key(10), ContractDataDurability::Persistent),
                data_key(MintClient::draw_data_key(10), ContractDataDurability::Temporary),
            ]
        );
        // A footprint that writes no slot gets nothing added.
        let empty = LedgerFootprint { read_only: Default::default(), read_write: Default::default() };
        assert!(neighbour_slot_keys(&empty, 4).is_empty());
    }
}
