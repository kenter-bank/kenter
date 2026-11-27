//! Networked printing: walk a partial token around the nodes the network
//! chose (`docs/architecture/node-selection.md`).
//!
//! Both clients print through here: the CLI's `print-net` and the window's
//! Deposit. It is a crate of its own because they are sibling binaries that
//! cannot reach each other -- see `Cargo.toml` for why neither `kenter-client`
//! nor `kenter-wallet` was the right home.
//!
//! # The shape
//!
//! The depositor holds the first and the last pair. `PartialToken::initiate`
//! needs both keys of pair 0, and `assemble_bearer_token` closes the chain
//! with the requestor's own pair, which is what guarantees one honest pair
//! (`docs/architecture/security-model.md`). So a print with `k` network
//! nodes is `k + 2` pairs.
//!
//! The depositor names only those two end pairs. They are exempt from the
//! roster check and need no stake. The `k` interior pairs claim their
//! positions after a drand round seeds the slot, so the depositor cannot
//! choose them, and the wallet needs no list of nodes to print
//! ([`print_selected`]).

use kenter_client::{Beacon, MintClient, RosterClient, SelectionInfo, SlotInfo, TokenMode};
use kenter_crypto::chain_data::token_chain_hash;
use kenter_crypto::container::{
    deserialize_partial_token, serialize_bearer_token, serialize_partial_token,
};
use kenter_crypto::keypair::StellarKeypair;
use kenter_crypto::token::{assemble_bearer_token, BearerToken, MintBinding, PartialToken};
use kenter_network::handlers::{build_extend_request, parse_extend_response};
use kenter_network::protocol::{ExtendResponse, HealthResponse};

/// How a depositor reaches nodes: plain HTTPS to the relay's open
/// `/proxy/<node>/<path>` route.
///
/// No relay session of its own, signed in with a Stellar address. A
/// roster-gated relay admits only roster members, and a depositor does not
/// join the roster (its end pairs are exempt, and joining would stake a
/// bond for nothing), so with a session no ordinary holder could print on a
/// gated relay at all.
///
/// A session would buy the depositor nothing. The relay's `/proxy` route
/// already reaches any registered node without one, and the nodes check
/// every request on its merits (`SlotInfo::admits_next`). Nothing a print
/// sends is secret: the chain's links and partial keys are published on
/// the ledger as each node confirms, and the depositor's own shards, the
/// final link and the claim key never leave this machine. TLS protects
/// the request from the network, and the relay reads it, with or without
/// a session. The relay learns the depositor's IP but not their Stellar
/// address.
/// The largest reply a node may send, in bytes.
pub const MAX_REPLY: usize = 256 * 1024;

#[derive(Clone)]
pub struct NodeRelay {
    base: String,
    http: reqwest::Client,
}

impl NodeRelay {
    /// `host` with its port if any, e.g. `relay.example.org` or
    /// `127.0.0.1:8000`. `secure` is `https`; plain `http` is for a relay
    /// on this machine and nothing else.
    pub fn new(host: &str, secure: bool) -> Result<Self, String> {
        let scheme = if secure { "https" } else { "http" };
        let http = reqwest::Client::builder()
            // A node answers `extend` only after its `confirm_link` lands,
            // which can take most of a minute; the relay waits 120s.
            .timeout(std::time::Duration::from_secs(130))
            // A relay is reached at the host the print chose, and nowhere
            // else: a redirect could send the request to plain http or an
            // address on the depositor's own network.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        Ok(NodeRelay { base: format!("{scheme}://{host}"), http })
    }

    /// `method path` on the node at `node`, through the relay, as JSON.
    pub async fn request_json(
        &self,
        node: &str,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value, String> {
        let url = format!("{}/proxy/{node}{path}", self.base);
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| format!("{method}: {e}"))?;
        let mut req = self.http.request(method, &url);
        if let Some(b) = body {
            req = req.json(b);
        }
        let mut resp = req.send().await.map_err(|e| format!("{node} {path}: {e}"))?;
        let status = resp.status();
        // Read at most MAX_REPLY: an extend reply is a few kilobytes, and
        // a node should not be able to make the wallet read without end.
        let mut bytes = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| format!("{node} {path}: {e}"))? {
            bytes.extend_from_slice(&chunk);
            if bytes.len() > MAX_REPLY {
                return Err(format!("{node} {path}: reply larger than {MAX_REPLY} bytes"));
            }
        }
        let text = String::from_utf8_lossy(&bytes).into_owned();
        if !status.is_success() {
            return Err(format!("{node} {path} returned HTTP {}: {text}", status.as_u16()));
        }
        serde_json::from_str(&text)
            .map_err(|e| format!("{node} {path}: body is not JSON: {e} ({text})"))
    }
}

#[derive(Debug, Clone)]
pub struct PairAddresses {
    pub node_a: String,
    pub node_b: String,
}

/// Ask a node who it is paired with, so the depositor can name both members.
pub async fn discover_pair(
    relay: &NodeRelay,
    node_address: &str,
) -> Result<PairAddresses, String> {
    let raw = relay
        .request_json(node_address, "POST", "/kenter/health", None)
        .await
        .map_err(|e| format!("health {node_address}: {e}"))?;

    let health: HealthResponse = serde_json::from_value(raw.clone())
        .map_err(|e| format!("health {node_address}: {raw} ({e})"))?;
    if health.status != "ok" {
        return Err(format!("node {node_address} is not ok: {}", health.status));
    }
    let node_a = health.node_address.unwrap_or_else(|| node_address.to_string());
    let node_b = health.partner_address.ok_or_else(|| {
        format!(
            "node {node_address} did not report a pair partner — it cannot take part \
             in a print, because request_print must name both members of its pair"
        )
    })?;
    Ok(PairAddresses { node_a, node_b })
}

/// Everything the depositor contributes to a networked print.
pub struct DepositorPairs {
    /// Opens the chain (link 0).
    pub first: (StellarKeypair, StellarKeypair),
    /// Closes it at assembly (link n-1) — the pair that keeps the token safe
    /// from the network (`docs/architecture/security-model.md`).
    pub last: (StellarKeypair, StellarKeypair),
}

impl DepositorPairs {
    /// One funded identity fills all four of the depositor's slots.
    ///
    /// Legal, and the default. The mint exempts pairs `0` and `n-1` from
    /// the distinctness and roster checks because they are the
    /// depositor's own: repeating one key there costs only the
    /// depositor, who holds both ends by construction and is the honest
    /// party at each. Requiring four distinct addresses would mean four
    /// funded, roster-joined, separately bonded accounts before anyone
    /// could print their own note — a bond
    /// posted against misbehaviour that can only harm its poster.
    ///
    /// What it does cost: both depositor pairs derive the *same* shard
    /// (ECDH is deterministic in its inputs), so they contribute
    /// `2 × shard` rather than two independent ones, and
    /// `TokenRecord.participants` repeats one address four times, which
    /// makes the arrangement visible on the ledger. Neither weakens the
    /// note against the nodes, who never learn that shard either way.
    /// [`Self::random`] is there for a deployment that wants the pair
    /// count to mean exactly what it says.
    pub fn testbed(keypair: &StellarKeypair) -> Self {
        DepositorPairs {
            first: (keypair.clone(), keypair.clone()),
            last: (keypair.clone(), keypair.clone()),
        }
    }

    /// Four distinct keys, so the pair count means exactly what it says.
    ///
    /// No caller today. The end pairs are exempt from the roster check,
    /// so these need no bond — but `confirm_link` still requires the
    /// submitter to be a named member of its pair, so a caller using
    /// this must submit the two depositor links from two of these keys
    /// rather than from one. [`Self::testbed`] avoids that and is the
    /// default.
    pub fn random() -> Self {
        DepositorPairs {
            first: (StellarKeypair::random(), StellarKeypair::random()),
            last: (StellarKeypair::random(), StellarKeypair::random()),
        }
    }
    pub fn addresses(&self) -> (PairAddresses, PairAddresses) {
        (
            PairAddresses {
                node_a: self.first.0.stellar_address(),
                node_b: self.first.1.stellar_address(),
            },
            PairAddresses {
                node_a: self.last.0.stellar_address(),
                node_b: self.last.1.stellar_address(),
            },
        )
    }
}

/// A `C…` contract strkey as the raw 32 bytes a note carries.
///
/// `kenter-crypto` holds no strkey dependency so that it builds for
/// wasm, so the encoding boundary lives out here.
fn parse_contract_id(id: &str) -> Result<[u8; 32], String> {
    stellar_strkey::Contract::from_string(id)
        .map(|c| c.0)
        .map_err(|e| format!("not a contract id ({id}): {e}"))
}

/// Check that a node's reply is the chain we sent it, plus one link from the
/// pair we named for it -- and nothing else.
///
/// The depositor is the only party that can check this before it matters:
/// `register_token` binds whatever chain hash it is given, and the mint never
/// sees the chain until a Path B redemption, which verifies it against the
/// slot's event id and refuses a chain built for any other. By then the slot is
/// gone and the escrow cannot be cancelled or redeemed. The check is here on
/// purpose -- the chain's proof is verified during Path B redemption or
/// locally by the depositor -- and the mint does not repeat it at
/// registration, because that would publish the chain at mint time.
///
/// Everything is compared rather than re-derived: the header and initiation
/// proof unchanged, every earlier link byte-identical, exactly one new link at
/// the next index signed by the two keys `request_print` named, and the whole
/// chain internally consistent.
pub fn check_extension(
    before: &PartialToken,
    after: &PartialToken,
    pair: &PairAddresses,
) -> Result<(), String> {
    // Compare against what the node was actually sent: `before` as it
    // reads back off the wire. The codec is not an identity on the struct
    // -- it stamps the container version, for one -- and comparing the
    // in-memory original would refuse the first reply of every honest
    // print.
    let before = &deserialize_partial_token(
        &serialize_partial_token(before).map_err(|e| format!("encode partial: {e}"))?,
    )
    .map_err(|e| format!("decode partial: {e}"))?;
    if canon(&after.header) != canon(&before.header) {
        return Err("returned a chain under a different header (event id, value or time)".into());
    }
    if canon(&after.initiation_proof) != canon(&before.initiation_proof) {
        return Err("returned a chain with a different initiation proof".into());
    }
    let n = before.chain.links.len();
    if after.chain.links.len() != n + 1 {
        return Err(format!(
            "returned {} links, expected {} (one added)",
            after.chain.links.len(),
            n + 1
        ));
    }
    if before.remaining_pairs == 0 || after.remaining_pairs != before.remaining_pairs - 1 {
        return Err("returned a chain whose remaining pair count did not step by one".into());
    }
    for (i, (old, new)) in before.chain.links.iter().zip(&after.chain.links).enumerate() {
        if canon(old) != canon(new) {
            return Err(format!("returned a chain whose link {i} is not the one sent"));
        }
    }
    let link = &after.chain.links[n];
    if link.link_index as usize != n {
        return Err(format!("new link claims index {}, expected {n}", link.link_index));
    }
    let raw = |addr: &str| {
        stellar_strkey::ed25519::PublicKey::from_string(addr)
            .map(|k| k.0)
            .map_err(|e| format!("pair address {addr}: {e}"))
    };
    if link.node_a_public != raw(&pair.node_a)? || link.node_b_public != raw(&pair.node_b)? {
        return Err("new link is not signed by the pair named in request_print".into());
    }
    after
        .verify_chain_integrity()
        .map_err(|e| format!("returned chain does not verify: {e}"))
}

/// Canonical bytes, for comparing types that are `Serialize` but not
/// `PartialEq`.
fn canon<T: serde::Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_default()
}

/// Progress callback, so the caller owns all the printing.
pub type Progress<'a> = &'a dyn Fn(&str);

/// How the depositor reaches a selected node.
pub enum Reach {
    /// Through the relay its roster endpoint names: `https://<node>.<relay>`
    /// means `https://<relay>/proxy/<node>/...`. What a wallet uses, so it
    /// needs no relay setting at all.
    ///
    /// **Only a relay in `relays`**, the build's own list
    /// (`Profile::relays`). A node names its relay, and an operator who
    /// named a host of their own would learn the IP of every depositor its
    /// pair is selected for. A node behind any other
    /// relay is treated as one that does not serve, and is skipped.
    Roster { roster: RosterClient, relays: Vec<String> },
    /// Through one relay for every node: a local test rig, whose relay
    /// advertises a domain it is not reachable at.
    Fixed(NodeRelay),
}

impl Reach {
    async fn relay_for(&mut self, node: &str) -> Result<NodeRelay, String> {
        match self {
            Reach::Fixed(r) => Ok(r.clone()),
            Reach::Roster { roster, relays } => {
                let ep = roster
                    .lookup(node)
                    .await
                    .map_err(|e| format!("roster lookup {node}: {e}"))?
                    .ok_or_else(|| format!("{node} has no endpoint on the roster"))?;
                let host = relay_host_of(&ep, node)?;
                if !relays.iter().any(|r| r.eq_ignore_ascii_case(&host)) {
                    return Err(format!("{node} is behind {host}, which is not one of this build's relays"));
                }
                NodeRelay::new(&host, true)
            }
        }
    }
}

/// The relay host a node's roster endpoint names.
///
/// An endpoint is `https://<node address>.<relay host>`, which the node's
/// daemon checks before recording it (`valid_endpoint`). Only that shape
/// is accepted here: https, the node's own address as the first label, a
/// host with no path. Anything else would send the print somewhere the
/// node never said it was.
pub fn relay_host_of(endpoint: &str, node: &str) -> Result<String, String> {
    let bad = |why: &str| Err(format!("{node}'s endpoint {endpoint:?}: {why}"));
    let Some(rest) = endpoint.strip_prefix("https://") else {
        return bad("not https");
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let lower = rest.to_ascii_lowercase();
    let prefix = format!("{}.", node.to_ascii_lowercase());
    let Some(host) = lower.strip_prefix(&prefix) else {
        return bad("does not start with the node's own address");
    };
    if host.is_empty()
        || host.contains('/')
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':')
    {
        return bad("not a plain host");
    }
    // A name, not an address: an IP literal or localhost would point the
    // wallet at a machine of the node's choosing, the depositor's own
    // network included.
    let name = host.rsplit_once(':').map_or(host, |(h, _)| h);
    if name.parse::<std::net::IpAddr>().is_ok() || name == "localhost" || !name.contains('.') {
        return bad("not a public host name");
    }
    Ok(host.to_string())
}

/// How long to keep waiting for claims after the window, before giving up
/// on a draw the network could not fill (about two minutes).
const CLAIM_GRACE_LEDGERS: u32 = 24;

/// How often the print re-reads the slot while it waits.
const POLL: std::time::Duration = std::time::Duration::from_secs(4);

/// What a print is for, as `request_print` and the note record it.
pub struct PrintOrder {
    pub total_pairs: u32,
    pub event_id: [u8; 32],
    pub denomination: u64,
    pub timestamp: i64,
    pub mode: TokenMode,
    pub owner_commitment: [u8; 32],
}

/// Print one note with the network choosing its nodes
/// (`docs/architecture/node-selection.md`).
///
/// 1. Request, naming only the depositor's own end pairs.
/// 2. Wait for the slot's beacon round, then seed it -- unless a daemon has
///    already. If the beacon cannot be reached, wait for the mint's
///    fallback to open and seed with that.
/// 3. Wait for the claims to fix the positions. A draw the network cannot
///    fill is cancelled, which refunds in full.
/// 4. Walk the chain: link 0 here, each selected pair through its relay,
///    skipping any that does not serve within the serve timeout.
/// 5. Close the chain here and register the note.
///
/// A slot is never left half-done without saying so: every error after the
/// request names the slot, and says whether it was cancelled.
pub async fn print_selected(
    mint: &mut MintClient,
    reach: &mut Reach,
    beacon: &Beacon,
    pairs: &DepositorPairs,
    order: &PrintOrder,
    progress: Progress<'_>,
) -> Result<(BearerToken, Vec<u8>), String> {
    let sel = mint.selection().await.map_err(|e| format!("selection: {e}"))?;
    let k = order.total_pairs.saturating_sub(2);
    let (first, last) = pairs.addresses();

    // 1. Request.
    let slot_id = mint
        .request_print(
            order.event_id,
            order.denomination as i128,
            order.total_pairs,
            (&first.node_a, &first.node_b),
            (&last.node_a, &last.node_b),
        )
        .await
        .map_err(|e| format!("request_print: {e}"))?;
    let slot = read_slot(mint, slot_id).await?;
    progress(&format!(
        "  slot {slot_id} requested: {} pairs, {k} chosen by the network; beacon round {}",
        order.total_pairs, slot.beacon_round
    ));

    // 2. Seed. The round is published at a known time; wait for it.
    seed(mint, beacon, &sel, slot_id, slot.beacon_round, progress).await?;

    // 3. Claims.
    let chain = loop {
        let ledger = latest_ledger(mint).await?;
        let slot = read_slot(mint, slot_id).await?;
        if let Some(chain) = slot.chain(ledger) {
            progress(&format!("  positions fixed: {k} of {k} claimed"));
            break chain;
        }
        if ledger > slot.claim_deadline.saturating_add(CLAIM_GRACE_LEDGERS) {
            return Err(abandon(
                mint,
                slot_id,
                &format!("only {} of {k} positions were claimed", slot.claims.len()),
            )
            .await);
        }
        progress(&format!(
            "  waiting for nodes: {} of {k} claimed",
            (slot.claims.len() as u32).min(k)
        ));
        tokio::time::sleep(POLL).await;
    };
    let _ = chain;

    // 4. Link 0, then the walk.
    let (mut partial, _shard) = PartialToken::initiate(
        order.event_id,
        order.timestamp,
        Some(order.denomination),
        order.total_pairs as u16,
        &pairs.first.0,
        &pairs.first.1,
        vec![],
    )
    .map_err(|e| format!("initiate: {e}"))?;
    let link0 = partial.chain.links[0].partial_public_key;
    mint.confirm_link(slot_id, 0, link0)
        .await
        .map_err(|e| format!("confirm_link 0: {e}"))?;
    progress("  link 0 opened and confirmed (depositor)");

    for i in 1..=k {
        partial = serve_position(mint, reach, &sel, slot_id, i, &partial, progress).await?;
    }

    // 5. Close here, register.
    let mut token = assemble_bearer_token(&partial, &pairs.last.0, &pairs.last.1, slot_id, None)
        .map_err(|e| format!("assemble: {e}"))?;
    // Stamp the note with the deployment that backs it, before anything
    // signs it (see the binding's own documentation).
    let mint_id = parse_contract_id(mint.contract_id())?;
    let pay_token = mint
        .pay_token()
        .await
        .map_err(|e| format!("pay_token: {e}"))?;
    token.mint_binding = Some(MintBinding {
        mint: mint_id,
        pay_token: parse_contract_id(&pay_token)?,
    });
    let final_index = (token.chain.links.len() - 1) as u32;
    let final_key = token.chain.links[final_index as usize].partial_public_key;
    mint.confirm_link(slot_id, final_index, final_key)
        .await
        .map_err(|e| format!("confirm_link {final_index}: {e}"))?;
    progress(&format!("  link {final_index} closed and confirmed (depositor)"));

    let chain_hash = token_chain_hash(&token).map_err(|e| format!("chain_hash: {e}"))?;
    mint.register_token(
        slot_id,
        token.ephemeral_public_key,
        chain_hash,
        order.mode,
        order.owner_commitment,
        token.claim_public_key(),
    )
    .await
    .map_err(|e| format!("register_token: {e}"))?;

    let container = serialize_bearer_token(&token, &pairs.last.0)
        .map_err(|e| format!("serialize: {e}"))?;
    Ok((token, container))
}

/// Seed `slot_id` with round `round`, or find a daemon already has.
///
/// If the beacon cannot be reached, the slot is **not** cancelled: once the
/// round's time has passed a cancel forfeits, while
/// a slot nobody could seed expires with a full refund. The error says so.
async fn seed(
    mint: &mut MintClient,
    beacon: &Beacon,
    sel: &SelectionInfo,
    slot_id: u32,
    round: u64,
    progress: Progress<'_>,
) -> Result<(), String> {
    // The local clock only says roughly when to start asking. Whether the
    // round is out is the beacon's answer, so a fast or slow clock costs
    // time, not the print.
    let at = sel.round_time(round);
    let now = unix_now();
    if at > now + 5 {
        progress(&format!("  waiting about {}s for the beacon round", at - now));
        tokio::time::sleep(std::time::Duration::from_secs(at - now - 5)).await;
    }
    let mut last = String::new();
    let mut told = false;
    // Ask the beacon until the mint's fallback opens, then seed with that.
    // A couple of minutes past the opening covers a local clock ahead of
    // the ledger's (the mint refuses until its own time has passed).
    let opens = sel.fallback_time(round);
    while unix_now() <= opens + FALLBACK_GRACE {
        if read_slot(mint, slot_id).await?.seed.is_some() {
            progress("  seeded (by a node)");
            return Ok(());
        }
        if unix_now() >= opens {
            match mint.seed_fallback(slot_id).await {
                Ok(_) => {
                    progress("  seeded with the mint's fallback: the beacon could not be reached");
                    return Ok(());
                }
                Err(e) => last = format!("seed_fallback: {e}"),
            }
        } else {
            match beacon.signature(round).await {
                Ok(sig) => match mint.seed_print(slot_id, sig).await {
                    Ok(_) => {
                        progress(&format!("  seeded with beacon round {round}"));
                        return Ok(());
                    }
                    Err(e) => last = format!("seed_print: {e}"),
                },
                Err(e) => {
                    if !told {
                        told = true;
                        progress(&format!(
                            "  the beacon cannot be reached ({e}); still trying, and the mint's \
                             fallback opens in about {}s",
                            opens.saturating_sub(unix_now())
                        ));
                    }
                    last = e.to_string();
                }
            }
        }
        tokio::time::sleep(POLL).await;
    }
    // A node may have seeded it while we failed.
    if read_slot(mint, slot_id).await?.seed.is_some() {
        return Ok(());
    }
    Err(format!(
        "slot {slot_id}: could not seed it with beacon round {round} or the fallback ({last}). \
         It is left open: a node may still seed it, and if nobody can, it expires with a full \
         refund. Cancelling now would forfeit the positions, because the round is already public."
    ))
}

/// Seconds past the fallback's opening that [`seed`] keeps trying.
const FALLBACK_GRACE: u64 = 120;

/// Get position `i`'s link built, skipping selected pairs that do not
/// serve, and return the extended partial.
async fn serve_position(
    mint: &mut MintClient,
    reach: &mut Reach,
    sel: &SelectionInfo,
    slot_id: u32,
    i: u32,
    partial: &PartialToken,
    progress: Progress<'_>,
) -> Result<PartialToken, String> {
    loop {
        let ledger = latest_ledger(mint).await?;
        let slot = read_slot(mint, slot_id).await?;
        let chain = slot
            .chain(ledger)
            .ok_or_else(|| format!("slot {slot_id}: positions not fixed"))?;
        let (node_a, node_b) = chain[i as usize].clone();
        let pair = PairAddresses { node_a: node_a.clone(), node_b };
        let request = build_extend_request(partial, slot_id)
            .map_err(|e| format!("build extend request: {e}"))?;
        let body = serde_json::to_value(&request)
            .map_err(|e| format!("encode extend request: {e}"))?;

        if slot.completed_links > i {
            // The node confirmed on-chain and its reply never reached us.
            // It keeps what it served, so the same request again gets the
            // same reply. Only if that fails too is
            // the link lost.
            for _ in 0..3 {
                if let Ok(raw) = ask(reach, &node_a, &body).await {
                    if let Ok(extended) = read_extension(&raw, partial, &pair) {
                        progress(&format!("  link {i}: the lost reply was sent again by {node_a}"));
                        return Ok(extended);
                    }
                }
                tokio::time::sleep(POLL).await;
            }
            return Err(abandon(
                mint,
                slot_id,
                &format!("position {i} confirmed its link but its reply was lost"),
            )
            .await);
        }

        let outcome = async {
            let raw = ask(reach, &node_a, &body).await?;
            read_extension(&raw, partial, &pair)
        }
        .await;

        match outcome {
            Ok(extended) => {
                progress(&format!("  link {i} added and confirmed by {node_a}"));
                return Ok(extended);
            }
            Err(e) => progress(&format!("  position {i} ({node_a}) did not serve: {e}")),
        }

        // Wait out its serve time, then skip it. A late confirmation in
        // the meantime is caught at the top of the loop.
        loop {
            let ledger = latest_ledger(mint).await?;
            let slot = read_slot(mint, slot_id).await?;
            if slot.completed_links > i || ledger > slot.last_progress + sel.serve_timeout {
                break;
            }
            tokio::time::sleep(POLL).await;
        }
        if read_slot(mint, slot_id).await?.completed_links > i {
            continue;
        }
        match mint.skip_position(slot_id).await {
            Ok(_) => progress(&format!("  position {i} skipped; a runner-up takes it")),
            Err(e) => {
                return Err(abandon(mint, slot_id, &format!("could not skip position {i}: {e}")).await);
            }
        }
    }
}

/// POST an extend request to `node` through its relay.
async fn ask(reach: &mut Reach, node: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
    let relay = reach.relay_for(node).await?;
    relay.request_json(node, "POST", "/kenter/extend", Some(body)).await
}

/// A node's extend reply, checked: ok, parseable, and exactly the chain we
/// sent plus one link from `pair`.
fn read_extension(raw: &serde_json::Value, partial: &PartialToken, pair: &PairAddresses) -> Result<PartialToken, String> {
    let response: ExtendResponse =
        serde_json::from_value(raw.clone()).map_err(|e| format!("{raw} ({e})"))?;
    if response.status != "ok" {
        return Err(format!(
            "refused: {}",
            response.error.unwrap_or_else(|| response.status.clone())
        ));
    }
    let extended = parse_extend_response(&response).map_err(|e| e.to_string())?;
    check_extension(partial, &extended, pair)?;
    Ok(extended)
}

/// Cancel `slot_id` and describe what happened, for an error message.
async fn abandon(mint: &mut MintClient, slot_id: u32, why: &str) -> String {
    match mint.cancel_print(slot_id).await {
        Ok(refund) => format!("slot {slot_id}: {why}; cancelled, {refund} refunded"),
        Err(e) => format!("slot {slot_id}: {why}; cancelling failed too ({e}), so it stays open"),
    }
}

async fn read_slot(mint: &MintClient, slot_id: u32) -> Result<SlotInfo, String> {
    let slot = mint
        .get_slot(slot_id)
        .await
        .map_err(|e| format!("get_slot {slot_id}: {e}"))?
        .ok_or_else(|| format!("slot {slot_id} is gone"))?;
    // Not an unseeded slot: its draw has lapsed, and only cancelling it is
    // left.
    if slot.lapsed {
        return Err(format!("slot {slot_id}'s draw has lapsed; it can only be cancelled"));
    }
    Ok(slot)
}

async fn latest_ledger(mint: &MintClient) -> Result<u32, String> {
    mint.tx()
        .rpc()
        .get_latest_ledger()
        .await
        .map_err(|e| format!("latest ledger: {e}"))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Rig {
        start: PartialToken,
        a: StellarKeypair,
        b: StellarKeypair,
        pair: PairAddresses,
    }

    fn rig() -> Rig {
        let (d1, d2) = (StellarKeypair::random(), StellarKeypair::random());
        let (start, _) =
            PartialToken::initiate([7u8; 32], 1_700_000_000, Some(1_000_000), 4, &d1, &d2, vec![])
                .unwrap();
        let (a, b) = (StellarKeypair::random(), StellarKeypair::random());
        let pair = PairAddresses { node_a: a.stellar_address(), node_b: b.stellar_address() };
        Rig { start, a, b, pair }
    }

    fn honest(r: &Rig) -> PartialToken {
        let mut t = r.start.clone();
        t.extend(&r.a, &r.b).unwrap();
        t
    }

    const NODE: &str = "GCVOCNDQUMFSBCIJREUBPENQ6TIIV6W4OQFYPCCQFBWF3CAS3GZ26E2R";

    #[test]
    fn a_node_endpoint_names_its_relay() {
        let ep = format!("https://{NODE}.relay.example.org");
        assert_eq!(relay_host_of(&ep, NODE).unwrap(), "relay.example.org");
        // Relays lowercase hosts; a trailing slash is harmless.
        assert_eq!(relay_host_of(&format!("{}/", ep.to_lowercase()), NODE).unwrap(), "relay.example.org");
    }

    #[test]
    fn an_endpoint_that_is_not_the_nodes_own_is_refused() {
        let other = "GCLQHD7NQ665D5F5LOG5VLNWCJHJBSUJRUB7GFCBKKNWHPYCRYFBNPTB";
        for ep in [
            format!("http://{NODE}.relay.example.org"),
            format!("https://{other}.relay.example.org"),
            format!("https://{NODE}.relay.example.org/path"),
            format!("https://{NODE}."),
            format!("https://{NODE}.evil\"><x>"),
            format!("https://relay.example.org"),
            format!("https://{NODE}.127.0.0.1"),
            format!("https://{NODE}.10.0.0.5:8000"),
            format!("https://{NODE}.localhost"),
            format!("https://{NODE}.intranet"),
        ] {
            assert!(relay_host_of(&ep, NODE).is_err(), "accepted {ep}");
        }
    }

    #[test]
    fn an_honest_extension_passes() {
        let r = rig();
        check_extension(&r.start, &honest(&r), &r.pair).unwrap();
    }

    /// What the driver really compares: its in-memory partial against a
    /// reply that went out and came back as bytes, as a node's does. The
    /// in-memory-only test above passed while every real print failed.
    #[test]
    fn an_honest_extension_that_crossed_the_wire_passes() {
        let r = rig();
        let wire = |t: &PartialToken| {
            deserialize_partial_token(&serialize_partial_token(t).unwrap()).unwrap()
        };
        let mut at_node = wire(&r.start);
        at_node.extend(&r.a, &r.b).unwrap();
        check_extension(&r.start, &wire(&at_node), &r.pair).unwrap();
        // And from a partial that has itself already crossed once.
        let mut again = wire(&at_node);
        let (c, d) = (StellarKeypair::random(), StellarKeypair::random());
        again.extend(&c, &d).unwrap();
        let pair = PairAddresses { node_a: c.stellar_address(), node_b: d.stellar_address() };
        check_extension(&wire(&at_node), &wire(&again), &pair).unwrap();
    }

    /// A chain built elsewhere, under another event id,
    /// handed back for this slot.
    #[test]
    fn a_chain_under_another_event_id_is_refused() {
        let r = rig();
        let (x, y) = (StellarKeypair::random(), StellarKeypair::random());
        let (mut other, _) =
            PartialToken::initiate([9u8; 32], 1_700_000_000, Some(1_000_000), 4, &x, &y, vec![])
                .unwrap();
        other.extend(&r.a, &r.b).unwrap();
        let e = check_extension(&r.start, &other, &r.pair).unwrap_err();
        assert!(e.contains("header") || e.contains("link 0"), "{e}");
    }

    #[test]
    fn a_link_from_the_wrong_pair_is_refused() {
        let r = rig();
        let mut t = r.start.clone();
        t.extend(&StellarKeypair::random(), &StellarKeypair::random()).unwrap();
        let e = check_extension(&r.start, &t, &r.pair).unwrap_err();
        assert!(e.contains("not signed by the pair"), "{e}");
    }

    #[test]
    fn nothing_added_or_two_added_is_refused() {
        let r = rig();
        assert!(check_extension(&r.start, &r.start, &r.pair).is_err());
        let mut two = honest(&r);
        two.extend(&r.a, &r.b).unwrap();
        assert!(check_extension(&r.start, &two, &r.pair).is_err());
    }

    #[test]
    fn a_rewritten_earlier_link_is_refused() {
        let r = rig();
        let mut t = honest(&r);
        t.chain.links[0].shard_commitment[0] ^= 1;
        assert!(check_extension(&r.start, &t, &r.pair).is_err());
    }
}
