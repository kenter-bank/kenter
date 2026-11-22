//! Live check: a node refuses to extend a look-alike chain for a real slot,
//! and still extends the depositor's own.
//!
//! The guard (`SlotInfo::admits_next`) is unit-tested against a modelled
//! mint. This runs it against the deployed contract, through a real relay and a
//! real `kenter-node`:
//!
//! 1. Reserve a slot of 3 pairs, seed it from the beacon, and wait for the
//!    draw (`docs/architecture/node-selection.md`). The node under test has to be the one
//!    selected: on a roster with other pairs it may not be, and then this
//!    says so and stops, having cancelled. Then confirm link 0.
//! 2. Build what a stranger can from public ledger data alone -- the slot's
//!    event id and link-0 partial key -- signed by throwaway keys, and POST
//!    it to the node's unauthenticated `/proxy/<node>/kenter/extend` with
//!    `curl`, as an attacker would.
//! 3. Read the slot back from the ledger: still one link.
//! 4. Send the depositor's real chain through the relay (the control), check
//!    the reply as the driver does, and finish the print: close, register.
//!
//! Testnet only, and it spends: a 0.1 USDC note plus fees. The note is
//! written to `WS62_OUT` and can be imported and redeemed like any other.
//!
//! Secrets from the environment only, never argv:
//!   KENTER_DEPOSITOR_SECRET   the depositor
//!   WS62_NODE                 the node's address (one interior pair)
//!   WS62_MINT                 the mint contract
//!   WS62_OUT                  where to write the note
//!   WS62_TUNNEL               relay host:port, default 127.0.0.1:8000 (plain)


use kenter_client::{MintClient, SorobanRpcClient, TokenMode, TxBuilder};
use kenter_crypto::chain_data::token_chain_hash;
use kenter_crypto::container::serialize_bearer_token;
use kenter_crypto::keypair::StellarKeypair;
use kenter_crypto::token::{assemble_bearer_token, PartialToken};
use kenter_network::handlers::{build_extend_request, parse_extend_response};
use kenter_network::protocol::ExtendResponse;
use kenter_print::{check_extension, discover_pair, DepositorPairs, NodeRelay};

const RPC: &str = "https://soroban-testnet.stellar.org";
const PASSPHRASE: &str = "Test SDF Network ; September 2015";

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("set {name}"))
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("FAILED: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let kp = StellarKeypair::from_stellar_secret(&env("KENTER_DEPOSITOR_SECRET")?)
        .map_err(|e| format!("depositor secret: {e}"))?;
    let node = env("WS62_NODE")?;
    let contract = env("WS62_MINT")?;
    let out = env("WS62_OUT")?;
    let tunnel = std::env::var("WS62_TUNNEL").unwrap_or_else(|_| "127.0.0.1:8000".into());

    // The depositor reaches the node through the relay's /proxy route,
    // like every client since MAINNET_READINESS 2.10: no relay session.
    let relay = NodeRelay::new(&tunnel, false)?;

    let mut mint = MintClient::new(
        TxBuilder::new(SorobanRpcClient::new(RPC, PASSPHRASE), kp.clone()),
        &contract,
    );
    let pairs = DepositorPairs::testbed(&kp);
    let event_id: [u8; 32] = rand::random();
    let denom: u64 = 1_000_000;

    // 1. Reserve, seed, and wait for the draw.
    let node_pair = discover_pair(&relay, &node).await?;
    println!("node {node} pairs with {}", node_pair.node_b);
    let (first, last) = pairs.addresses();
    let slot_id = mint
        .request_print(
            event_id,
            denom as i128,
            3,
            (&first.node_a, &first.node_b),
            (&last.node_a, &last.node_b),
        )
        .await
        .map_err(|e| format!("request_print: {e}"))?;
    println!("slot {slot_id} reserved (3 pairs)");
    let sel = mint.selection().await.map_err(|e| format!("selection: {e}"))?;
    let round = mint.get_slot(slot_id).await.map_err(|e| e.to_string())?.ok_or("slot vanished")?.beacon_round;
    let wait = sel.round_time(round).saturating_sub(now() as u64) + 1;
    tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
    let beacon = kenter_client::Beacon::quicknet().map_err(|e| e.to_string())?;
    let sig = beacon.signature(round).await.map_err(|e| e.to_string())?;
    if let Err(e) = mint.seed_print(slot_id, sig).await {
        println!("seed_print: {e} (a node may have seeded it)");
    }
    let chain = loop {
        let ledger = mint.tx().rpc().get_latest_ledger().await.map_err(|e| e.to_string())?;
        let slot = mint.get_slot(slot_id).await.map_err(|e| e.to_string())?.ok_or("slot vanished")?;
        if let Some(c) = slot.chain(ledger) {
            break c;
        }
        tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    };
    if chain[1].0 != node {
        let refund = mint.cancel_print(slot_id).await.map_err(|e| e.to_string())?;
        return Err(format!(
            "the draw selected {} rather than {node}; cancelled ({refund} refunded).              Run it on a roster where {node} is the only pair.",
            chain[1].0
        ));
    }
    let (mut partial, _) =
        PartialToken::initiate(event_id, now(), Some(denom), 3, &pairs.first.0, &pairs.first.1, vec![])
            .map_err(|e| format!("initiate: {e}"))?;
    mint.confirm_link(slot_id, 0, partial.chain.links[0].partial_public_key)
        .await
        .map_err(|e| format!("confirm_link 0: {e}"))?;
    println!("link 0 confirmed");

    // 2. The look-alike, from public data only.
    let public = mint
        .get_slot(slot_id)
        .await
        .map_err(|e| format!("get_slot: {e}"))?
        .ok_or("slot vanished")?;
    let (sa, sb) = (StellarKeypair::random(), StellarKeypair::random());
    let (mut fake, _) = PartialToken::initiate(public.event_id, now(), Some(denom), 3, &sa, &sb, vec![])
        .map_err(|e| format!("fake initiate: {e}"))?;
    fake.chain.links[0].partial_public_key = public.partial_keys[0];
    let signable = fake.chain.links[0].signable_bytes(&public.event_id);
    fake.chain.links[0].signature_a = sa.sign(&signable).to_bytes();
    fake.chain.links[0].signature_b = sb.sign(&signable).to_bytes();
    fake.running_public_key = public.partial_keys[0];
    fake.verify_chain_integrity()
        .map_err(|e| format!("the look-alike should be self-consistent: {e}"))?;

    let body = serde_json::to_string(&build_extend_request(&fake, slot_id).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let body_file = std::env::temp_dir().join(format!("ws62-forged-{slot_id}.json"));
    std::fs::write(&body_file, &body).map_err(|e| e.to_string())?;
    let url = format!("http://{tunnel}/proxy/{node}/kenter/extend");
    let started = std::time::Instant::now();
    let reply = std::process::Command::new("curl")
        .args(["-s", "-m", "150", "-X", "POST", "-H", "Content-Type: application/json"])
        .arg("--data-binary")
        .arg(format!("@{}", body_file.display()))
        .arg(&url)
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    let _ = std::fs::remove_file(&body_file);
    println!(
        "forged extend -> {} ({:.1}s)",
        String::from_utf8_lossy(&reply.stdout),
        started.elapsed().as_secs_f32()
    );

    // 3. The ledger is the judge.
    let after = mint
        .get_slot(slot_id)
        .await
        .map_err(|e| format!("get_slot: {e}"))?
        .ok_or("slot vanished")?;
    println!("slot {slot_id} after the forgery: {} link(s) confirmed", after.completed_links);
    if after.completed_links != 1 {
        return Err("the node confirmed a link for the forged chain".into());
    }
    println!("PASS: the node refused the look-alike and the ledger is unchanged");

    // 4. The control: the depositor's own chain still goes through.
    let request = build_extend_request(&partial, slot_id).map_err(|e| e.to_string())?;
    let raw = relay
        .request_json(&node, "POST", "/kenter/extend", Some(&serde_json::to_value(&request).unwrap()))
        .await
        .map_err(|e| format!("honest extend: {e}"))?;
    let response: ExtendResponse =
        serde_json::from_value(raw.clone()).map_err(|e| format!("{raw} ({e})"))?;
    if response.status != "ok" {
        return Err(format!("honest extend refused: {:?}", response.error));
    }
    let extended = parse_extend_response(&response).map_err(|e| e.to_string())?;
    check_extension(&partial, &extended, &node_pair)?;
    partial = extended;
    println!("PASS: the depositor's own extend succeeded (link 1 confirmed by the node)");

    let mut token = assemble_bearer_token(&partial, &pairs.last.0, &pairs.last.1, slot_id, None)
        .map_err(|e| format!("assemble: {e}"))?;
    let final_index = (token.chain.links.len() - 1) as u32;
    let final_key = token.chain.links[final_index as usize].partial_public_key;
    mint.confirm_link(slot_id, final_index, final_key)
        .await
        .map_err(|e| format!("confirm_link {final_index}: {e}"))?;
    let chain_hash = token_chain_hash(&token).map_err(|e| e.to_string())?;
    mint.register_token(
        slot_id,
        token.ephemeral_public_key,
        chain_hash,
        TokenMode::PureBearer,
        [0u8; 32],
        token.claim_public_key(),
    )
    .await
    .map_err(|e| format!("register_token: {e}"))?;
    token.mint_binding = None;
    let container = serialize_bearer_token(&token, &pairs.last.0).map_err(|e| e.to_string())?;
    std::fs::write(&out, &container).map_err(|e| format!("writing {out}: {e}"))?;
    println!("registered; note written to {out}");
    Ok(())
}
