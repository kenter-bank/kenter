//! What the network charges for a no-argument contract call.
//!
//! Exists to separate two explanations of the same gap. A 3-pair
//! `redeem_by_chain` costs 13.05M instructions on the network and
//! 9.88M in the contract test suite. Either the network adds a fixed
//! per-transaction cost the harness does not charge -- wasm parsing
//! and instantiation, envelope decode, footprint load -- or it scales
//! everything by a constant factor. The two agree at 3 pairs and
//! disagree by 20 points of the CPU budget at 24, so which one holds
//! decides whether `MAX_REDEEMABLE_PAIRS = 24` is safe.
//!
//! A call that does almost nothing tells them apart. Under the fixed
//! model it still costs the whole overhead; under the scaling model it
//! costs almost nothing.
//!
//! ```text
//! cargo run -p kenter-client --example sim_cost -- <contract-id> <fn>
//! ```
//!
//! Source account comes from `STELLAR_SECRET` (never argv). The call
//! is simulated, never submitted.

use kenter_client::rpc::SorobanRpcClient;
use kenter_client::tx::TxBuilder;
use kenter_crypto::keypair::StellarKeypair;

const RPC: &str = "https://soroban-testnet.stellar.org";
const PASSPHRASE: &str = "Test SDF Network ; September 2015";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (contract, function) = match args.as_slice() {
        [c, f] => (c.clone(), f.clone()),
        _ => {
            eprintln!("usage: sim_cost <contract-id> <function>   (no-argument functions only)");
            std::process::exit(2);
        }
    };

    let secret = std::env::var("STELLAR_SECRET")
        .map_err(|_| "set STELLAR_SECRET to a funded testnet secret (not accepted on argv)")?;
    let keypair = StellarKeypair::from_stellar_secret(&secret)?;

    let tx = TxBuilder::new(SorobanRpcClient::new(RPC, PASSPHRASE), keypair);
    let r = tx.simulate_resources(&contract, &function, vec![]).await?;

    println!("{function} on {contract}");
    println!("  instructions  : {}", r.instructions);
    println!("  disk read     : {} bytes", r.disk_read_bytes);
    println!("  write         : {} bytes", r.write_bytes);
    println!(
        "  footprint     : {} read-only, {} read-write",
        r.read_only_entries, r.read_write_entries
    );
    println!("  resource fee  : {} stroops", r.min_resource_fee);
    Ok(())
}
