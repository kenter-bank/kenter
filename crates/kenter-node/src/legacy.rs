//! The development form: flags, with the pair's secrets in the
//! environment or in files. For development and `kenter-systest`,
//! which drive several nodes on one machine with keys they generate.
//!
//! Unlike an installed node this does not leave selection when it stops,
//! and binds to one relay with no fallback: the behaviour the test
//! harnesses rely on.

use std::sync::Arc;

use kenter_network::tunnel::{LinkConfirmer, TunnelClient, TunnelConfig};
use kenter_crypto::keypair::StellarKeypair;
use kenter_node::chain::Chain;
use kenter_node::daemon::{MintLinkConfirmer, pair_handler};
use kenter_node::keys::PairKeys;

pub const USAGE: &str = "\
kenter-node (development form)

SECRETS (never passed on argv):
    KENTER_NODE_SECRET            this node's Stellar secret (S...)
    KENTER_NODE_PARTNER_SECRET    its pair partner's secret (S...)
    --secret-file <path>          alternative to KENTER_NODE_SECRET
    --partner-secret-file <path>  alternative to KENTER_NODE_PARTNER_SECRET

OPTIONS:
    --tunnel <host>        relay host (default: the first relay built into this release)
    --insecure             use ws:// instead of wss:// (local dev relay)
    --label <name>         roster label for this node (default \"kenter-node\")
    --roster <id>          roster contract id
    --mint <id>            mint contract id (for confirm_link)
    --rpc <url>            Soroban RPC url
    --no-roster            skip roster registration (pure transport testing)
    --volunteer            join (or convert) as a volunteer: same bond, but
                           the mint burns this node's fees instead of paying
                           them. Permanent for both addresses.
    --no-confirm           extend without recording links on-chain

NOTES:
    One process serves ONE PAIR and therefore holds both of the pair's secrets.
    After extending a chain this node calls confirm_link itself, because the
    mint accepts that call only from a member of the assigned pair. It needs a
    FUNDED account to do so. --no-confirm skips it, which is fine for transport
    testing and useless for a real print.";

struct Config {
    secret: String,
    partner_secret: String,
    tunnel_host: String,
    secure: bool,
    label: String,
    net: kenter_client::NetworkConfig,
    join_roster: bool,
    volunteer: bool,
    confirm_links: bool,
}

fn read_secret(env_key: &str, file: Option<&String>) -> Result<String, String> {
    if let Some(path) = file {
        let s = std::fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?;
        return Ok(s.trim().to_string());
    }
    match std::env::var(env_key) {
        Ok(v) if !v.trim().is_empty() => Ok(v.trim().to_string()),
        _ => Err(format!(
            "missing {env_key} (or pass the matching --*-secret-file). \
             Secrets are not accepted on argv."
        )),
    }
}

fn parse_args(args: &[String]) -> Result<Config, String> {
    let mut tunnel_host = kenter_client::network::built()
        .relays
        .first()
        .map(|h| h.to_string())
        .unwrap_or_default();
    let mut secure = true;
    let mut label = "kenter-node".to_string();
    let mut roster_id: Option<String> = None;
    let mut mint_id: Option<String> = None;
    let mut rpc_url: Option<String> = None;
    let mut join_roster = true;
    let mut volunteer = false;
    let mut confirm_links = true;
    let mut secret_file: Option<String> = None;
    let mut partner_secret_file: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let next = |i: &mut usize, flag: &str| -> Result<String, String> {
            *i += 1;
            args.get(*i).cloned().ok_or_else(|| format!("{flag} requires a value"))
        };
        match args[i].as_str() {
            "--tunnel" => tunnel_host = next(&mut i, "--tunnel")?,
            "--insecure" => secure = false,
            "--label" => label = next(&mut i, "--label")?,
            "--roster" => roster_id = Some(next(&mut i, "--roster")?),
            "--mint" => mint_id = Some(next(&mut i, "--mint")?),
            "--rpc" => rpc_url = Some(next(&mut i, "--rpc")?),
            "--no-roster" => join_roster = false,
            "--volunteer" => volunteer = true,
            "--no-confirm" => confirm_links = false,
            "--secret-file" => secret_file = Some(next(&mut i, "--secret-file")?),
            "--partner-secret-file" => {
                partner_secret_file = Some(next(&mut i, "--partner-secret-file")?)
            }
            other => return Err(format!("unexpected argument: {other:?}")),
        }
        i += 1;
    }

    let flags = kenter_client::Overrides {
        rpc: rpc_url,
        mint: mint_id,
        roster: roster_id,
        ..Default::default()
    };
    let net = kenter_client::NetworkConfig::resolve(
        kenter_client::network::built(),
        flags.or(kenter_client::Overrides::from_env()),
    )?;
    if tunnel_host.is_empty() {
        return Err("--tunnel <host> is required: this build has no relays built in".into());
    }

    Ok(Config {
        secret: read_secret("KENTER_NODE_SECRET", secret_file.as_ref())?,
        partner_secret: read_secret("KENTER_NODE_PARTNER_SECRET", partner_secret_file.as_ref())?,
        tunnel_host,
        secure,
        label,
        net,
        join_roster,
        volunteer,
        confirm_links,
    })
}

/// Register an identity on the roster if it is not already a member, on
/// the requested terms. A paid node asked to volunteer converts in place;
/// nothing turns a volunteer back.
///
/// Decided from the full record (`get_node`), not from `node_terms`:
/// `node_terms` is `None` for a member that is merely inactive, and
/// joining again would be refused.
async fn ensure_roster(
    chain: &Chain,
    keypair: &StellarKeypair,
    label: &str,
    volunteer: bool,
) -> Result<(), String> {
    let address = keypair.stellar_address();
    let view = chain.view(keypair).await?;
    match view.node {
        None => {
            chain.join(keypair, label, volunteer).await?;
            tracing::info!(%address, volunteer, "joined the roster");
        }
        Some(n) if n.unbonding_at.is_some() => {
            return Err(format!("{address} is unbonding; withdraw its stake before it can serve"));
        }
        Some(n) => {
            if volunteer && !n.volunteer {
                chain.join(keypair, label, true).await?;
                tracing::info!(%address, "converted to volunteer");
            } else {
                tracing::info!(%address, volunteer = n.volunteer, "already on the roster");
            }
            if !n.active {
                chain.set_active(keypair, true).await?;
                tracing::info!(%address, "back in selection");
            }
        }
    }
    Ok(())
}

pub async fn run(args: Vec<String>) -> Result<(), String> {
    let cfg = parse_args(&args)?;

    let own = StellarKeypair::from_stellar_secret(&cfg.secret)
        .map_err(|e| format!("bad node secret: {e}"))?;
    let partner = StellarKeypair::from_stellar_secret(&cfg.partner_secret)
        .map_err(|e| format!("bad partner secret: {e}"))?;
    if own.raw_public() == partner.raw_public() {
        // The pair's shard is an ECDH between the two keys; identical keys make
        // it derivable from one secret and the "pair" meaningless.
        return Err("node and partner secrets are the same key — a pair must be two keys".into());
    }
    let keys = PairKeys { own, partner };
    let [own_address, partner_address] = keys.addresses();
    tracing::info!(node = %own_address, partner = %partner_address, "pair node starting");

    let chain = Chain::new(cfg.net.clone());
    if cfg.join_roster {
        ensure_roster(&chain, &keys.own, &cfg.label, cfg.volunteer).await?;
        ensure_roster(&chain, &keys.partner, &format!("{}-partner", cfg.label), cfg.volunteer).await?;
    } else {
        tracing::warn!("--no-roster: this node is not registered, so prints naming it will be rejected on-chain");
    }

    // One lock for every own-key submission: the confirmer and selection
    // share the account (daemon module docs).
    let own_lock: kenter_node::daemon::OwnKeyLock = Default::default();
    let mut owed = None;
    let confirmer: Option<Arc<dyn LinkConfirmer>> = if cfg.confirm_links {
        tracing::info!(mint = %cfg.net.mint, "links will be confirmed on-chain");
        let c = MintLinkConfirmer::new(&cfg.net, &keys.own, Arc::clone(&own_lock));
        owed = Some(c.owed());
        Some(Arc::new(c))
    } else {
        tracing::warn!("--no-confirm: links will not be recorded, so prints this node joins cannot be registered");
        None
    };
    let handler = pair_handler(&keys, confirmer);

    // Nodes claim their own positions in prints: without this the
    // node would serve but never be in a print. Only with a roster and
    // on-chain confirmation, since a claim the node cannot serve is waste.
    let keys = Arc::new(keys);
    if cfg.join_roster && cfg.confirm_links {
        tokio::spawn(kenter_node::select::run(
            Arc::new(Chain::new(cfg.net.clone())),
            Arc::clone(&keys),
            Arc::clone(&own_lock),
            None,
            None,
            owed,
        ));
    }

    let tunnel_cfg = TunnelConfig {
        host: cfg.tunnel_host.clone(),
        secure: cfg.secure,
        services: vec!["kenter".into()],
        ..Default::default()
    };
    tracing::info!(url = %tunnel_cfg.wss_url(), "connecting to relay");

    let (endpoint, session) = TunnelClient::new(keys.own.clone(), tunnel_cfg)
        .run(handler)
        .await
        .map_err(|e| format!("tunnel: {e}"))?;

    tracing::info!(
        endpoint = %endpoint.endpoint_url,
        relay = %endpoint.server_address,
        services = ?endpoint.services,
        "node is serving"
    );
    println!("kenter-node serving as {own_address}");
    println!("  pair partner : {partner_address}");
    println!("  endpoint     : {}", endpoint.endpoint_url);
    println!("  endpoints    : /kenter/health  /kenter/shard  /kenter/extend");

    // Close the tunnel cleanly on interrupt so the relay drops the binding
    // rather than waiting for a timeout. Awaiting the session itself also means
    // a dropped tunnel exits the process instead of leaving a zombie.
    let stop = session.shutdown_trigger();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::info!("interrupt — shutting down");
            stop();
        }
    });
    session.join().await.map_err(|e| format!("session task: {e}"))?;
    tracing::info!("tunnel session ended");
    Ok(())
}
