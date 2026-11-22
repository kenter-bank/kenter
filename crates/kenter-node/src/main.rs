//! `kenter-node`: run a Kenter pair node.
//!
//! An installed node is driven by subcommands and keeps its
//! keys and config in its home directory (`kenter_node::home`):
//!
//! ```text
//! kenter-node init        create the pair's keys and config
//! kenter-node addresses   the two addresses, and what each needs
//! kenter-node run         serve (the default when the home has a node)
//! kenter-node status      the daemon's state and the pair's on-chain state
//! kenter-node claim | leave | withdraw
//! kenter-node show-phrase
//! ```
//!
//! A second form, flags with secrets in `KENTER_NODE_SECRET` and
//! `KENTER_NODE_PARTNER_SECRET`, serves development and `kenter-systest`
//! (see [`legacy`]). Secrets are never accepted on argv in
//! either form: a process list is not a secret store.
//!
//! # One process is one *pair*
//!
//! `ExtendNodeContext` holds both of a pair's secrets, because
//! `PartialToken::extend` dual-signs the link, so the party that can build
//! a pair's link can also compute its shard. The unit of trust is the pair:
//! a 3-pair token involves 3 independent parties, not 6
//! (`crates/kenter-node/ARCHITECTURE.md`).

use std::io::BufRead;
use std::process::ExitCode;

use kenter_node::chain::{Chain, LOW_BALANCE, pair_funding_target, spendable, xlm};
use kenter_node::config::{NodeConfig, Relay};
use kenter_node::home::Home;
use kenter_node::keys::{self, PairKeys};
use kenter_node::status::{DaemonLock, DaemonStatus, Reporter, State, daemon_running};

mod legacy;

const USAGE: &str = "\
kenter-node: a Kenter pair node

USAGE:
    kenter-node <COMMAND> [OPTIONS]

COMMANDS:
    init [--name <n>] [--relay <host>]... [--insecure] [--volunteer] [--restore] [--keystore]
                  Create this install's pair: a new recovery phrase (shown once),
                  or --restore to read an existing phrase from stdin. --relay may
                  repeat; relays are tried in order. --insecure: the relays given
                  use ws:// (a local development relay only).
    addresses     The pair's two addresses and the XLM each needs to join.
    run           Serve until interrupted. Joins the roster when funded, binds
                  to the first relay that answers, and leaves selection on a
                  clean stop. The default when no command is given.
    status        The daemon's state and the pair's balances, stake, terms
                  and fees.
    stop          Stop the running node cleanly (it leaves selection first).
    claim         Claim credited fees for both addresses (paid nodes).
    leave         Leave the roster: both stakes start unbonding (one week).
    withdraw      Reclaim both stakes once unbonding has run out.
    show-phrase   Print the recovery phrase. Anyone who sees it owns the stake.
    keystore [status|enable|disable|wipe-file]
                  Where the phrase is kept. enable moves it from its file into
                  the OS keystore (Credential Manager, Keychain) and destroys
                  the file; disable moves it back. init --keystore starts there.
                  wipe-file destroys a phrase file left behind by an
                  interrupted move (only if it matches the keystore).

claim, leave and withdraw refuse while the node is running: stop it first.

Home: KENTER_NODE_HOME, else a per-user directory for this build's network.
RPC: node.json's \"rpc\", else KENTER_RPC, else the build's default.

DEVELOPMENT (secrets from the environment, never argv):
    KENTER_NODE_SECRET=S... KENTER_NODE_PARTNER_SECRET=S... kenter-node --tunnel <host> [...]
    kenter-node --help-legacy   for those flags.";

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kenter_node=info,kenter_network=info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();

    // The older invocation: flags first, or no arguments with secrets in
    // the environment. Kept exactly for kenter-systest and dev scripts.
    let legacy = match args.first().map(String::as_str) {
        Some("--help") | Some("-h") => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Some("--help-legacy") => {
            println!("{}", legacy::USAGE);
            return ExitCode::SUCCESS;
        }
        Some(a) if a.starts_with("--") => true,
        None => std::env::var_os("KENTER_NODE_SECRET").is_some(),
        _ => false,
    };

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: starting the runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = if legacy {
        rt.block_on(legacy::run(args))
    } else {
        rt.block_on(command(args))
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn command(args: Vec<String>) -> Result<(), String> {
    let home = Home::locate()?;
    let (cmd, rest) = match args.split_first() {
        Some((c, rest)) => (c.as_str(), rest),
        None => ("run", &[][..]),
    };
    match cmd {
        "init" => init(&home, rest).await,
        "addresses" => no_args(rest).and(addresses(&home).await),
        "run" => no_args(rest).and(run(home).await),
        "status" => no_args(rest).and(status(&home).await),
        "stop" => no_args(rest).and(stop(&home).await),
        "claim" => no_args(rest).and(claim(&home).await),
        "leave" => no_args(rest).and(leave(&home).await),
        "withdraw" => no_args(rest).and(withdraw(&home).await),
        "show-phrase" => no_args(rest).and(show_phrase(&home)),
        "keystore" => keystore_cmd(&home, rest),
        "help" => {
            println!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command {other:?} (see --help)")),
    }
}

fn no_args(rest: &[String]) -> Result<(), String> {
    match rest.first() {
        None => Ok(()),
        Some(a) => Err(format!("unexpected argument {a:?}")),
    }
}

async fn init(home: &Home, rest: &[String]) -> Result<(), String> {
    let mut name: Option<String> = None;
    let mut relays: Vec<Relay> = Vec::new();
    let mut insecure = false;
    let mut volunteer = false;
    let mut restore = false;
    let mut keystore = false;
    let mut i = 0;
    while i < rest.len() {
        let value = |i: &mut usize, flag: &str| -> Result<String, String> {
            *i += 1;
            rest.get(*i).cloned().ok_or_else(|| format!("{flag} requires a value"))
        };
        match rest[i].as_str() {
            "--name" => name = Some(value(&mut i, "--name")?),
            "--relay" => relays.push(Relay::new(&value(&mut i, "--relay")?)),
            "--insecure" => insecure = true,
            "--volunteer" => volunteer = true,
            "--restore" => restore = true,
            "--keystore" => keystore = true,
            other => return Err(format!("unexpected argument {other:?}")),
        }
        i += 1;
    }

    if keystore && !keys::os::supported() {
        return Err("this build has no OS keystore (build with --features keystore)".into());
    }
    // The phrase is what makes a home "a node": a config left by an init
    // that failed before writing it does not block a retry (SA-5).
    if keys::has_pair(home)? {
        return Err(format!(
            "{} already holds a node. One install is one pair; use another \
             KENTER_NODE_HOME for a second.",
            home.root().display()
        ));
    }

    let mut cfg = NodeConfig::new(name.as_deref().unwrap_or("kenter-node"));
    if !relays.is_empty() {
        cfg.relays = relays;
    }
    if insecure {
        for r in &mut cfg.relays {
            r.secure = false;
        }
    }
    cfg.volunteer = volunteer;
    // A restored phrase is, by definition, already written down.
    cfg.backup_confirmed = restore;
    cfg.validate()?;

    let phrase = if restore {
        use std::io::IsTerminal;
        let line = if std::io::stdin().is_terminal() {
            eprintln!("Enter the pair's recovery phrase, then press Enter:");
            // Not echoed: the phrase is the stake (SA-5).
            zeroize::Zeroizing::new(
                rpassword::read_password().map_err(|e| format!("reading the phrase: {e}"))?,
            )
        } else {
            let mut line = zeroize::Zeroizing::new(String::new());
            std::io::stdin()
                .lock()
                .read_line(&mut line)
                .map_err(|e| format!("reading the phrase: {e}"))?;
            line
        };
        zeroize::Zeroizing::new(line.trim().to_string())
    } else {
        keys::new_phrase()?
    };
    let pair = PairKeys::from_phrase(&phrase)?;
    // Config first, phrase last: a failure part-way leaves a home that a
    // second `init` will still accept. In the keystore case the entry is
    // written before the config that names it.
    if keystore {
        keys::store_phrase_os(&mut cfg, &phrase)?;
        cfg.save(home)?;
    } else {
        cfg.save(home)?;
        keys::store_phrase(home, &phrase)?;
    }

    println!("Node set up in {}", home.root().display());
    if !restore {
        println!();
        println!("RECOVERY PHRASE. Write it down and keep it offline. It is the only");
        println!("way to get the stake back if this machine is lost:");
        println!();
        println!("    {}", &*phrase);
        println!();
    }
    if cfg.volunteer {
        println!("Terms: VOLUNTEER. The mint burns this pair's fees, permanently, for both addresses.");
    } else {
        println!("Terms: paid. Fees are credited and claimable.");
    }
    let [own, partner] = pair.addresses();
    println!("Node    : {own}");
    println!("Partner : {partner}");
    println!();
    println!("Next: `kenter-node addresses` shows the one address to fund and how much; the node funds its partner. Then `kenter-node run`.");
    Ok(())
}

async fn addresses(home: &Home) -> Result<(), String> {
    let cfg = NodeConfig::load(home)?;
    let pair = PairKeys::load(home)?;
    let chain = Chain::new(cfg.network()?);
    let [own, partner] = pair.addresses();
    // One address and one amount: the node funds its
    // partner from this address itself.
    match chain.min_stake(&own).await {
        Ok(stake) => println!(
            "Send {} XLM to the node's address:

    {own}
",
            xlm(pair_funding_target(stake, cfg.volunteer))
        ),
        Err(e) => {
            eprintln!("(could not read the roster's stake: {e})");
            println!("The node's address:

    {own}
");
        }
    }
    println!("That covers both halves of the pair: the node creates and funds its");
    println!("partner ({partner}) from it. Both stakes come back a");
    println!("week after `kenter-node leave`, and `withdraw` gathers them here.");
    Ok(())
}

async fn run(home: Home) -> Result<(), String> {
    let cfg = NodeConfig::load(&home)?;
    let pair = PairKeys::load(&home)?;
    let reporter = Reporter::new(home.clone());
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    // A request left over from a stop that found nothing running.
    let _ = std::fs::remove_file(home.stop_request());
    let stop_file = home.stop_request();
    tokio::spawn(async move {
        let mut poll = tokio::time::interval(std::time::Duration::from_secs(2));
        let terminate = terminated();
        tokio::pin!(terminate);
        loop {
            tokio::select! {
                r = tokio::signal::ctrl_c() => {
                    if r.is_ok() {
                        tracing::info!("interrupt: stopping (leaving selection first)");
                        break;
                    }
                }
                _ = &mut terminate => {
                    tracing::info!("terminated: stopping (leaving selection first)");
                    break;
                }
                _ = poll.tick() => {
                    if stop_file.exists() {
                        let _ = std::fs::remove_file(&stop_file);
                        tracing::info!("stop requested: stopping (leaving selection first)");
                        break;
                    }
                }
            }
        }
        let _ = stop_tx.send(true);
        // Keep the sender alive: dropping it also reads as a stop.
        std::future::pending::<()>().await;
    });
    kenter_node::daemon::run(home, cfg, pair, reporter, stop_rx).await
}

/// SIGTERM, which is how systemd (and most supervisors) stop a service.
/// Without it a `systemctl stop` killed the node without leaving
/// selection. Never resolves where there is no such signal.
async fn terminated() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut s) = signal(SignalKind::terminate()) {
            s.recv().await;
            return;
        }
    }
    std::future::pending::<()>().await
}

/// Ask the running daemon to stop cleanly, and wait for it.
async fn stop(home: &Home) -> Result<(), String> {
    if !daemon_running(home) {
        return Err("no node is running from this home".into());
    }
    std::fs::write(home.stop_request(), b"")
        .map_err(|e| format!("writing {}: {e}", home.stop_request().display()))?;
    println!("Stop requested; the node is leaving selection...");
    // Two roster transactions at up to ~45s each, plus the poll.
    for _ in 0..120 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if !daemon_running(home) {
            println!("Stopped.");
            return Ok(());
        }
    }
    Err("the node has not stopped after two minutes; it may still be finishing a transaction".into())
}

async fn status(home: &Home) -> Result<(), String> {
    let cfg = NodeConfig::load(home)?;
    let pair = PairKeys::load(home)?;
    let chain = Chain::new(cfg.network()?);

    let running = daemon_running(home);
    let reported = DaemonStatus::read(home);
    println!("Node     : {} ({})", cfg.name, chain.net.profile.name);
    match (running, &reported) {
        (true, Some(s)) => {
            println!("Daemon   : {:?}{}", s.state, s.detail.as_ref().map(|d| format!(": {d}")).unwrap_or_default());
            if let Some(r) = &s.relay {
                println!("Relay    : {r}");
            }
            if let Some(e) = &s.endpoint {
                println!("Endpoint : {e}");
            }
            println!(
                "Prints   : {} positions claimed, {} won, {} links confirmed since start",
                s.claims_made, s.claims_won, s.links_confirmed
            );
        }
        (true, None) => println!("Daemon   : running"),
        (false, _) => println!("Daemon   : not running"),
    }
    println!("Terms    : {}", if cfg.volunteer { "volunteer (fees burned)" } else { "paid" });
    if keys::leftover_file(home) {
        println!(
            "WARNING  : {} is still on disk although the phrase is in the OS keystore              (an interrupted move). Destroy it with `kenter-node keystore wipe-file`.",
            home.phrase().display()
        );
    }
    println!();

    for (label, kp) in [("node", &pair.own), ("partner", &pair.partner)] {
        let v = chain.view(kp).await?;
        println!("{label}: {}", v.address);
        match v.native {
            None => println!("  balance  : account not created yet (send XLM to it)"),
            Some(n) => {
                let free = spendable(n, v.subentries);
                let warn = if v.node.is_some() && free < LOW_BALANCE { "  LOW: top up for fees" } else { "" };
                println!("  balance  : {} XLM ({} spendable){warn}", xlm(n), xlm(free));
            }
        }
        match &v.node {
            None => println!("  roster   : not a member"),
            Some(n) => {
                let state = match (n.active, n.unbonding_at) {
                    (_, Some(at)) => format!("unbonding, withdrawable at ledger {at}"),
                    (true, None) => "selectable".to_string(),
                    (false, None) => "inactive (not selectable)".to_string(),
                };
                println!("  roster   : {state}; stake {} XLM; {}", xlm(n.staked), if n.volunteer { "volunteer" } else { "paid" });
                if !n.tunnel_endpoint.is_empty() {
                    println!("  endpoint : {}", n.tunnel_endpoint);
                }
            }
        }
        if let Some(a) = v.accrued.filter(|a| *a > 0) {
            println!("  fees     : {} in the mint's fee token, owed (`kenter-node claim`)", xlm(a));
        }
    }
    if running && reported.as_ref().is_some_and(|s| s.state == State::Failed) {
        return Err("the daemon has stopped serving; see the detail above".into());
    }
    Ok(())
}

/// Commands that submit transactions run only with the daemon stopped, so
/// they never race its account sequence. The returned lock is held for
/// the whole command, so a daemon cannot start mid-way either.
fn stopped_node(home: &Home) -> Result<(DaemonLock, PairKeys, Chain), String> {
    let lock = DaemonLock::acquire(home).map_err(|e| {
        if e.contains("already running") {
            "the node is running; stop it first (Quit from the tray, or `kenter-node stop`)".to_string()
        } else {
            e
        }
    })?;
    let cfg = NodeConfig::load(home)?;
    let pair = PairKeys::load(home)?;
    let chain = Chain::new(cfg.network()?);
    Ok((lock, pair, chain))
}

async fn claim(home: &Home) -> Result<(), String> {
    let (_lock, pair, chain) = stopped_node(home)?;
    for kp in [&pair.own, &pair.partner] {
        let (got, code) = chain.claim(kp).await?;
        // Fee-token units (7 decimals, like XLM), named by the token.
        println!("{}: claimed {} {code}", kp.stellar_address(), xlm(got));
    }
    Ok(())
}

async fn leave(home: &Home) -> Result<(), String> {
    let (_lock, pair, chain) = stopped_node(home)?;
    for kp in [&pair.own, &pair.partner] {
        let at = chain.leave(kp).await?;
        println!("{}: unbonding; withdrawable from ledger {at}", kp.stellar_address());
    }
    println!("Run `kenter-node withdraw` once that ledger has passed (about a week).");
    Ok(())
}

async fn withdraw(home: &Home) -> Result<(), String> {
    let (_lock, pair, chain) = stopped_node(home)?;
    for kp in [&pair.own, &pair.partner] {
        // Say why before the contract refuses with a bare trap.
        match chain.view(kp).await?.node {
            None => {
                println!("{}: not on the roster; nothing to withdraw", kp.stellar_address());
                continue;
            }
            Some(n) if n.unbonding_at.is_none() => {
                return Err(format!(
                    "{} has not left the roster; run `kenter-node leave` first",
                    kp.stellar_address()
                ));
            }
            Some(_) => {}
        }
        let got = chain.withdraw(kp).await?;
        println!("{}: {} XLM returned", kp.stellar_address(), xlm(got));
    }
    // Gather the pair's XLM back on the node's own address, one sum.
    match chain.sweep_partner(&pair.own, &pair.partner).await {
        Ok(0) => {}
        Ok(moved) => println!("{} XLM moved from the partner to {}", xlm(moved), pair.own.stellar_address()),
        Err(e) => eprintln!("(the partner's XLM stays where it is: {e})"),
    }
    Ok(())
}

/// `keystore` (where the phrase is), `keystore enable` (file to OS
/// keystore), `keystore disable` (back to a file). Moving needs the node
/// stopped: the lock is held throughout.
fn keystore_cmd(home: &Home, rest: &[String]) -> Result<(), String> {
    use kenter_node::config::KeyStore;
    match rest.first().map(String::as_str) {
        None | Some("status") => {
            let cfg = NodeConfig::load(home)?;
            match cfg.key_store {
                KeyStore::File => println!("The phrase is in {}", home.phrase().display()),
                KeyStore::Os => println!("The phrase is in the OS keystore (kenter-node / {})", cfg.key_id.unwrap_or_default()),
            }
            if !keys::os::supported() {
                println!("This build has no OS keystore.");
            }
            Ok(())
        }
        Some("wipe-file") => {
            let _lock = DaemonLock::acquire(home).map_err(|e| {
                if e.contains("already running") { "the node is running; stop it first".to_string() } else { e }
            })?;
            keys::wipe_leftover(home)?;
            println!("The leftover phrase file has been destroyed.");
            Ok(())
        }
        Some(op @ ("enable" | "disable")) => {
            let _lock = DaemonLock::acquire(home).map_err(|e| {
                if e.contains("already running") { "the node is running; stop it first".to_string() } else { e }
            })?;
            if op == "enable" {
                keys::move_to_os(home)?;
                println!("The phrase is now in the OS keystore, and its file has been destroyed.");
            } else {
                keys::move_to_file(home)?;
                println!("The phrase is now in {}, and the keystore entry is deleted.", home.phrase().display());
            }
            Ok(())
        }
        Some(other) => Err(format!("keystore: unknown action {other:?} (status, enable, disable, wipe-file)")),
    }
}

fn show_phrase(home: &Home) -> Result<(), String> {
    let phrase = keys::load_phrase(home)?;
    eprintln!("Anyone who sees this phrase can take the pair's stake.");
    println!("{}", &*phrase);
    Ok(())
}
