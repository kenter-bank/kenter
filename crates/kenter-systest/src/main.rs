//! The local system test (`docs/SYSTEM_TEST.md`).
//!
//! Brings up a relay and real node daemons on this machine, points two GUI
//! clients at them, and checks the ledger after each step the operator takes.
//!
//! # What it does and does not drive
//!
//! It provisions accounts, runs the daemons, and makes every assertion. It
//! does **not** drive the GUI: there are no automation hooks, and inventing
//! some in order to test the UI would mostly test the hooks. So it stops at
//! each manual step, says exactly what to do in the window, and reads the
//! ledger when told to continue.
//!
//! # What an assertion is
//!
//! A ledger-visible consequence, not a screen that advanced. Escrow moved, a
//! slot was allocated, links were confirmed *by the nodes*, a token record
//! exists, an owner pointer moved, a payout landed. The observed value goes
//! in the log whether the check passed or failed, so one run can be compared
//! with another.
//!
//! # Secrets
//!
//! Node keys are generated per run and live only in memory and in the child
//! processes' environment — never argv, never disk. The log records
//! addresses. The one secret the harness needs from outside is the funder's,
//! read from `KENTER_SYSTEST_FUNDER_SECRET`.

mod chain;
mod fund;
mod log;
mod procs;

use chain::Account;
use kenter_client::{TokenMode, TokenState};
use kenter_vault::{KeyVault, SoftVault};
use log::Recorder;
use procs::{Daemon, EnvVar};
use zeroize::Zeroizing;

/// Circle's testnet USDC (`docs/TESTNET.md`): its Stellar Asset Contract
/// and issuer. The mint under test must escrow this asset.
const USDC_SAC: &str = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
const USDC_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

/// The build's testnet contracts, with `KENTER_MINT` / `KENTER_ROSTER`
/// applied; empty when there are none (checked before a run starts).
fn network_default(pick: fn(&kenter_client::NetworkConfig) -> String) -> String {
    kenter_client::NetworkConfig::from_env().map(|c| pick(&c)).unwrap_or_default()
}

/// What client 1 deposits, in stroops. Small enough to run many times on a
/// modest testnet balance, large enough that the fee is not the whole note.
const DEPOSIT: i128 = 10_000_000;
/// What a run tops client 1 up to, when it is short.
///
/// Three deposits of 1.00 plus margin. Topping up *to* a figure rather than
/// *by* one matters: a client that still holds the USDC from the last run
/// needs nothing, and a harness that sends five every time drains the funder
/// in four runs — which is exactly what happened.
const SEED_USDC: i128 = 50_000_000;
/// Below this, client 1 cannot finish the run, so it gets topped up.
const NEED_USDC: i128 = 40_000_000;
/// What phase 8 prints.
///
/// Deliberately a tenth of what the client phases use. Phase 8 proves a
/// protocol path, not an amount, and its payout goes to a freshly generated
/// payee that nothing ever sweeps — so every run of it spends the face value
/// out of the funder for good. Testnet USDC is refilled by hand from an
/// interactive faucet, and a dollar a run is how the funder ran dry. A tenth
/// still dwarfs the 800-stroop fee, so the arithmetic under test is the same
/// arithmetic.
const SMALL_DEPOSIT: i128 = 1_000_000;

const USAGE: &str = "\
kenter-systest — the local system test

USAGE:
    kenter-systest [OPTIONS]

SECRETS (never on argv):
    KENTER_SYSTEST_FUNDER_SECRET   a funded testnet secret holding USDC
    TUNNLER_SERVER_SECRET          a local relay's identity (usually from .env);
                                   needed only when the run starts one

OPTIONS:
    --nodes <n>        node daemons to run (default 2)
    --skip-test        unattended: start a local relay and three local nodes,
                       print 4 pairs, kill the node drawn for position 1 as
                       soon as positions are fixed, and check the wallet code
                       skips it for the runner-up and the note still prints.
                       Best with other operators' nodes offline.
    --burst <n>        unattended: n fresh depositors send request_print at
                       the same moment, so several land in one ledger; check
                       every one got its own slot, then cancel each before
                       its round is out (a full refund). Starts no nodes.
    --remote <pairs>   print one note of <pairs> pairs across whatever
                       nodes the network selects, reaching each through its own relay, instead of
                       starting any here; redeem it and check every fee.
    --volunteers <k>   the first k of them join as volunteers, whose fees
                       the mint burns; phase 8 checks the burn (default 0)
    --relay <host>     the relay this run's nodes reach the network through.
                       The wallet reaches a selected node only through the
                       relays built into the release, so the GUI phases
                       default to the build's first relay. --skip-test and
                       --from 8 print through the
                       harness itself and default to a local relay.
                       `local` forces a local relay.
    --port <p>         local relay port on 127.0.0.1 (default 8000)
    --mint <id>        mint contract (default: the USDC mint)
    --roster <id>      roster contract
    --run-dir <path>   where clients, logs and artifacts go
    --stay-joined      leave this run's nodes on the roster at the end. By
                       default they leave: a node that never leaves counts
                       toward every daemon's estimate of the roster for
                       good, though it will never serve again
    --keep-going       do not stop at the first failed check
    --preflight        check the environment and stop, provisioning nothing
    --manual-clients   print the client environment instead of launching them
    --from <phase>     skip to a phase (3, 3b, 4, 5, 6, 7, 8); earlier ones
                       are assumed done. Provisioning and the network always
                       run. `--from 8` needs no clients and no human.
    --step-file <path> wait for this file at each manual step instead of stdin
    --fund <G...>      fund a wallet the GUI just made, and exit. XLM, then
                       the mint's asset once the wallet has a trustline for
                       it. Safe to repeat. See `fund.rs` for the order.
    --amount <usdc>    how much --fund sends, in USDC (default 5)
    --help

The run is interactive: it stops at each step that needs the window.";

struct Config {
    nodes: usize,
    /// How many of the node daemons (the first ones) join as volunteers,
    /// whose fees the mint burns. Phase 8
    /// then checks the burn on the ledger.
    volunteers: usize,
    /// Print one note of this many pairs across the network's selection,
    /// instead of starting any nodes here (`--remote`).
    remote_pairs: Option<u32>,
    /// Fire this many simultaneous print requests (`--burst`) and stop.
    burst: Option<usize>,
    /// Run the unattended skip test (`--skip-test`) and stop.
    skip_test: bool,
    /// The relay the nodes tunnel through: a public host (TLS), or `None`
    /// for one the harness starts on 127.0.0.1 (`--relay`).
    relay: Option<String>,
    /// `--relay` was given, so the default for the run is not applied.
    relay_given: bool,
    port: u16,
    mint: String,
    roster: String,
    run_dir: std::path::PathBuf,
    keep_going: bool,
    /// Do not have this run's nodes leave the roster at the end.
    stay_joined: bool,
    /// Check the environment and stop. Nothing is generated, funded or
    /// joined to the roster, so it is safe to run as often as you like —
    /// which is the point: find a wrong mint or an empty funder before
    /// committing six accounts and an operator's attention to a run.
    preflight_only: bool,
    /// Launch the two clients yourself instead of letting the harness do it.
    ///
    /// The harness launching them is the default because it already knows
    /// every variable, and a client started against the wrong mint or the
    /// wrong wallet directory invalidates the whole run while looking fine.
    /// Worth having the escape hatch anyway: a client that needs restarting
    /// mid-run, or one run under a debugger, has to be started by hand.
    manual_clients: bool,
    /// Advance manual steps by creating this file rather than pressing Enter.
    ///
    /// For running the harness somewhere with no usable stdin — a background
    /// process, or an agent driving it a phase at a time. Closed stdin is
    /// worse than useless here: `read_line` returns immediately at EOF, so
    /// every pause would fall straight through and the run would assert
    /// against work nobody had done yet.
    step_file: Option<std::path::PathBuf>,
    /// Send USDC to this address and exit, running no test.
    ///
    /// The client has no surface for its own Stellar account yet — no
    /// balance, no address to fund, no way to see USDC arrive — so topping a
    /// client up during a run is something only the outside can do. A flag
    /// rather than a hand-rolled CLI invocation each time, because the
    /// hand-rolled one is where a wrong contract id or a missing decimal
    /// gets in.
    fund_to: Option<String>,
    /// What `--fund` sends, in stroops.
    fund_amount: i128,
    /// Start at this phase, assuming the earlier ones already happened.
    ///
    /// A manual run costs an operator real attention, and losing all of it
    /// to a failure in phase four is the kind of thing that stops a test
    /// being run at all. The daemons and the clients still come up — those
    /// are cheap and have to exist — but first run, the deposit and the
    /// stall are skipped when they are already behind you.
    from_phase: String,
}

/// One node daemon: the pair it serves, and the process serving it.
struct Node {
    own: Account,
    partner: Account,
    daemon: Option<Daemon>,
}

struct Run {
    cfg: Config,
    rec: Recorder,
    funder: Account,
    nodes: Vec<Node>,
    relay: Option<Daemon>,
    clients: Vec<Daemon>,
    client1: Option<String>,
    client2: Option<String>,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let _ = dotenvy::dotenv();
    let cfg = match parse_args() {
        Ok(Some(cfg)) => cfg,
        Ok(None) => return std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            return std::process::ExitCode::FAILURE;
        }
    };

    match run(cfg).await {
        Ok(0) => std::process::ExitCode::SUCCESS,
        Ok(_) => std::process::ExitCode::FAILURE,
        Err(e) => {
            eprintln!("\nerror: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn parse_args() -> Result<Option<Config>, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut cfg = Config {
        nodes: 2,
        volunteers: 0,
        remote_pairs: None,
        burst: None,
        skip_test: false,
        relay: None,
        relay_given: false,
        port: 8000,
        mint: std::env::var("KENTER_SYSTEST_MINT").unwrap_or_else(|_| network_default(|c| c.mint.clone())),
        roster: network_default(|c| c.roster.clone()),
        run_dir: std::path::PathBuf::from("target").join("systest"),
        keep_going: false,
        stay_joined: false,
        preflight_only: false,
        manual_clients: false,
        step_file: None,
        fund_to: None,
        fund_amount: SEED_USDC,
        from_phase: "0".into(),
    };
    fn next(args: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
        *i += 1;
        args.get(*i).cloned().ok_or_else(|| format!("{flag} needs a value"))
    }

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--nodes" => {
                cfg.nodes = next(&args, &mut i, "--nodes")?
                    .parse()
                    .map_err(|_| "--nodes must be a number")?
            }
            "--skip-test" => cfg.skip_test = true,
            "--burst" => {
                cfg.burst = Some(
                    next(&args, &mut i, "--burst")?
                        .parse()
                        .map_err(|_| "--burst takes a number of requests")?,
                )
            }
            "--relay" => {
                let v = next(&args, &mut i, "--relay")?;
                cfg.relay = (v != "local").then_some(v);
                cfg.relay_given = true;
            }
            "--remote" => {
                cfg.remote_pairs = Some(
                    next(&args, &mut i, "--remote")?
                        .parse()
                        .map_err(|_| "--remote takes a pair count, at least 3")?,
                )
            }
            "--volunteers" => {
                cfg.volunteers = next(&args, &mut i, "--volunteers")?
                    .parse()
                    .map_err(|_| "--volunteers must be a number")?
            }
            "--port" => {
                cfg.port = next(&args, &mut i, "--port")?
                    .parse()
                    .map_err(|_| "--port must be a number")?
            }
            "--mint" => cfg.mint = next(&args, &mut i, "--mint")?,
            "--roster" => cfg.roster = next(&args, &mut i, "--roster")?,
            "--run-dir" => cfg.run_dir = next(&args, &mut i, "--run-dir")?.into(),
            "--keep-going" => cfg.keep_going = true,
            "--stay-joined" => cfg.stay_joined = true,
            "--preflight" => cfg.preflight_only = true,
            "--manual-clients" => cfg.manual_clients = true,
            "--step-file" => cfg.step_file = Some(next(&args, &mut i, "--step-file")?.into()),
            "--from" => cfg.from_phase = next(&args, &mut i, "--from")?,
            "--fund" => cfg.fund_to = Some(next(&args, &mut i, "--fund")?),
            "--amount" => {
                let v = next(&args, &mut i, "--amount")?;
                let stroops = v
                    .parse::<f64>()
                    .map_err(|_| "--amount must be a number of USDC".to_string())?;
                cfg.fund_amount = (stroops * 10_000_000.0).round() as i128;
            }
            "--help" | "-h" => {
                println!("{USAGE}");
                return Ok(None);
            }
            other => return Err(format!("unexpected argument: {other:?}")),
        }
        i += 1;
    }
    if cfg.volunteers > cfg.nodes {
        return Err("--volunteers cannot exceed --nodes".into());
    }
    if cfg.nodes == 0 {
        return Err("a networked print needs at least one node".into());
    }
    // The GUI wallet reaches a selected node only through the relays built
    // into the release; a node behind a relay on 127.0.0.1 is one it can
    // never reach. The harness's own prints (the skip
    // test, phase 8) name their relay, so a local one serves them.
    if !cfg.relay_given && !cfg.skip_test && cfg.from_phase != "8" && cfg.remote_pairs.is_none() && cfg.burst.is_none() {
        cfg.relay = kenter_client::network::TESTNET.relays.first().map(|h| h.to_string());
    }
    if cfg.mint.is_empty() || cfg.roster.is_empty() {
        return Err("no mint or roster: set KENTER_MINT and KENTER_ROSTER (or --mint / --roster), or build with KENTER_TESTNET_MINT and KENTER_TESTNET_ROSTER"
            .into());
    }
    Ok(Some(cfg))
}

async fn run(cfg: Config) -> Result<usize, String> {
    let secret = std::env::var("KENTER_SYSTEST_FUNDER_SECRET").map_err(|_| {
        "set KENTER_SYSTEST_FUNDER_SECRET to a funded testnet secret holding USDC \
         (e.g. from `stellar keys show testnet-deployer`). Not accepted on argv."
            .to_string()
    })?;
    let funder = {
        let keypair = kenter_crypto::keypair::StellarKeypair::from_stellar_secret(&secret)
            .map_err(|e| format!("bad KENTER_SYSTEST_FUNDER_SECRET: {e}"))?;
        Account {
            address: keypair.stellar_address(),
            keypair,
            label: "funder".into(),
        }
    };

    // Before anything else: --fund is a one-shot errand, not a test run, and
    // it should not create a results log or a run directory.
    if let Some(to) = cfg.fund_to.clone() {
        return fund::errand(&funder, &to, cfg.fund_amount, &cfg.mint).await;
    }

    std::fs::create_dir_all(&cfg.run_dir).map_err(|e| format!("{}: {e}", cfg.run_dir.display()))?;
    let rec = Recorder::new(std::path::Path::new("docs/systest-runs"), "Kenter local system test")
        .map_err(|e| format!("results log: {e}"))?;

    let mut run = Run {
        cfg,
        rec,
        funder,
        nodes: Vec::new(),
        relay: None,
        clients: Vec::new(),
        client1: None,
        client2: None,
    };

    let outcome = run.all_phases().await;

    // Teardown happens whatever went wrong: a harness that panics or bails
    // must not leave daemons holding the relay port and a roster identity.
    run.teardown();
    run.leave_roster().await;
    run.rec.verdict();
    println!("\nlog: {}", run.rec.path().display());

    outcome?;
    Ok(run.rec.failed)
}

impl Run {
    async fn all_phases(&mut self) -> Result<(), String> {
        self.preflight().await?;
        if self.cfg.preflight_only {
            self.rec.note("--preflight: stopping before anything is provisioned");
            return Ok(());
        }
        if let Some(pairs) = self.cfg.remote_pairs {
            return self.remote_print(pairs).await;
        }
        if let Some(n) = self.cfg.burst {
            return self.burst_test(n).await;
        }
        if self.cfg.skip_test {
            // Three pairs claim for two positions, so there is a runner-up.
            self.cfg.nodes = self.cfg.nodes.max(3);
            self.provision().await?;
            self.bring_up_network().await?;
            return self.skip_test().await;
        }
        self.provision().await?;
        self.bring_up_network().await?;
        // Phase 8 drives everything itself, so starting two windows for it
        // would only invite the operator to act in them — which is how four
        // phases got measured against a baseline taken after the fact.
        if self.cfg.from_phase != "8" {
            self.clients().await?;
        }
        if self.wants("3") {
            self.networked_deposit().await?;
        }
        if self.wants("3b") {
            self.stalled_print().await?;
        }
        if self.wants("4") {
            self.export().await?;
        }
        if self.wants("5") {
            self.spend_and_accept().await?;
        }
        if self.wants("6") {
            self.redeem_note().await?;
        }
        if self.wants("7") {
            self.claim_fees().await?;
        }
        if self.wants("8") {
            self.directed_redeem().await?;
        }
        Ok(())
    }

    /// Should this phase run, given `--from`?
    ///
    /// Ordered by the sequence in the runbook rather than numerically,
    /// because "3b" sits between 3 and 4 and no number does.
    fn wants(&self, phase: &str) -> bool {
        const ORDER: [&str; 8] = ["0", "3", "3b", "4", "5", "6", "7", "8"];
        let at = |p: &str| ORDER.iter().position(|x| *x == p);
        match (at(&self.cfg.from_phase), at(phase)) {
            (Some(from), Some(this)) => this >= from,
            // An unrecognised --from runs everything rather than silently
            // skipping the test someone asked for.
            _ => true,
        }
    }

    /// Stop on the first failed check unless told otherwise. Phases build on
    /// each other, so carrying on usually produces a cascade that buries the
    /// one thing that actually broke.
    fn gate(&self) -> Result<(), String> {
        if self.rec.failed > 0 && !self.cfg.keep_going {
            return Err("a check failed — stopping (pass --keep-going to continue)".into());
        }
        Ok(())
    }

    // ── preflight ───────────────────────────────────────────────────────

    async fn preflight(&mut self) -> Result<(), String> {
        self.rec.phase("Preflight");
        self.rec.note(&format!("mint   {}", self.cfg.mint));
        self.rec.note(&format!("roster {}", self.cfg.roster));
        self.rec.note(&format!("nodes  {}", self.cfg.nodes));
        self.rec.note(&format!("funder {}", self.funder.address));

        let funded = chain::exists(&self.funder.address).await;
        self.rec.check(funded, "the funder account exists", &self.funder.address);

        let mut mint = chain::mint(&self.funder, &self.cfg.mint);
        let pay_token = mint.pay_token().await.map_err(|e| format!("pay_token: {e}"))?;
        self.rec.check(
            pay_token == USDC_SAC,
            "the mint escrows USDC",
            &pay_token,
        );

        // Reported, not asserted. Whether this is enough depends on what
        // the clients already hold, which is not known until they are read —
        // and failing here would block a run that needed no top-up at all.
        let balance = chain::balance(&self.funder, USDC_SAC, &self.funder.address).await?;
        self.rec.note(&format!("funder holds {balance} stroops USDC"));

        match &self.cfg.relay {
            Some(host) => self.rec.note(&format!("nodes reach the network through {host}")),
            None => {
                if std::env::var("TUNNLER_SERVER_SECRET").is_err() {
                    return Err("TUNNLER_SERVER_SECRET is not set (it is normally in .env)".into());
                }
                self.rec.note(&format!("nodes use a local relay on 127.0.0.1:{}", self.cfg.port));
            }
        }
        self.gate()
    }

    /// How the harness reaches its nodes when it prints itself.
    fn reach(&self) -> Result<kenter_print::Reach, String> {
        let relay = match &self.cfg.relay {
            Some(host) => kenter_print::NodeRelay::new(host, true)?,
            None => kenter_print::NodeRelay::new(&format!("127.0.0.1:{}", self.cfg.port), false)?,
        };
        Ok(kenter_print::Reach::Fixed(relay))
    }

    /// The `kenter-node` arguments that point a node at this run's relay.
    fn tunnel_args(&self) -> Vec<String> {
        match &self.cfg.relay {
            Some(host) => vec!["--tunnel".into(), host.clone()],
            None => vec![
                "--tunnel".into(),
                format!("127.0.0.1:{}", self.cfg.port),
                "--insecure".into(),
            ],
        }
    }

    // ── phase 0 ─────────────────────────────────────────────────────────

    async fn provision(&mut self) -> Result<(), String> {
        self.rec.phase("Phase 0 — provision");

        for i in 0..self.cfg.nodes {
            let own = Account::generate(&format!("node{}-own", i + 1));
            let partner = Account::generate(&format!("node{}-partner", i + 1));
            self.nodes.push(Node { own, partner, daemon: None });
        }

        // Collected first so the borrow of `self.nodes` ends before the log
        // and the network calls, which need `&mut self`.
        let accounts: Vec<(String, String)> = self
            .nodes
            .iter()
            .flat_map(|n| [&n.own, &n.partner])
            .map(|a| (a.label.clone(), a.address.clone()))
            .collect();

        for (label, address) in &accounts {
            let what = chain::fund(address).await?;
            self.rec.note(&format!("{label} {address} — {what}"));
        }

        // Only needed to claim fees (Phase 7), but it is one transaction and
        // it makes that leg testable rather than aspirational.
        for i in 0..self.nodes.len() {
            for which in 0..2 {
                let account = if which == 0 { &self.nodes[i].own } else { &self.nodes[i].partner };
                let label = account.label.clone();
                let what = chain::ensure_trustline(account, "USDC", USDC_ISSUER).await?;
                self.rec.note(&format!("{label} USDC trustline — {what}"));
            }
        }

        self.rec.check(
            accounts.len() == self.cfg.nodes * 2,
            "two accounts per node pair",
            accounts.len(),
        );
        self.gate()
    }

    // ── phase 1 ─────────────────────────────────────────────────────────

    async fn bring_up_network(&mut self) -> Result<(), String> {
        self.rec.phase("Phase 1 — bring up the network");
        let log_dir = self.cfg.run_dir.join("logs");
        let host = format!("127.0.0.1:{}", self.cfg.port);

        // A local relay only when the nodes are not using a public one.
        if self.cfg.relay.is_none() {
            let relay_env: Vec<EnvVar> = vec![
                ("TUNNLER_HOST", Zeroizing::new("127.0.0.1".to_string())),
                ("TUNNLER_PORT", Zeroizing::new(self.cfg.port.to_string())),
                ("ROSTER_CONTRACT_ID", Zeroizing::new(self.cfg.roster.clone())),
                // The relay gates connections on roster membership and caches the
                // answer. A depositor joins the roster moments before it first
                // connects, so a long cache would hold a "not a node" from before
                // the join and lock the client out of its own first deposit.
                ("TUNNLER_ROSTER_CACHE_TTL", Zeroizing::new("5".to_string())),
            ];
            let mut relay = Daemon::spawn("relay", "kenter-tunnler", &[], &relay_env, &log_dir)?;
            relay.wait_for("listening", 30)?;
            self.rec.note(&format!("relay listening on {host}"));
            self.relay = Some(relay);
        }

        for i in 0..self.nodes.len() {
            let name = format!("node{}", i + 1);
            let mut args = self.tunnel_args();
            args.extend([
                "--mint".into(),
                self.cfg.mint.clone(),
                "--roster".into(),
                self.cfg.roster.clone(),
                "--label".into(),
                format!("systest-{name}"),
            ]);
            if i < self.cfg.volunteers {
                args.push("--volunteer".into());
            }
            let env: Vec<EnvVar> = vec![
                ("KENTER_NODE_SECRET", self.nodes[i].own.keypair.stellar_secret()),
                (
                    "KENTER_NODE_PARTNER_SECRET",
                    self.nodes[i].partner.keypair.stellar_secret(),
                ),
            ];
            let mut daemon = Daemon::spawn(&name, "kenter-node", &args, &env, &log_dir)?;
            // Roster joins are two transactions, so the first start is slow.
            daemon.wait_for("node is serving", 120)?;
            self.rec.note(&format!(
                "{name} serving as {} paired with {}{}",
                self.nodes[i].own.address,
                self.nodes[i].partner.address,
                if i < self.cfg.volunteers { " (volunteer)" } else { "" }
            ));
            self.nodes[i].daemon = Some(daemon);
        }

        // The daemons report their own joins; this is the ledger agreeing.
        let mut roster = kenter_client::RosterClient::new(self.funder.tx(), &self.cfg.roster);
        let addresses: Vec<String> = self
            .nodes
            .iter()
            .flat_map(|n| [n.own.address.clone(), n.partner.address.clone()])
            .collect();
        for address in addresses {
            let is_node = roster
                .is_node(&address)
                .await
                .map_err(|e| format!("is_node({address}): {e}"))?;
            self.rec.check(is_node, "on the roster", &address);
        }
        self.gate()
    }

    // ── phase 2 ─────────────────────────────────────────────────────────

    async fn clients(&mut self) -> Result<(), String> {
        self.rec.phase("Phase 2 — first run and trustline");

        let c1 = self.cfg.run_dir.join("client1");
        let c2 = self.cfg.run_dir.join("client2");

        // No node list and no relay setting: the wallet finds the nodes the
        // draw selects on the roster and reaches them through the relays
        // built into the release. This run's nodes
        // tunnel through that relay, so they are among them.
        let env_for = |_n: usize, dir: &std::path::Path| -> Vec<EnvVar> {
            let env: Vec<EnvVar> = vec![
                ("KENTER_WALLET_DIR", Zeroizing::new(dir.join("wallet").display().to_string())),
                ("KENTER_VAULT", Zeroizing::new(dir.join("vault").display().to_string())),
                ("KENTER_MINT", Zeroizing::new(self.cfg.mint.clone())),
                ("KENTER_ROSTER", Zeroizing::new(self.cfg.roster.clone())),
                // These are throwaway testnet wallets created and discarded
                // by a test. Retyping 24 words by hand per run is the kind
                // of friction that gets a test run less often.
                ("KENTER_DEV_COPY_PHRASE", Zeroizing::new("1".to_string())),
            ];
            env
        };

        if self.cfg.manual_clients {
            println!("\nStart each client in its own terminal, with its own environment:\n");
            for (n, dir) in [(1, &c1), (2, &c2)] {
                println!("  # client {n}");
                for (k, v) in env_for(n, dir) {
                    println!("  {k}={}", v.as_str());
                }
                println!("  cargo run -p kenter-ui\n");
            }
        } else {
            let log_dir = self.cfg.run_dir.join("logs");
            for (n, dir) in [(1, &c1), (2, &c2)] {
                let name = format!("client{n}");
                let mut client =
                    Daemon::spawn(&name, "kenter-ui", &[], &env_for(n, dir), &log_dir)?;

                // The window announces its mint and roster on startup, which
                // turns the one thing that could silently invalidate the run
                // into an assertion. It also settles whether the `.env` in
                // the working directory can override what was passed here:
                // the line says which ids the client actually resolved.
                client.wait_for("kenter: mint", 60)?;
                let line = client
                    .log()
                    .lines()
                    .find(|l| l.starts_with("kenter: mint"))
                    .unwrap_or_default()
                    .to_string();
                self.rec.check(
                    line.contains(&self.cfg.mint) && line.contains(&self.cfg.roster),
                    &format!("client {n} resolved the right mint and roster"),
                    &line,
                );
                self.clients.push(client);
            }
            self.rec.note("both clients launched by the harness");
        }
        self.gate()?;

        pause(self.cfg.step_file.as_deref(), &[
            "In EACH client: complete first run (passphrase, phrase, account).",
            "It then shows an address and waits. Send it at least 3 XLM.",
            "It adds the trustline itself once the XLM lands, then lets you in.",
            "Client 1's Account page should show its USDC and XLM balances.",
        ])?;

        for (n, dir) in [(1, &c1), (2, &c2)] {
            let vault_path = dir.join("vault");
            let address = read_vault_address(&vault_path)?;
            self.rec.check(true, &format!("client {n} account"), &address);

            // Deliberately no faucet here. Funding a client is the one
            // step that has to come from outside it, and a harness that
            // quietly does it skips the whole first-run flow it is meant to
            // be exercising.
            self.rec.check(
                chain::exists(&address).await,
                &format!("client {n} was funded from outside"),
                &address,
            );

            // read_only, not a throwaway keypair: `TxBuilder::new` derives the
            // source address FROM the keypair, so a random one asks the
            // ledger about a random account and reports every trustline
            // missing. Same trap that hid the trustline offer in Settings.
            let has = kenter_client::TxBuilder::read_only(
                kenter_client::SorobanRpcClient::new(chain::RPC, chain::PASSPHRASE),
                &address,
            )
                .has_trustline("USDC", USDC_ISSUER)
                .await
                .map_err(|e| format!("has_trustline: {e}"))?;
            self.rec.check(
                has,
                &format!("client {n} has a USDC trustline (added at first run)"),
                &address,
            );
            if n == 1 {
                self.client1 = Some(address);
            } else {
                self.client2 = Some(address);
            }
        }

        let c1_address = self.client1.clone().expect("client 1");
        let held = chain::balance(&self.funder, USDC_SAC, &c1_address).await?;
        if held < NEED_USDC {
            let short = SEED_USDC - held;
            let funder_has = chain::balance(&self.funder, USDC_SAC, &self.funder.address).await?;
            if funder_has < short {
                return Err(format!(
                    "client 1 holds {held} stroops and needs {SEED_USDC}, but the funder has \
                     only {funder_has}. Top the funder up from Circle's faucet \
                     (faucet.circle.com), or pass a smaller run."
                ));
            }
            chain::pay(&self.funder, USDC_SAC, &c1_address, short).await?;
            self.rec.note(&format!("topped client 1 up by {short} stroops"));
        } else {
            self.rec.note(&format!("client 1 already holds {held} stroops — no top-up"));
        }
        let balance = chain::balance(&self.funder, USDC_SAC, &c1_address).await?;
        self.rec.check(
            balance >= DEPOSIT,
            "client 1 holds enough USDC to deposit",
            format!("{balance} stroops"),
        );
        self.gate()
    }

    // ── phase 3 ─────────────────────────────────────────────────────────

    async fn networked_deposit(&mut self) -> Result<(), String> {
        self.rec.phase("Phase 3 — networked deposit");
        let client1 = self.client1.clone().expect("client 1");
        let mint_id = self.cfg.mint.clone();

        let since = chain::latest_ledger().await?;
        let escrow_before = chain::balance(&self.funder, USDC_SAC, &mint_id).await?;
        let holder_before = chain::balance(&self.funder, USDC_SAC, &client1).await?;
        let want_pairs = self.cfg.nodes as u32 + 2;

        pause(self.cfg.step_file.as_deref(), &[
            &format!("In client 1: Deposit 1.00, mode = bearer, {want_pairs} pairs, then confirm."),
            "Nothing names the nodes: they select themselves, seeded by drand.",
            "Watch the node logs: the selected ones log `link confirmed on-chain`.",
        ])?;

        // A registered print deletes its slot, so the events are the record.
        let print = self.print_by(&client1, since).await?;
        self.rec.check(print.total_pairs == want_pairs, "pairs in the print", print.total_pairs);
        self.rec.check(print.registered, "the print registered a note", print.slot_id);
        self.rec.check(print.amount == DEPOSIT, "amount escrowed", print.amount);
        let token = chain::mint(&self.funder, &mint_id)
            .get_token(print.slot_id)
            .await
            .map_err(|e| format!("get_token: {e}"))?;
        self.rec.check(
            token.as_ref().is_some_and(|t| t.state == TokenState::Active && t.amount == DEPOSIT),
            "the note is live on the ledger, at its face value",
            format!("{:?}", token.as_ref().map(|t| (t.state.clone(), t.amount))),
        );
        self.rec.check(
            token.as_ref().is_some_and(|t| t.participants_len == want_pairs * 2),
            "participants named",
            format!("{:?}", token.as_ref().map(|t| t.participants_len)),
        );
        self.rec.check(
            print.chain.len() == want_pairs as usize,
            "selection closed on a whole chain",
            print.chain.len(),
        );

        // The draw chose the interior, so positions are
        // whoever won, not node i at link i. What must hold: every interior
        // pair is a pair registered with the mint, and none repeats.
        let interior: Vec<(String, String)> = if print.chain.len() >= 2 {
            print.chain[1..print.chain.len() - 1].to_vec()
        } else {
            Vec::new()
        };
        let mut mint_r = chain::mint(&self.funder, &mint_id);
        let mut seen = std::collections::HashSet::new();
        for (a, b) in &interior {
            let registered = mint_r
                .pair_of(a)
                .await
                .map_err(|e| format!("pair_of: {e}"))?
                .is_some_and(|(p, _)| &p == b);
            let ours = self.nodes.iter().any(|n| n.own.address == *a);
            self.rec.check(
                registered && seen.insert(a.clone()),
                "an interior pair is a registered pair, once",
                format!("{a} / {b}{}", if ours { " (this run's)" } else { " (another operator's)" }),
            );
        }
        // And the depositor holds the two ends, which is what keeps the token
        // out of reach of any coalition of nodes.
        let holds = |p: &(String, String)| p.0 == client1 && p.1 == client1;
        let ends_held = print.chain.first().is_some_and(holds) && print.chain.last().is_some_and(holds);
        self.rec.check(
            ends_held || (holds(&print.first) && holds(&print.last)),
            "the depositor holds both ends of the chain",
            format!("{:?} … {:?}", print.first, print.last),
        );

        let escrow_after = chain::balance(&self.funder, USDC_SAC, &mint_id).await?;
        let holder_after = chain::balance(&self.funder, USDC_SAC, &client1).await?;
        self.rec.check(
            escrow_after - escrow_before == DEPOSIT,
            "the mint's escrow grew by the deposit",
            escrow_after - escrow_before,
        );
        self.rec.check(
            holder_before - holder_after == DEPOSIT,
            "client 1 paid the deposit",
            holder_before - holder_after,
        );
        self.gate()
    }

    // ── phase 3b ────────────────────────────────────────────────────────

    async fn stalled_print(&mut self) -> Result<(), String> {
        self.rec.phase("Phase 3b — a selected node dies mid-print");
        let mint_id = self.cfg.mint.clone();

        let before_slot = chain::mint(&self.funder, &mint_id)
            .next_slot_id()
            .await
            .map_err(|e| format!("next_slot_id: {e}"))?;
        let escrow_before = chain::balance(&self.funder, USDC_SAC, &mint_id).await?;

        // A node the draw selected dies mid-print. The depositor skips a
        // silent pair after `serve_timeout`, and a runner-up serves, or,
        // with none left, the print cancels itself
        // (`docs/architecture/node-selection.md`).
        // Either way the operator does nothing, and that is what is checked.
        println!();
        println!("  >> In client 1: start another Deposit of 1.00 and confirm.");
        println!("  >> A node this run started will be killed once it is selected.");
        println!("\n  watching for the draw...");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(600);
        let mut killed: Option<usize> = None;
        let mut slot_id = None;
        while std::time::Instant::now() < deadline && killed.is_none() {
            let mint = chain::mint(&self.funder, &mint_id);
            let next = mint.next_slot_id().await.map_err(|e| format!("next_slot_id: {e}"))?;
            if next > before_slot {
                let id = next - 1;
                slot_id = Some(id);
                let ledger = chain::latest_ledger().await?;
                if let Some(slot) = mint.get_slot(id).await.map_err(|e| format!("get_slot: {e}"))? {
                    if let Some(chain_now) = slot.chain(ledger) {
                        let hit = self.nodes.iter().position(|n| {
                            chain_now.iter().any(|(a, _)| *a == n.own.address)
                        });
                        match hit {
                            Some(i) => {
                                if let Some(d) = self.nodes[i].daemon.as_mut() {
                                    d.stop();
                                }
                                self.nodes[i].daemon = None;
                                self.rec.note(&format!("slot {id}: stopped selected node {}", i + 1));
                                killed = Some(i);
                            }
                            None => {
                                self.rec.note(&format!(
                                    "slot {id}: no node of this run was selected, so none to kill"
                                ));
                                break;
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }

        pause(self.cfg.step_file.as_deref(), &[
            "Wait for client 1's deposit to finish: it should complete through a",
            "runner-up, or fail saying it cancelled and refunded. Touch nothing.",
        ])?;

        let Some(id) = slot_id else {
            self.rec.check(false, "a slot was requested", "none appeared");
            return self.gate();
        };
        let still = chain::mint(&self.funder, &mint_id)
            .get_slot(id)
            .await
            .map_err(|e| format!("get_slot: {e}"))?;
        self.rec.check(
            still.is_none(),
            "the print finished on its own: registered through a runner-up, or cancelled",
            match &still {
                None => "slot retired".to_string(),
                Some(s) => format!("still open at {}/{} links", s.completed_links, s.total_pairs),
            },
        );
        let escrow_end = chain::balance(&self.funder, USDC_SAC, &mint_id).await?;
        let grew = escrow_end - escrow_before;
        self.rec.check(
            grew == DEPOSIT || grew <= 0,
            "the escrow is either a registered note's or given back",
            grew,
        );
        if let Some(i) = killed {
            self.restart_node(i).await?;
        }
        self.gate()
    }

    /// Bring a stopped node back up with the same identity.
    async fn restart_node(&mut self, i: usize) -> Result<(), String> {
        if self.nodes[i].daemon.is_some() {
            return Ok(());
        }
        let name = format!("node{}", i + 1);
        let mut args = self.tunnel_args();
        args.extend([
            "--mint".into(),
            self.cfg.mint.clone(),
            "--roster".into(),
            self.cfg.roster.clone(),
            "--label".into(),
            format!("systest-{name}"),
        ]);
        let env: Vec<EnvVar> = vec![
            ("KENTER_NODE_SECRET", self.nodes[i].own.keypair.stellar_secret()),
            (
                "KENTER_NODE_PARTNER_SECRET",
                self.nodes[i].partner.keypair.stellar_secret(),
            ),
        ];
        let log_dir = self.cfg.run_dir.join("logs");
        let mut daemon = Daemon::spawn(&name, "kenter-node", &args, &env, &log_dir)?;
        // Already on the roster from the first start, so this is quick.
        daemon.wait_for("node is serving", 120)?;
        self.nodes[i].daemon = Some(daemon);
        self.rec.note(&format!("restarted node {}", i + 1));
        Ok(())
    }

    // ── phase 4 ─────────────────────────────────────────────────────────

    async fn export(&mut self) -> Result<(), String> {
        self.rec.phase("Phase 4 — Pay, bearer");
        let mint_id = self.cfg.mint.clone();
        // The client's outbox, because that is what the save dialog now
        // offers by default. Naming a directory of the harness's own would
        // make the operator navigate somewhere for no reason, and a step
        // that exists only to satisfy the test is a step that gets done
        // wrong.
        let dir = self.cfg.run_dir.join("client1").join("wallet").join("outbox");
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;

        let escrow_before = chain::balance(&self.funder, USDC_SAC, &mint_id).await?;
        let slot_before = chain::mint(&self.funder, &mint_id)
            .next_slot_id()
            .await
            .map_err(|e| format!("next_slot_id: {e}"))?;

        println!("\n  watching: {}\n", dir.display());
        pause(self.cfg.step_file.as_deref(), &[
            "In client 1: open a BEARER note on the billfold and press Export.",
            "Then 'Hand over...' and accept the location the dialog offers.",
            "(Verbs are on the note card now - there is no Pay button up top.)",
        ])?;

        let exported = newest_file(&dir)?;
        let slot_id = chain::slot_of(&exported)?;
        self.rec.check(true, "the exported file parses as a container", exported.display());

        let token = chain::mint(&self.funder, &mint_id)
            .get_token(slot_id)
            .await
            .map_err(|e| format!("get_token: {e}"))?;
        match token {
            Some(t) => {
                self.rec.check(
                    t.state == TokenState::Active,
                    "the exported note is live on the ledger",
                    format!("{:?}", t.state),
                );
                self.rec.check(t.amount == DEPOSIT, "its face value", t.amount);
            }
            None => {
                self.rec.check(false, "the exported note has a ledger record", "not found");
            }
        }

        // A bearer handover is off-chain. A transaction here would mean the
        // export is not what it claims to be.
        let escrow_after = chain::balance(&self.funder, USDC_SAC, &mint_id).await?;
        let slot_after = chain::mint(&self.funder, &mint_id)
            .next_slot_id()
            .await
            .map_err(|e| format!("next_slot_id: {e}"))?;
        self.rec.check(
            escrow_after == escrow_before,
            "exporting moved no value",
            format!("{escrow_before} → {escrow_after}"),
        );
        self.rec.check(
            slot_after == slot_before,
            "exporting allocated no slot",
            format!("{slot_before} → {slot_after}"),
        );
        self.gate()
    }

    // ── phase 5 ─────────────────────────────────────────────────────────

    async fn spend_and_accept(&mut self) -> Result<(), String> {
        self.rec.phase("Phase 5 — Pay, spend mode");
        let mint_id = self.cfg.mint.clone();
        let client1 = self.client1.clone().expect("client 1");
        let since = chain::latest_ledger().await?;

        pause(self.cfg.step_file.as_deref(), &[
            "In client 1: Deposit 1.00 with mode = spend, and let it finish.",
        ])?;
        let print = self.print_by(&client1, since).await?;
        let mode = chain::mint(&self.funder, &mint_id)
            .get_token(print.slot_id)
            .await
            .map_err(|e| format!("get_token: {e}"))?
            .map(|t| t.mode);
        self.rec.check(
            print.registered && mode == Some(TokenMode::Spend),
            "the spend-mode note registered",
            format!("slot {} {mode:?}", print.slot_id),
        );

        let inbox = self.cfg.run_dir.join("client2").join("wallet").join("inbox");
        println!("\n  client 2's inbox: {}\n", inbox.display());
        pause(self.cfg.step_file.as_deref(), &[
            "In client 2: Accept — copy the receive address it shows.",
            "In client 1: Pay → the spend-mode note → paste that address, confirm.",
            "In client 2: accept the note when it appears.",
        ])?;

        // `accepted/` first, for the same reason phase 6 does: the watch
        // moves a note there the moment the gates pass, so by the time there
        // is anything to assert about it has already left the inbox root.
        // Looking only in the root found nothing and called a completed
        // handover an empty inbox.
        let delivered =
            newest_file(&inbox.join("accepted")).or_else(|_| newest_file(&inbox))?;
        let slot_id = chain::slot_of(&delivered)?;
        self.rec.check(true, "a note reached client 2's inbox", delivered.display());

        let token = chain::mint(&self.funder, &mint_id)
            .get_token(slot_id)
            .await
            .map_err(|e| format!("get_token: {e}"))?
            .ok_or("the delivered note has no ledger record")?;

        self.rec.check(
            token.mode == TokenMode::Spend,
            "the note is spend mode",
            format!("{:?}", token.mode),
        );
        self.rec.check(
            token.owner_commitment != [0u8; 32],
            "it carries an owner commitment",
            hex::encode(token.owner_commitment),
        );
        self.rec.check(
            token.state == TokenState::Active,
            "it is still live after the transfer",
            format!("{:?}", token.state),
        );
        // Client 2 accepted it, and G3 compares the live commitment against
        // its own derived one — so an accepted note is the client's own
        // statement that the pointer now names it. The harness cannot derive
        // that commitment (it is behind client 2's passphrase), so what it
        // checks is that a pointer exists and the note survived the move.
        self.gate()
    }

    // ── phase 6 ─────────────────────────────────────────────────────────

    async fn redeem_note(&mut self) -> Result<(), String> {
        self.rec.phase("Phase 6 — Redeem");
        let mint_id = self.cfg.mint.clone();
        let client2 = self.client2.clone().expect("client 2");
        // `accepted/` first: the receive watch moves a note there once the
        // gates pass, so by the time there is anything to redeem it has
        // already left the inbox root. Looking only in the root found
        // nothing and reported it as an empty inbox.
        let inbox = self.cfg.run_dir.join("client2").join("wallet").join("inbox");
        let note = newest_file(&inbox.join("accepted")).or_else(|_| newest_file(&inbox))?;
        self.rec.note(&format!("redeeming {}", note.display()));
        let redeemed_slot = chain::slot_of(&note)?;
        // What the note's own record says it will cost: one `node_fee` per
        // interior participant, at the fee captured when it was printed.
        let record = chain::mint(&self.funder, &mint_id)
            .get_token(redeemed_slot)
            .await
            .map_err(|e| format!("get_token: {e}"))?
            .ok_or("the note to redeem has no ledger record")?;
        let node_fee = record.node_fee as i128;
        let interior_participants = (record.participants_len as i128 - 4).max(0);
        let winners = interior_pairs(&chain::parse_note(&note)?)?;
        let terms = terms_of(&self.funder, &self.cfg.roster, &winners).await?;

        let escrow_before = chain::balance(&self.funder, USDC_SAC, &mint_id).await?;
        let holder_before = chain::balance(&self.funder, USDC_SAC, &client2).await?;
        let accrued_before = self.accrued_by_node().await?;

        pause(self.cfg.step_file.as_deref(), &[
            "In client 2: Redeem the note it just accepted.",
        ])?;

        let mut mint = chain::mint(&self.funder, &mint_id);
        let redeemed = mint
            .is_redeemed(redeemed_slot)
            .await
            .map_err(|e| format!("is_redeemed: {e}"))?;
        self.rec.check(redeemed, "the note is redeemed", redeemed);

        let escrow_after = chain::balance(&self.funder, USDC_SAC, &mint_id).await?;
        let holder_after = chain::balance(&self.funder, USDC_SAC, &client2).await?;
        self.rec.check(
            escrow_before - escrow_after == DEPOSIT,
            "the escrow released the note's face value",
            escrow_before - escrow_after,
        );

        // The payout is face minus this note's own fees, which is the figure
        // the client quoted — checking against the face would pass for the
        // wrong reason.
        let fee_total = node_fee * interior_participants;
        self.rec.check(
            holder_after - holder_before == DEPOSIT - fee_total,
            "client 2 received face minus this note's fees",
            format!("{} (fees {fee_total})", holder_after - holder_before),
        );

        // Only meaningful if *these* nodes printed the note being redeemed.
        //
        // Node identities are generated per run and held in memory, so on a
        // resumed run `self.nodes` are strangers to this note: they would
        // each accrue zero and report four failures that say nothing about
        // the system. Phase 5 running in this process is exactly the
        // condition for the fees to land on accounts this process knows.
        if self.wants("5") {
            // A node of this run earns one fee if the draw put it in the
            // chain and it is not a volunteer; otherwise nothing.
            let accrued_after = self.accrued_by_node().await?;
            let addresses: Vec<String> = self
                .nodes
                .iter()
                .flat_map(|n| [n.own.address.clone(), n.partner.address.clone()])
                .collect();
            for ((address, before), after) in addresses.iter().zip(&accrued_before).zip(&accrued_after) {
                let paid = terms.iter().any(|(a, volunteer)| a == address && !volunteer);
                let want = if paid { node_fee } else { 0 };
                self.rec.check(
                    after - before == want,
                    &format!("{address} accrued {}", if paid { "one fee" } else { "nothing" }),
                    after - before,
                );
            }
        } else {
            self.rec.note(
                "fee accrual not checked: this note was printed by an earlier run's                  nodes, whose keys are gone. Phase 8 proves accrual and claim together.",
            );
        }
        self.gate()
    }

    // ── phase 7 ─────────────────────────────────────────────────────────

    async fn claim_fees(&mut self) -> Result<(), String> {
        self.rec.phase("Phase 7 — a node claims its fees");
        let mint_id = self.cfg.mint.clone();
        // Whichever of this run's nodes the draw paid.
        let mut pick = None;
        for (i, n) in self.nodes.iter().enumerate() {
            let a = chain::mint(&self.funder, &mint_id)
                .accrued_fees(&n.own.address)
                .await
                .map_err(|e| format!("accrued_fees: {e}"))?;
            if a > 0 {
                pick = Some((i, a));
                break;
            }
        }
        let Some((i, accrued)) = pick else {
            self.rec.note("no node of this run has accrued fees — skipping");
            return self.gate();
        };
        let address = self.nodes[i].own.address.clone();
        let before = chain::balance(&self.funder, USDC_SAC, &address).await?;

        let mut mint =
            kenter_client::MintClient::new(self.nodes[i].own.tx(), &mint_id);
        let paid = mint
            .claim_fees()
            .await
            .map_err(|e| format!("claim_fees: {e}"))?;
        self.rec.check(paid == accrued, "claimed what had accrued", paid);

        let after = chain::balance(&self.funder, USDC_SAC, &address).await?;
        self.rec.check(
            after - before == accrued,
            "the node was paid in USDC",
            after - before,
        );
        let left = chain::mint(&self.funder, &mint_id)
            .accrued_fees(&address)
            .await
            .map_err(|e| format!("accrued_fees: {e}"))?;
        self.rec.check(left == 0, "its claimable balance is drained", left);
        self.gate()
    }

    // ── phase 8 ─────────────────────────────────────────────────────────

    /// Print a note and redeem it **to somebody else**, then let a node
    /// claim what it earned. Entirely automatic.
    ///
    /// Two things only this phase can prove, and neither needs the window:
    ///
    /// **Redeem to an address** is not offered by the GUI, which always
    /// pays the holder's own account. Here the payout
    /// goes to an address that never authorised anything and never held the
    /// note.
    ///
    /// **Claiming fees** is unreachable from any resumed run, because node
    /// identities are generated per run and kept in memory — so the fees a
    /// previous run accrued belong to keys that no longer exist. Minting and
    /// claiming inside one phase is the only way those are the same nodes.
    async fn directed_redeem(&mut self) -> Result<(), String> {
        self.rec.phase("Phase 8 — redeem to an address, and a node claims its fees");
        let mint_id = self.cfg.mint.clone();

        // The depositor does not join the roster: its own end pairs are
        // exempt from the roster check, and joining would lock `min_stake`
        // for nothing.

        // Somebody who never authorised anything and never held the note.
        let payee = Account::generate("payee");
        chain::fund(&payee.address).await?;
        chain::ensure_trustline(&payee, "USDC", USDC_ISSUER).await?;
        self.rec.note(&format!("payee {} funded with a USDC trustline", payee.address));

        // Every selected node is reached through this run's relay. A node of
        // another operator that wins a position and sits behind a different
        // relay cannot be reached this way and is skipped for a runner-up,
        // which this run's nodes are.
        let mut reach = self.reach()?;
        let mut mint = chain::mint(&self.funder, &mint_id);
        let seed_since = chain::latest_ledger().await?;
        let (token, _container) =
            print_through_draw(&mut mint, &mut reach, &self.funder, self.cfg.nodes as u32 + 2).await?;
        self.rec.check(true, "printed a note through the draw", token.ephemeral_address());
        self.check_seed_source(&mint_id, seed_since, token.slot_id).await?;
        let winners = interior_pairs(&token)?;
        let terms = terms_of(&self.funder, &self.cfg.roster, &winners).await?;

        let chain_data = kenter_crypto::chain_data::serialize_token_chain_data(&token)
            .map_err(|e| format!("chain data: {e}"))?;

        let payee_before = chain::balance(&self.funder, USDC_SAC, &payee.address).await?;
        let funder_before = chain::balance(&self.funder, USDC_SAC, &self.funder.address).await?;
        let mint_before = chain::balance(&self.funder, USDC_SAC, &mint_id).await?;
        let node_fee = chain::mint(&self.funder, &mint_id)
            .node_fee()
            .await
            .map_err(|e| format!("node_fee: {e}"))? as i128;
        let since = chain::latest_ledger().await?;

        let paid = mint
            .redeem_by_chain(
                &payee.address,
                token.slot_id,
                chain_data,
                token.sign_claim(
                    &kenter_client::tx::address_xdr(&mint_id)
                        .map_err(|e| format!("contract xdr: {e}"))?,
                    &kenter_client::tx::address_xdr(&payee.address)
                        .map_err(|e| format!("recipient xdr: {e}"))?,
                ),
            )
            .await
            .map_err(|e| format!("redeem_by_chain: {e}"))?;

        let payee_after = chain::balance(&self.funder, USDC_SAC, &payee.address).await?;
        let funder_after = chain::balance(&self.funder, USDC_SAC, &self.funder.address).await?;
        let mint_after = chain::balance(&self.funder, USDC_SAC, &mint_id).await?;
        // One fee per interior participant; the depositor's end pairs pay
        // none. The volunteers are whichever of the winners volunteer.
        let fee_total = node_fee * 2 * winners.len() as i128;
        let volunteer_addresses: Vec<String> =
            terms.iter().filter(|(_, v)| *v).map(|(a, _)| a.clone()).collect();
        let burned_total = node_fee * volunteer_addresses.len() as i128;

        self.rec.check(
            payee_after - payee_before == paid,
            "the payee received the payout",
            payee_after - payee_before,
        );
        self.rec.check(
            paid == SMALL_DEPOSIT - fee_total,
            "which is face minus this note's fees",
            format!("{paid} (fees {fee_total})"),
        );
        // The point of the feature: the escrow went straight past the
        // account that authorised the redemption. Before this it could only
        // reach that account.
        //
        // The baseline is taken after the print, so the deposit has already
        // left — the redeemer's balance should not move *at all* here. An
        // earlier version of this check expected it to drop by the deposit
        // and failed, which was the assertion being wrong rather than the
        // contract.
        self.rec.check(
            funder_after == funder_before,
            "the redeemer received none of the escrow",
            format!("{funder_before} -> {funder_after}"),
        );

        // Volunteers: their fees are burned, so
        // they leave the mint without reaching anyone. The holder is paid
        // the same either way (checked above), and the mint's balance
        // falls by the payout plus the burn.
        self.rec.check(
            mint_before - mint_after == paid + burned_total,
            "the mint's balance fell by the payout plus the volunteers' burn",
            format!("{} = {paid} + {burned_total}", mint_before - mint_after),
        );
        let (burned, locked) = chain::fee_burned_since(&mint_id, since).await?;
        let burned: Vec<_> = burned.into_iter().filter(|b| b.slot_id == token.slot_id).collect();
        let mut want = volunteer_addresses.clone();
        let mut got: Vec<String> = burned.iter().map(|b| b.node.clone()).collect();
        want.sort();
        got.sort();
        self.rec.check(
            got == want && burned.iter().all(|b| b.amount == node_fee),
            "one FEE burned event per volunteer participant, for one fee each",
            format!(
                "{} event(s): {}",
                burned.len(),
                burned
                    .iter()
                    .map(|b| format!("{} {} (tx {})", b.node, b.amount, b.tx_hash))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        );
        self.rec.check(locked == 0, "no FEE locked: the pay token accepted the burn", locked);
        for address in &volunteer_addresses {
            let accrued = chain::mint(&self.funder, &mint_id)
                .accrued_fees(address)
                .await
                .map_err(|e| format!("accrued_fees: {e}"))?;
            // A volunteer of this run accrues nothing ever; another
            // operator's may have converted from paid, so only ours count.
            if self.nodes.iter().any(|n| n.own.address == *address || n.partner.address == *address) {
                self.rec.check(accrued == 0, "a volunteer was credited nothing", format!("{address}: {accrued}"));
            }
        }

        // The fees belong to nodes whose keys this run still holds.
        // The claim needs a paid node of this run that the draw selected.
        let paid_winner = self.nodes.iter().find(|n| {
            winners.iter().any(|(a, _)| *a == n.own.address)
                && !volunteer_addresses.contains(&n.own.address)
        });
        let Some(paid_node) = paid_winner else {
            self.rec.note("no paid node of this run was selected: no fee to claim");
            return self.gate();
        };
        let node = paid_node.own.address.clone();
        let accrued = chain::mint(&self.funder, &mint_id)
            .accrued_fees(&node)
            .await
            .map_err(|e| format!("accrued_fees: {e}"))?;
        self.rec.check(accrued >= node_fee, "a paid node accrued its fee", accrued);

        let before = chain::balance(&self.funder, USDC_SAC, &node).await?;
        let claimed = kenter_client::MintClient::new(paid_node.own.tx(), &mint_id)
            .claim_fees()
            .await
            .map_err(|e| format!("claim_fees: {e}"))?;
        let after = chain::balance(&self.funder, USDC_SAC, &node).await?;

        self.rec.check(claimed == accrued, "claimed what had accrued", claimed);
        self.rec.check(
            after - before == accrued,
            "the node was actually paid in USDC",
            after - before,
        );
        let left = chain::mint(&self.funder, &mint_id)
            .accrued_fees(&node)
            .await
            .map_err(|e| format!("accrued_fees: {e}"))?;
        self.rec.check(left == 0, "its claimable balance is drained", left);

        self.gate()
    }

    // ── skip test ───────────────────────────────────────────────────────

    /// A selected node dies before it serves, and the print goes on without
    /// it (`docs/architecture/node-selection.md`).
    ///
    /// No human is involved: the harness prints through the wallet's own
    /// code (`print_selected`), watches the slot, and kills whichever of its
    /// nodes the draw put at position 1 the moment positions are fixed. The
    /// wallet code then has to wait out the serve timeout, skip that pair,
    /// and finish with the runner-up.
    async fn skip_test(&mut self) -> Result<(), String> {
        self.rec.phase("Skip test — a selected node dies before it serves");
        let mint_id = self.cfg.mint.clone();

        // Every local pair registered with the mint, and a ledger past it:
        // only a pair registered before the request may claim.
        let started = std::time::Instant::now();
        loop {
            let mut mint = chain::mint(&self.funder, &mint_id);
            let mut all = true;
            for n in &self.nodes {
                if mint.pair_of(&n.own.address).await.ok().flatten().is_none() {
                    all = false;
                }
            }
            if all {
                break;
            }
            if started.elapsed() > std::time::Duration::from_secs(180) {
                self.rec.check(false, "every local pair registered", "not within 3 minutes");
                return self.gate();
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
        self.rec.check(true, "every local pair registered", self.nodes.len());
        tokio::time::sleep(std::time::Duration::from_secs(8)).await;

        let node_fee = chain::mint(&self.funder, &mint_id)
            .node_fee()
            .await
            .map_err(|e| format!("node_fee: {e}"))? as i128;
        let slot_id = chain::mint(&self.funder, &mint_id)
            .next_slot_id()
            .await
            .map_err(|e| format!("next_slot_id: {e}"))?;
        let since = chain::latest_ledger().await?;
        let funder_before = chain::balance(&self.funder, USDC_SAC, &self.funder.address).await?;
        self.rec.note(&format!("printing 4 pairs as slot {slot_id}"));

        // The print, through the wallet's own code, and the watcher that
        // kills the node at position 1, side by side.
        let mut reach = self.reach()?;
        // The print holds its own copy of the funder, so the harness can
        // still change itself (kill a node) while the print runs.
        let funder = self.funder.clone();
        let mut mint = chain::mint(&funder, &mint_id);
        let print = print_through_draw(&mut mint, &mut reach, &funder, 4);
        let reader = chain::mint(&funder, &mint_id);
        let watch = async {
            let until = std::time::Instant::now() + std::time::Duration::from_secs(600);
            while std::time::Instant::now() < until {
                let ledger = chain::latest_ledger().await.unwrap_or(0);
                if let Ok(Some(slot)) = reader.get_slot(slot_id).await {
                    if let Some(chain_now) = slot.chain(ledger) {
                        let at_one = chain_now[1].0.clone();
                        let done = slot.completed_links;
                        return Some((at_one, done));
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            }
            None
        };
        // The watcher returns at once when positions are fixed; the kill
        // happens here, between the two futures, so the print keeps
        // running while it does.
        tokio::pin!(print);
        let fixed = tokio::select! {
            r = &mut print => {
                self.rec.check(false, "positions were fixed before the print finished", format!("{:?}", r.as_ref().err()));
                return self.gate();
            }
            w = watch => w,
        };
        let Some((at_one, links_then)) = fixed else {
            self.rec.check(false, "positions were fixed", "not within 10 minutes");
            return self.gate();
        };
        let victim = self.nodes.iter().position(|n| n.own.address == at_one);
        match victim {
            Some(i) if links_then <= 1 => {
                if let Some(d) = self.nodes[i].daemon.as_mut() {
                    d.stop();
                }
                self.nodes[i].daemon = None;
                self.rec.note(&format!("killed node {} ({at_one}), drawn for position 1", i + 1));
            }
            Some(_) => {
                self.rec.check(false, "the node at position 1 was killed before it served", "it served first; rerun");
                return self.gate();
            }
            None => self.rec.note(&format!(
                "position 1 went to another operator's node ({at_one}); the local relay cannot reach it, \
                 so it is skipped the same way"
            )),
        }

        let printed = print.await;
        let (token, _container) = match printed {
            Ok(t) => t,
            Err(e) => {
                self.rec.check(false, "the print completed after the skip", e);
                return self.gate();
            }
        };
        self.rec.check(true, "the print completed after the skip", token.ephemeral_address());
        let state = chain::mint(&self.funder, &mint_id)
            .get_token_state(token.slot_id)
            .await
            .map_err(|e| format!("get_token_state: {e}"))?;
        self.rec.check(
            matches!(state, Some(kenter_client::TokenState::Active)),
            "the note is registered and active",
            format!("{state:?}"),
        );

        let skips: Vec<_> = chain::skips_since(&mint_id, since)
            .await?
            .into_iter()
            .filter(|s| s.slot_id == token.slot_id)
            .collect();
        let first = skips.iter().find(|s| s.position == 1);
        self.rec.check(
            first.is_some_and(|s| s.skipped == at_one),
            "a PRINT skip event replaced the pair at position 1",
            format!("{skips:?}"),
        );
        self.rec.check(
            skips.iter().all(|s| s.fee == 2 * node_fee),
            "each skip cost the depositor one pair's fee",
            format!("{:?}", skips.iter().map(|s| s.fee).collect::<Vec<_>>()),
        );
        let winners = interior_pairs(&token)?;
        self.rec.check(
            winners.iter().all(|(a, b)| *a != at_one && *b != at_one),
            "the skipped pair is not in the note's chain",
            format!("{winners:?}"),
        );
        if let Some(s) = first {
            self.rec.check(
                winners.first().is_some_and(|(a, b)| *a == s.replacement || *b == s.replacement),
                "the runner-up built position 1 instead",
                s.replacement.clone(),
            );
        }
        let funder_after = chain::balance(&self.funder, USDC_SAC, &self.funder.address).await?;
        let want = SMALL_DEPOSIT + 2 * node_fee * skips.len() as i128;
        self.rec.check(
            funder_before - funder_after == want,
            "the depositor paid the deposit plus the skip fees, nothing else",
            format!("{} (expected {want})", funder_before - funder_after),
        );
        self.gate()
    }

    // ── burst ───────────────────────────────────────────────────────────

    /// Several print requests in one ledger (`--burst`).
    ///
    /// A slot's id comes from a shared counter, so requests simulated
    /// against the same counter declare the same keys, and without more
    /// every one applied after the first would trap. The client declares
    /// the next `NEIGHBOUR_SLOTS` ids too and retries once.
    async fn burst_test(&mut self, n: usize) -> Result<(), String> {
        self.rec.phase(&format!("Burst — {n} print requests at once"));
        const AMOUNT: i128 = 100_000; // 0.01 USDC, above one interior pair's fees
        let mint_id = self.cfg.mint.clone();

        let mut depositors = Vec::new();
        for i in 0..n {
            let d = Account::generate(&format!("burst{}", i + 1));
            chain::fund(&d.address).await?;
            chain::ensure_trustline(&d, "USDC", USDC_ISSUER).await?;
            chain::pay(&self.funder, USDC_SAC, &d.address, 2 * AMOUNT).await?;
            depositors.push(d);
        }
        self.rec.check(true, "depositors funded", depositors.len());

        let mut set = tokio::task::JoinSet::new();
        for (i, d) in depositors.iter().enumerate() {
            let d = d.clone();
            let mint_id = mint_id.clone();
            set.spawn(async move {
                let mut mint = kenter_client::MintClient::new(d.tx(), &mint_id);
                let own = (d.address.as_str(), d.address.as_str());
                let r = mint
                    .request_print(rand::random::<[u8; 32]>(), AMOUNT, 3, own, own)
                    .await
                    .map_err(|e| e.to_string());
                (i, r)
            });
        }
        let mut slots = vec![None; n];
        while let Some(joined) = set.join_next().await {
            let (i, r) = joined.map_err(|e| format!("join: {e}"))?;
            match r {
                Ok(slot) => slots[i] = Some(slot),
                Err(e) => self.rec.note(&format!("request {} failed: {e}", i + 1)),
            }
        }
        let got: Vec<u32> = slots.iter().flatten().copied().collect();
        let mut distinct = got.clone();
        distinct.sort();
        distinct.dedup();
        self.rec.check(got.len() == n, "every request landed", format!("{} of {n}", got.len()));
        self.rec.check(distinct.len() == got.len(), "each got its own slot", format!("{distinct:?}"));

        // Which ledgers they landed in: the point is several in one.
        let since = distinct.first().copied();
        if let Some(first) = since {
            let mint = chain::mint(&self.funder, &mint_id);
            let mut created = Vec::new();
            for id in &distinct {
                if let Ok(Some(s)) = mint.get_slot(*id).await {
                    created.push(s.created_at);
                }
            }
            created.sort();
            let mut ledgers = created.clone();
            ledgers.dedup();
            self.rec.note(&format!(
                "slots {first}.. landed in {} ledger(s): {created:?}",
                ledgers.len()
            ));
        }

        // Cancel each before its beacon round is out: no draw yet, so a
        // full refund.
        for (i, d) in depositors.iter().enumerate() {
            let Some(slot) = slots[i] else { continue };
            let mut mint = kenter_client::MintClient::new(d.tx(), &mint_id);
            let refund = match mint.cancel_print(slot).await {
                Ok(r) => Ok(r),
                // Once more: the beacon round may have come out between
                // simulating the cancel and applying it.
                Err(_) => mint.cancel_print(slot).await,
            };
            match refund {
                // A round out by the cancel forfeits one position's fees.
                Ok(r) => self.rec.check(r == AMOUNT || r == AMOUNT / 2, "cancelled and refunded", format!("slot {slot}: {r}")),
                Err(e) => self.rec.check(false, "cancelled and refunded", format!("slot {slot}: {e}")),
            };
        }
        self.gate()
    }

    // ── remote print ────────────────────────────────────────────────────

    /// Print one note of `pairs` pairs across whatever nodes the network
    /// selects, each reached through its own relay, and redeem it to a third
    /// party. Nothing is started here: the nodes are real installs.
    ///
    /// What it proves: the wallet's path, with no node list and no relay
    /// setting. The draw picks the interior, and every fee is checked
    /// against who it picked.
    /// Check how `slot_id` was seeded: from the beacon, or by the mint's
    /// fallback when this run has the beacon turned off
    /// (`KENTER_BEACON_MIRRORS=none`, which the run's own nodes inherit).
    async fn check_seed_source(&mut self, mint_id: &str, since: u32, slot_id: u32) -> Result<(), String> {
        let fallback = chain::fallback_slots_since(mint_id, since).await?.contains(&slot_id);
        let want = beacon_off();
        self.rec.check(
            fallback == want,
            if want {
                "seeded by the mint's fallback: the beacon was off"
            } else {
                "seeded from the beacon, not the fallback"
            },
            format!("slot {slot_id}: PRINT fallback event {}", if fallback { "present" } else { "absent" }),
        );
        Ok(())
    }

    async fn remote_print(&mut self, pairs: u32) -> Result<(), String> {
        self.rec.phase(&format!("Remote print — {pairs} pairs, nodes chosen by the network"));
        let mint_id = self.cfg.mint.clone();

        let payee = Account::generate("payee");
        chain::fund(&payee.address).await?;
        chain::ensure_trustline(&payee, "USDC", USDC_ISSUER).await?;
        self.rec.note(&format!("payee {} funded with a USDC trustline", payee.address));

        let mut mint = chain::mint(&self.funder, &mint_id);
        let node_fee = mint.node_fee().await.map_err(|e| format!("node_fee: {e}"))? as i128;
        let mut reach = kenter_print::Reach::Roster {
            roster: kenter_client::RosterClient::new(self.funder.tx(), &self.cfg.roster),
            relays: kenter_client::network::built().relays.iter().map(|r| r.to_string()).collect(),
        };
        let started = std::time::Instant::now();
        let seed_since = chain::latest_ledger().await?;
        let (token, _container) = print_through_draw(&mut mint, &mut reach, &self.funder, pairs).await?;
        self.rec.check(
            true,
            "printed a note through the draw",
            format!("{} in {:.0}s", token.ephemeral_address(), started.elapsed().as_secs_f64()),
        );
        self.check_seed_source(&mint_id, seed_since, token.slot_id).await?;
        let winners = interior_pairs(&token)?;
        let terms = terms_of(&self.funder, &self.cfg.roster, &winners).await?;
        for (a, b) in &winners {
            self.rec.note(&format!("selected: {a} / {b}"));
        }
        let mut accrued_before = std::collections::HashMap::new();
        for (a, _) in &terms {
            let acc = chain::mint(&self.funder, &mint_id)
                .accrued_fees(a)
                .await
                .map_err(|e| format!("accrued_fees: {e}"))?;
            accrued_before.insert(a.clone(), acc);
        }

        let chain_data = kenter_crypto::chain_data::serialize_token_chain_data(&token)
            .map_err(|e| format!("chain data: {e}"))?;
        let mint_before = chain::balance(&self.funder, USDC_SAC, &mint_id).await?;
        let since = chain::latest_ledger().await?;
        let paid = mint
            .redeem_by_chain(
                &payee.address,
                token.slot_id,
                chain_data,
                token.sign_claim(
                    &kenter_client::tx::address_xdr(&mint_id).map_err(|e| format!("contract xdr: {e}"))?,
                    &kenter_client::tx::address_xdr(&payee.address).map_err(|e| format!("recipient xdr: {e}"))?,
                ),
            )
            .await
            .map_err(|e| format!("redeem_by_chain: {e}"))?;
        let mint_after = chain::balance(&self.funder, USDC_SAC, &mint_id).await?;
        let payee_got = chain::balance(&self.funder, USDC_SAC, &payee.address).await?;

        let fee_total = node_fee * 2 * winners.len() as i128;
        let volunteers = terms.iter().filter(|(_, v)| *v).count() as i128;
        let burned_total = node_fee * volunteers;
        self.rec.check(payee_got == paid, "the payee received the payout", paid);
        self.rec.check(
            paid == SMALL_DEPOSIT - fee_total,
            "which is face minus one fee per interior participant",
            format!("{paid} (fees {fee_total})"),
        );
        self.rec.check(
            mint_before - mint_after == paid + burned_total,
            "the mint's balance fell by the payout plus any volunteers' burn",
            format!("{} = {paid} + {burned_total}", mint_before - mint_after),
        );
        let (burned, locked) = chain::fee_burned_since(&mint_id, since).await?;
        let burned: Vec<_> = burned.into_iter().filter(|b| b.slot_id == token.slot_id).collect();
        self.rec.check(
            burned.len() as i128 == volunteers && locked == 0,
            "one FEE burned event per volunteer participant, none locked",
            format!("{} burned, {locked} locked", burned.len()),
        );
        for (a, volunteer) in &terms {
            let after = chain::mint(&self.funder, &mint_id)
                .accrued_fees(a)
                .await
                .map_err(|e| format!("accrued_fees: {e}"))?;
            let want = if *volunteer { 0 } else { node_fee };
            self.rec.check(
                after - accrued_before[a] == want,
                if *volunteer { "a volunteer was credited nothing" } else { "a paid node was credited one fee" },
                format!("{a}: +{}", after - accrued_before[a]),
            );
        }
        self.gate()
    }

    // ── teardown ────────────────────────────────────────────────────────

    /// Take this run's nodes off the roster.
    ///
    /// Their keys exist only in this process, so a node left joined can
    /// never leave afterwards, and it counts toward the roster's size for
    /// good: every daemon's sortition then expects more claimants than
    /// there are (see the live-pair estimate in
    /// `docs/architecture/node-selection.md`). The stake stays bonded and
    /// is not withdrawn; it is friendbot XLM.
    async fn leave_roster(&mut self) {
        if self.cfg.stay_joined || self.nodes.is_empty() {
            return;
        }
        let mut left = 0;
        for i in 0..self.nodes.len() {
            for which in 0..2 {
                let account = if which == 0 { &self.nodes[i].own } else { &self.nodes[i].partner };
                let mut roster = kenter_client::RosterClient::new(account.tx(), &self.cfg.roster);
                match roster.leave().await {
                    Ok(_) => left += 1,
                    Err(e) => self.rec.note(&format!("{} did not leave the roster: {e}", account.address)),
                }
            }
        }
        self.rec.note(&format!("{left} of this run's node addresses left the roster"));
    }

    fn teardown(&mut self) {
        self.rec.phase("Teardown");
        // Clients first: they hold a relay session, and closing them before
        // the relay means the relay drops the binding cleanly rather than at
        // timeout.
        for (i, client) in self.clients.iter_mut().enumerate() {
            let log = client.log();
            client.stop();
            self.rec.block(&format!("client {} log", i + 1), &log);
        }
        self.clients.clear();
        for i in 0..self.nodes.len() {
            if let Some(mut d) = self.nodes[i].daemon.take() {
                let log = d.log();
                d.stop();
                self.rec.block(&format!("node {} log", i + 1), &log);
            }
        }
        if let Some(mut relay) = self.relay.take() {
            let log = relay.log();
            relay.stop();
            self.rec.block("relay log", &log);
        }
        self.rec.note("processes stopped; accounts left in place for inspection");
    }

    // ── helpers ─────────────────────────────────────────────────────────

    /// The one print this depositor requested since ledger `since`, read
    /// from the mint's events, failing if there is anything but one.
    ///
    /// A registered print deletes its slot, so the slot cannot be read
    /// afterwards; the events are the record. More than one means the
    /// operator did something the phase did not ask for, which is worth
    /// stopping on rather than guessing about.
    async fn print_by(&mut self, depositor: &str, since: u32) -> Result<chain::PrintSeen, String> {
        let mut found: Vec<_> = chain::prints_since(&self.cfg.mint, since)
            .await?
            .into_iter()
            .filter(|p| p.depositor == depositor)
            .collect();
        match found.len() {
            1 => Ok(found.pop().expect("one")),
            0 => Err(format!(
                "no print requested by {depositor} since ledger {since} — did the deposit run?"
            )),
            n => Err(format!("{n} prints by {depositor} — expected exactly one")),
        }
    }

    /// Claimable fees for every node account, in a stable order.
    async fn accrued_by_node(&self) -> Result<Vec<i128>, String> {
        let mut mint = chain::mint(&self.funder, &self.cfg.mint);
        let mut out = Vec::new();
        for node in &self.nodes {
            for address in [&node.own.address, &node.partner.address] {
                out.push(
                    mint.accrued_fees(address)
                        .await
                        .map_err(|e| format!("accrued_fees({address}): {e}"))?,
                );
            }
        }
        Ok(out)
    }
}

/// Print a manual step and wait for whoever is doing it.
///
/// Returns an error only if the step was abandoned — a step file containing
/// `abort`, or an hour with no answer. Both end the run rather than leaving a
/// process holding the relay port forever.
fn pause(step_file: Option<&std::path::Path>, lines: &[&str]) -> Result<(), String> {
    println!();
    for line in lines {
        println!("  >> {line}");
    }
    use std::io::Write as _;

    let Some(path) = step_file else {
        print!("\n  [Enter] when done, or Ctrl-C to stop: ");
        let _ = std::io::stdout().flush();
        let mut buf = String::new();
        let _ = std::io::stdin().read_line(&mut buf);
        return Ok(());
    };

    println!("\n  WAITING — create {} to continue", path.display());
    let _ = std::io::stdout().flush();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3600);
    loop {
        if path.exists() {
            let body = std::fs::read_to_string(path).unwrap_or_default();
            // Remove it first: a file left behind would make the *next* step
            // fall straight through, which is the failure this whole
            // mechanism exists to avoid.
            let _ = std::fs::remove_file(path);
            if body.trim().eq_ignore_ascii_case("abort") {
                return Err("the step was aborted".into());
            }
            println!("  continuing");
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("no answer at {} within an hour", path.display()));
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// The most recently modified file in a directory.
fn newest_file(dir: &std::path::Path) -> Result<std::path::PathBuf, String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut best: Option<(std::time::SystemTime, std::path::PathBuf)> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        if best.as_ref().is_none_or(|(t, _)| modified > *t) {
            best = Some((modified, path));
        }
    }
    best.map(|(_, p)| p)
        .ok_or_else(|| format!("nothing in {}", dir.display()))
}

/// The Stellar address of the first key in a client's vault.
///
/// Read rather than asked for: the address is on screen in the client, but
/// copying a 56-character string by hand is a way to test the operator.
fn read_vault_address(path: &std::path::Path) -> Result<String, String> {
    let vault = SoftVault::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let keys = vault
        .list_keys()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    keys.first()
        .map(|k| k.stellar_address.clone())
        .ok_or_else(|| format!("{} has no account — was first run completed?", path.display()))
}


/// Print one note of `total_pairs` through the draw, as the wallet does.
/// Whether this run has the beacon turned off, so prints must be seeded by
/// the mint's fallback.
fn beacon_off() -> bool {
    std::env::var(kenter_client::beacon::MIRRORS_ENV)
        .is_ok_and(|v| v.trim().eq_ignore_ascii_case("none"))
}

async fn print_through_draw(
    mint: &mut kenter_client::MintClient,
    reach: &mut kenter_print::Reach,
    funder: &Account,
    total_pairs: u32,
) -> Result<(kenter_crypto::token::BearerToken, Vec<u8>), String> {
    let beacon = kenter_client::Beacon::quicknet().map_err(|e| format!("beacon: {e}"))?;
    let order = kenter_print::PrintOrder {
        total_pairs,
        event_id: rand::random(),
        denomination: SMALL_DEPOSIT as u64,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        mode: kenter_client::TokenMode::PureBearer,
        owner_commitment: [0u8; 32],
    };
    kenter_print::print_selected(
        mint,
        reach,
        &beacon,
        &kenter_print::DepositorPairs::testbed(&funder.keypair),
        &order,
        &|line: &str| println!("  {}", line.trim()),
    )
    .await
}

/// The interior pairs a note was built by, read off its own chain: link 0
/// and the last are the depositor's.
fn interior_pairs(token: &kenter_crypto::token::BearerToken) -> Result<Vec<(String, String)>, String> {
    let links = &token.chain.links;
    let g = |k: &[u8; 32]| stellar_strkey::ed25519::PublicKey(*k).to_string().as_str().to_owned();
    Ok(links[1..links.len().saturating_sub(1)]
        .iter()
        .map(|l| (g(&l.node_a_public), g(&l.node_b_public)))
        .collect())
}

/// Every address of `pairs` with its terms: true for a volunteer.
async fn terms_of(
    funder: &Account,
    roster: &str,
    pairs: &[(String, String)],
) -> Result<Vec<(String, bool)>, String> {
    let mut r = kenter_client::RosterClient::new(funder.tx(), roster);
    let mut out = Vec::new();
    for (a, b) in pairs {
        for x in [a, b] {
            let t = r
                .node_terms(x)
                .await
                .map_err(|e| format!("node_terms({x}): {e}"))?
                .ok_or_else(|| format!("{x} is not selectable on the roster"))?;
            out.push((x.clone(), t));
        }
    }
    Ok(out)
}
