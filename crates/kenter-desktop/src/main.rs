//! `kenter` — the desktop reference client, a command-line wallet.
//!
//! It holds notes in a local store, reconciles them against the mint over
//! Soroban RPC, prints notes through the node network (`print-net`), takes
//! delivery of spend-mode payments (`receive`), redeems (`redeem`), and backs
//! up and restores the wallet. `kenter help` lists every command.
//!
//! `print` mints in-process, one machine playing every node role. It is a
//! testbed convenience for exercising the token format offline; real notes
//! come from `print-net`.

use std::path::PathBuf;
use std::process::ExitCode;

use kenter_client::{
    MintClient, SorobanRpcClient, TokenMode, TokenState, TxBuilder, WalletChain,
};
use kenter_crypto::chain_data::serialize_token_chain_data;
use kenter_crypto::container::{
    deserialize_bearer_token, is_symtoken, serialize_bearer_token, verify_bearer_signature,
};
use kenter_crypto::keypair::StellarKeypair;
use kenter_crypto::spend::{authorize_redeem, owner_commitment};
use kenter_crypto::token::{assemble_bearer_token, BearerToken, PartialToken};
use kenter_vault::{mnemonic, DerivingVault, KeyVault, SoftVault};
use kenter_wallet::{
    fmt_stroops, Balance, HeldToken, Store, TokenStatus, TokenWallet, WalletError,
};

use kenter_wallet::FileStore;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str);
    let result = match cmd {
        Some("print") => cmd_print(&args[2..]),
        Some("print-net") => cmd_print_net(&args[2..]),
        Some("inspect") => cmd_inspect(&args[2..]),
        Some("keygen") => cmd_keygen(&args[2..]),
        Some("keys") => cmd_keys(&args[2..]),
        Some("seed") => cmd_seed(&args[2..]),
        Some("receive") => cmd_receive(&args[2..]),
        Some("keycard") => cmd_keycard(&args[2..]),
        Some("import") => cmd_import(&args[2..]),
        Some("held") => cmd_held(&args[2..]),
        Some("forget") => cmd_forget(&args[2..]),
        Some("sync") => cmd_sync(&args[2..]),
        Some("backup") => cmd_backup(&args[2..]),
        Some("redeem") => cmd_redeem(&args[2..]),
        Some("balance") => cmd_balance(&args[2..]),
        Some("register") => cmd_register(&args[2..]),
        Some("spend-demo") => cmd_spend_demo(&args[2..]),
        Some("help") | Some("--help") | Some("-h") | None => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        Some(other) => Err(format!("unknown command: {other:?}\n\n{USAGE}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The build's network with the environment's overrides
/// (`kenter_client::network`). Testnet unless built with `mainnet`.
fn net_default() -> Result<kenter_client::NetworkConfig, String> {
    kenter_client::NetworkConfig::from_env()
}

/// An RPC client for `--rpc` against `--contract`, under the same rules as
/// the GUI: a flag may change the endpoint, never a mainnet build's
/// contracts.
fn cli_rpc(rpc_url: &str, contract: &str) -> Result<SorobanRpcClient, String> {
    let flags = kenter_client::Overrides {
        rpc: Some(rpc_url.to_string()),
        mint: Some(contract.to_string()),
        ..Default::default()
    };
    let cfg = kenter_client::NetworkConfig::resolve(
        kenter_client::network::built(),
        flags.or(kenter_client::Overrides::from_env()),
    )?;
    Ok(cfg.rpc_client())
}

/// Where the wallet keeps its state. Explicit `--wallet` wins, then
/// `KENTER_WALLET_DIR`, then `~/.kenter/wallet`. Unlike the vault (which demands
/// an explicit path because it holds key material), the token store gets a
/// default: it is consulted by almost every command, and in spend mode its
/// contents are inert without the owner key.
fn resolve_wallet_dir(explicit: Option<String>) -> Result<PathBuf, String> {
    if let Some(p) = explicit {
        return Ok(PathBuf::from(p));
    }
    if let Ok(p) = std::env::var("KENTER_WALLET_DIR") {
        if !p.is_empty() {
            return Ok(PathBuf::from(p));
        }
    }
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map_err(|_| {
            "cannot determine home directory - pass --wallet <dir> or set KENTER_WALLET_DIR"
                .to_string()
        })?;
    Ok(PathBuf::from(home).join(".kenter").join("wallet"))
}

/// Where the vault lives when no `--vault` was given.
///
/// The store is encrypted, so every command that touches it needs
/// the seed, and requiring an explicit `--vault` on all of them would be a lot
/// of typing for a path that is the same every time. Same order the GUI uses.
fn resolve_vault_path(explicit: Option<String>) -> Result<PathBuf, String> {
    if let Some(p) = explicit {
        return Ok(PathBuf::from(p));
    }
    if let Ok(p) = std::env::var("KENTER_VAULT") {
        if !p.is_empty() {
            return Ok(PathBuf::from(p));
        }
    }
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map_err(|_| "cannot determine home directory - pass --vault <file>".to_string())?;
    Ok(PathBuf::from(home).join(".kenter").join("vault.json"))
}

/// Open the token store, unlocking it with the seed.
///
/// The store is encrypted (`docs/architecture/custody.md`): a pure-bearer note is
/// redeemable from its bytes alone, so plaintext records are the money sitting
/// readable on disk. That makes a seed mandatory to hold anything at all, and
/// it makes every command that reads the store prompt once. The GUI pays this
/// cost with a session unlock; a CLI process has no session to amortise it
/// over.
fn open_store(dir: &std::path::Path, vault_path: Option<String>) -> Result<FileStore, String> {
    let vault_path = resolve_vault_path(vault_path)?;
    let vault = SoftVault::open(&vault_path).map_err(|e| e.to_string())?;
    if !vault.has_seed() {
        return Err(format!(
            "{} holds no seed - the token store is encrypted under it.\n  \
             Create one with: kenter seed generate --vault {}",
            vault_path.display(),
            vault_path.display()
        ));
    }
    let pass = read_passphrase("vault passphrase: ")?;
    let creds = vault
        .store_credentials(pass.as_bytes())
        .map_err(|e| e.to_string())?;
    FileStore::open(dir, creds).map_err(|e| e.to_string())
}

/// A Stellar secret, from the environment or a file -- never the command
/// line. A command line is visible to every other process on the machine,
/// lands in shell history, and is echoed by most CI runners; a funded key
/// must not travel that way. `kenter-node` reads `KENTER_NODE_SECRET` the
/// same way.
///
/// `what` names the key for the error message, e.g. "the depositor".
fn resolve_secret(file: Option<String>, env_key: &str, what: &str) -> Result<String, String> {
    resolve_optional_secret(file, env_key)?.ok_or_else(|| {
        format!("no secret for {what}: set {env_key}, or pass --secret-file <path>")
    })
}

/// Like [`resolve_secret`], for a key the command can do without.
fn resolve_optional_secret(file: Option<String>, env_key: &str) -> Result<Option<String>, String> {
    if let Ok(v) = std::env::var(env_key) {
        let v = v.trim().to_string();
        if !v.is_empty() {
            return Ok(Some(v));
        }
    }
    let Some(path) = file else { return Ok(None) };
    let v = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
    let v = v.trim().to_string();
    if v.is_empty() {
        return Err(format!("{path} is empty"));
    }
    Ok(Some(v))
}

/// Refuse any secret-bearing flag before anything else runs, network lookups
/// included, so the refusal does not depend on how the build is configured.
/// Each entry is (flag, environment variable, file flag).
fn refuse_argv_secrets(args: &[String], flags: &[(&str, &str, &str)]) -> Result<(), String> {
    for a in args {
        if let Some((flag, env_key, file_flag)) = flags.iter().find(|(f, _, _)| a == f) {
            return Err(argv_secret_refused(flag, env_key, file_flag));
        }
    }
    Ok(())
}

/// The refusal for a secret given on the command line.
fn argv_secret_refused(flag: &str, env_key: &str, file_flag: &str) -> String {
    format!(
        "{flag} is not accepted: a secret on the command line is visible to every process on this machine and kept in shell history. Set {env_key}=..., or pass {file_flag} <path>."
    )
}

/// Parse a `--wallet <dir>` flag plus any positional arguments.
fn parse_wallet_args(args: &[String]) -> Result<(PathBuf, Vec<String>), String> {
    let mut wallet_dir: Option<String> = None;
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--wallet" => wallet_dir = Some(parse_next(args, &mut i, "--wallet")?),
            other if other.starts_with("--") => {
                return Err(format!("unexpected argument: {other:?}"));
            }
            _ => rest.push(args[i].clone()),
        }
        i += 1;
    }
    Ok((resolve_wallet_dir(wallet_dir)?, rest))
}

/// `import` - verify token files offline and persist them into the wallet.
///
/// Goes through the wallet core so an imported token gets exactly the checks any
/// shell applies (container parse + chain integrity + duplicate detection). The
/// chain reader it is built with is never contacted - importing is offline - but
/// `TokenWallet` owns the verification path and reusing it beats re-implementing
/// it here.
fn cmd_import(args: &[String]) -> Result<(), String> {
    let (dir, files) = parse_wallet_args(args)?;
    if files.is_empty() {
        return Err("import requires at least one <file.symtoken>".into());
    }
    let now = unix_now();

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
    rt.block_on(async move {
        let store = open_store(&dir, None)?;
        let net = net_default()?;
        let rpc = net.rpc_client();
        let mint = MintClient::new(
            TxBuilder::new(rpc, StellarKeypair::random()),
            &net.mint,
        );
        let mut wallet = TokenWallet::new(WalletChain::new(mint), store);

        let mut imported = 0usize;
        let mut failed = 0usize;
        for path in &files {
            let bytes = match std::fs::read(path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("error {path}: {e}");
                    failed += 1;
                    continue;
                }
            };
            match wallet.import(bytes, now).await {
                Ok(h) => {
                    println!("imported {}  {}", short(&h.id), fmt_stroops(h.amount));
                    imported += 1;
                }
                Err(WalletError::Duplicate(id)) => {
                    println!("skip     {} (already held)", short(&id));
                }
                Err(e) => {
                    eprintln!("error {path}: {e}");
                    failed += 1;
                }
            }
        }
        let total = wallet.held().await.map_err(|e| e.to_string())?.len();
        println!();
        println!("wallet: {}", dir.display());
        println!("  imported {imported}, {total} held total");
        if failed > 0 {
            return Err(format!("{failed} file(s) failed"));
        }
        Ok::<(), String>(())
    })
}

/// `held` - list the tokens in the wallet. Offline: no chain read, so these are
/// face values and say nothing about whether a token is still unredeemed.
fn cmd_held(args: &[String]) -> Result<(), String> {
    let (dir, rest) = parse_wallet_args(args)?;
    if !rest.is_empty() {
        return Err(format!("unexpected argument: {:?}", rest[0]));
    }
    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
    rt.block_on(async move {
        let store = open_store(&dir, None)?;
        let held = store.all().await.map_err(|e| e.to_string())?;
        println!("wallet: {}", dir.display());
        if held.is_empty() {
            println!("  (no tokens held - `kenter import <file.symtoken>`)");
            return Ok::<(), String>(());
        }
        println!("  {} token(s)", held.len());
        println!();
        println!("{:<14}  {:>18}  {}", "token", "face amount", "imported (unix)");
        let mut total = 0u64;
        for t in &held {
            total = total.saturating_add(t.amount);
            println!(
                "{:<14}  {:>18}  {}",
                short(&t.id),
                fmt_stroops(t.amount),
                t.imported_at
            );
        }
        println!();
        println!("  total face value: {}", fmt_stroops(total));
        println!("  (run `kenter balance` to reconcile against the ledger)");
        Ok(())
    })
}

/// Resolve a token id, or any unambiguous prefix of one, against the wallet.
///
/// Ids are 56-character addresses and `held` prints them abbreviated, so
/// requiring the full string would make every command a copy-paste exercise.
async fn find_held(store: &FileStore, needle: &str) -> Result<HeldToken, String> {
    let all = store.all().await.map_err(|e| e.to_string())?;
    // An exact id wins outright: `G…-1` is also a prefix of `G…-12`.
    if let Some(t) = all.iter().find(|t| t.id == needle) {
        return Ok(t.clone());
    }
    let mut hits: Vec<HeldToken> = all.into_iter().filter(|t| t.id.starts_with(needle)).collect();
    match hits.len() {
        0 => Err(format!("no held token matching {needle:?} (see `kenter held`)")),
        1 => Ok(hits.remove(0)),
        n => Err(format!("{n} held tokens match {needle:?} - use a longer prefix")),
    }
}

/// `forget` - drop a token record from the wallet.
///
/// Local only: this deletes the stored bytes, it does not touch the ledger. If
/// the token is unredeemed and not backed up elsewhere, the value goes with it -
/// a bearer token cannot be reissued.
/// `forget` - drop a note from the store.
///
/// This deletes the only copy of a bearer instrument. There is no
/// undo and no recovery from the ledger: a note cannot be found from
/// chain data, which is why backups exist.
///
/// So it always asks, and `--yes` is the only way past. It reports
/// whether any mint has confirmed the note, because that is the
/// difference between deleting a receipt and deleting money -- but it
/// does not decide for the holder on that basis. A `Redeemed` marker
/// holds a ledger number and nothing about which note was paid, so on
/// an unbound note it is no evidence at all, and asking
/// every time is the cheaper side to be wrong on.
fn cmd_forget(args: &[String]) -> Result<(), String> {
    let (dir, rest) = parse_wallet_args(args)?;
    let id = rest.first().ok_or("forget requires a <token-id>")?.clone();
    let force = rest.iter().any(|a| a == "--yes");
    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
    rt.block_on(async move {
        let mut store = open_store(&dir, None)?;
        let t = find_held(&store, &id).await?;

        if !force {
            eprintln!(
                "forget {}  {}",
                short(&t.id),
                fmt_stroops(t.amount)
            );
            match &t.mint {
                Some(m) => eprintln!("  confirmed by mint {}", short(m)),
                None => eprintln!(
                    "  no mint has confirmed these bytes, so nothing here \
                     knows whether the note is still live"
                ),
            }
            eprintln!(
                "  this deletes the only copy. It cannot be recovered from \
                 the ledger."
            );
            eprint!("  type the amount in stroops to confirm: ");
            use std::io::Write;
            std::io::stderr().flush().ok();
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .map_err(|e| format!("reading confirmation: {e}"))?;
            if line.trim() != t.amount.to_string() {
                return Err("not confirmed; nothing was deleted".to_string());
            }
        }

        store.remove(&t.id).await.map_err(|e| e.to_string())?;
        println!("forgot {}  {}", short(&t.id), fmt_stroops(t.amount));
        println!("  the bytes are deleted locally; the ledger is unchanged.");
        Ok(())
    })
}

/// `backup` - export and restore the token blobs.
///
/// The half of recovery a recovery phrase does not cover. The phrase restores
/// your OWNER KEYS; it cannot restore the tokens, because they cannot be found
/// from the ledger (`docs/architecture/custody.md`). Without the blobs there is nothing to
/// redeem, so this has to be run after every receive, not once.
///
/// The file is sealed under a key derived from the wallet seed, so restoring
/// needs the phrase and the file and nothing else - not the vault file, which
/// is precisely the thing a backup has to survive the loss of.
fn cmd_backup(args: &[String]) -> Result<(), String> {
    use kenter_wallet::backup;

    let sub = args.first().map(String::as_str);
    let mut wallet_dir: Option<String> = None;
    let mut vault_path: Option<String> = None;
    let mut file: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--wallet" => wallet_dir = Some(parse_next(args, &mut i, "--wallet")?),
            "--vault" => vault_path = Some(parse_next(args, &mut i, "--vault")?),
            "--file" => file = Some(parse_next(args, &mut i, "--file")?),
            other if other.starts_with("--") => {
                return Err(format!("unexpected argument: {other:?}"))
            }
            _ => file = Some(args[i].clone()),
        }
        i += 1;
    }

    // `inspect` reads only the header, so it needs neither wallet nor vault.
    if sub == Some("inspect") {
        let path = file.ok_or("backup inspect requires a <file>")?;
        let bytes = std::fs::read(&path).map_err(|e| format!("reading {path}: {e}"))?;
        let header = backup::inspect(&bytes).map_err(|e| e.to_string())?;
        println!("{path}");
        println!("  wallet      : {}", header.seed_fingerprint);
        println!("  tokens      : {}", header.token_count);
        println!("  created at  : {} (unix)", header.created_at);
        println!("  version     : {}", header.version);
        // What a restorer will have to be given. For a BIP85 child this is
        // the whole point of the header: the index is not recoverable from
        // anywhere else, and without it the phrase alone will not open the
        // file.
        println!("  seed        : {:?}", header.origin());
        if let Some(d) = &header.bip85 {
            println!(
                "  derivation  : m/83696968'/39'/0'/{}'/{}'",
                d.words, d.index
            );
            match &d.root_fingerprint {
                Some(fp) => println!("  root        : {fp}"),
                None => println!("  root        : not recorded — try each root you hold"),
            }
        }
        if let Some(digest) = &header.content_digest {
            println!("  contents    : {digest}");
        }
        println!();
        println!("  the token bytes are sealed; only the phrase that made this");
        println!("  wallet can open them.");
        return Ok(());
    }

    let dir = resolve_wallet_dir(wallet_dir)?;
    let vault_path = vault_path.ok_or("--vault <file> is required (the seed seals the backup)")?;
    let vault = SoftVault::open(&vault_path).map_err(|e| e.to_string())?;
    if !vault.has_seed() {
        return Err(format!("{vault_path} holds no seed — nothing to seal a backup with"));
    }
    let pass = read_passphrase("vault passphrase: ")?;
    let creds = vault
        .backup_credentials(pass.as_bytes())
        .map_err(|e| e.to_string())?;
    // The store is sealed under the same vault the backup is: opening it from
    // anywhere else could pair one wallet's tokens with another's seal.
    let store_creds = vault
        .store_credentials(pass.as_bytes())
        .map_err(|e| e.to_string())?;
    drop(pass);

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
    rt.block_on(async move {
        let mut store = FileStore::open(&dir, store_creds).map_err(|e| e.to_string())?;

        match sub {
            Some("export") => {
                let path = file.ok_or("backup export requires a <file>")?;
                let tokens = store.all().await.map_err(|e| e.to_string())?;
                let pending = store.pending().await.map_err(|e| e.to_string())?;
                // This CLI only ever makes software-seeded wallets, so the
                // origin is not a guess. A card-rooted wallet exported from
                // here would be unopenable later, which is why `SeedSource`
                // has to be passed rather than defaulted.
                let seed = backup::SeedSource::software(&creds.fingerprint);
                // The library's export: it reads the owner-index counter
                // without advancing it.
                let bytes = backup::export(&mut store, &creds.key, &seed, unix_now())
                    .await
                    .map_err(|e| e.to_string())?;
                std::fs::write(&path, &bytes).map_err(|e| format!("writing {path}: {e}"))?;

                println!("backed up {} token(s) -> {path}", tokens.len());
                println!("  wallet  : {}", creds.fingerprint);
                println!("  pending : {}", pending.len());
                println!("  size    : {} bytes", bytes.len());
                println!();
                println!("  This file is bearer value. It is encrypted, but anyone with");
                println!("  your recovery phrase AND this file has your tokens.");
                println!("  Re-export after every receive: a backup taken before a payment");
                println!("  does not contain it, and a token cannot be recovered any other");
                println!("  way.");
                Ok::<(), String>(())
            }
            Some("restore") => {
                let path = file.ok_or("backup restore requires a <file>")?;
                let bytes = std::fs::read(&path).map_err(|e| format!("reading {path}: {e}"))?;
                let contents = backup::decode(&creds.key, &creds.fingerprint, &bytes)
                    .map_err(|e| e.to_string())?;

                // The library's restore: under the wallet lock, `backup::check`
                // on each note, merge rather than replace, and the counter only
                // moves forward.
                let report = backup::restore(&mut store, &contents)
                    .await
                    .map_err(|e| e.to_string())?;

                println!("restored {} token(s) from {path}", report.tokens_added);
                if report.tokens_kept > 0 {
                    println!("  {} already held (kept the wallet's copy)", report.tokens_kept);
                }
                for (id, why) in &report.rejected {
                    println!("  refused {}: {why}", short(id));
                }
                println!("  wallet : {}", creds.fingerprint);
                println!();
                println!("  Run `kenter sync` to reconcile ownership against the ledger.");
                Ok(())
            }
            _ => Err(
                "usage: kenter backup <export <file> | restore <file> | inspect <file>> \
                 --vault <file> [--wallet <dir>]"
                    .into(),
            ),
        }
    })
}

/// `sync` - reconcile ownership against the ledger and repair the wallet's view.
///
/// Two repairs: bind a token whose receive crashed
/// before it was recorded, and flag a token that has been paid away. The second
/// matters for honesty - a token you paid someone is still Active on the ledger,
/// so until it is flagged your own balance still counts it as spendable.
///
/// Needs no vault: the owner commitment is stored on the token at bind time.
fn cmd_sync(args: &[String]) -> Result<(), String> {
    let mut wallet_dir: Option<String> = None;
    let mut rpc_url = net_default()?.rpc;
    let mut contract = net_default()?.mint;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--wallet" => wallet_dir = Some(parse_next(args, &mut i, "--wallet")?),
            "--rpc" => rpc_url = parse_next(args, &mut i, "--rpc")?,
            "--contract" => contract = parse_next(args, &mut i, "--contract")?,
            other => return Err(format!("unexpected argument: {other:?}")),
        }
        i += 1;
    }
    let dir = resolve_wallet_dir(wallet_dir)?;

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
    rt.block_on(async move {
        let store = open_store(&dir, None)?;
        let rpc = cli_rpc(&rpc_url, &contract)?;
        let mint = MintClient::new(TxBuilder::new(rpc, StellarKeypair::random()), &contract);
        let mut wallet = TokenWallet::new(WalletChain::new(mint), store);

        println!("wallet: {}", dir.display());
        let report = wallet.sync().await.map_err(|e| e.to_string())?;
        if report.is_empty() {
            println!("  up to date");
            return Ok::<(), String>(());
        }
        for (id, index) in &report.bound {
            println!("  bound    {}  -> owner index {index}", short(id));
        }
        for id in &report.spent_away {
            println!("  spent    {}  (paid away; no longer yours)", short(id));
        }
        Ok(())
    })
}

/// `balance` - reconcile every held token against the mint contract.
///
/// Kenter has no balance query: a balance is the sum of the bearer tokens you
/// hold, partitioned by each one's on-chain status. Reads the persistent wallet
/// store (see `import`), so it reports what you actually hold rather than
/// whichever files happened to be on the command line.
fn cmd_balance(args: &[String]) -> Result<(), String> {
    let mut wallet_dir: Option<String> = None;
    let mut rpc_url = net_default()?.rpc;
    let mut contract = net_default()?.mint;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--wallet" => wallet_dir = Some(parse_next(args, &mut i, "--wallet")?),
            "--rpc" => rpc_url = parse_next(args, &mut i, "--rpc")?,
            "--contract" => contract = parse_next(args, &mut i, "--contract")?,
            other => return Err(format!("unexpected argument: {other:?}")),
        }
        i += 1;
    }
    let dir = resolve_wallet_dir(wallet_dir)?;

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
    rt.block_on(async move {
        let store = open_store(&dir, None)?;
        let rpc = cli_rpc(&rpc_url, &contract)?;
        // Reads (getLedgerEntries) don't use the source account; a throwaway key
        // satisfies the TxBuilder.
        let mint = MintClient::new(TxBuilder::new(rpc, StellarKeypair::random()), &contract);
        let mut wallet = TokenWallet::new(WalletChain::new(mint), store);

        let held = wallet.held().await.map_err(|e| e.to_string())?;
        println!("wallet: {}", dir.display());
        if held.is_empty() {
            println!("  (no tokens held - `kenter import <file.symtoken>`)");
            return Ok::<(), String>(());
        }

        println!("reconciling {} token(s) against {rpc_url}", held.len());
        println!("  contract {contract}");
        println!();
        let reconciled = wallet.reconcile().await.map_err(|e| e.to_string())?;

        println!("{:<14}  {:>18}  {}", "token", "amount", "status");
        for r in &reconciled {
            println!(
                "{:<14}  {:>18}  {}",
                short(&r.held.id),
                fmt_stroops(r.held.amount),
                status_str(r.status),
            );
        }

        let b = Balance::from_reconciled(&reconciled);
        println!();
        println!("  spendable : {}", fmt_stroops(b.spendable));
        println!("  redeemed  : {}", fmt_stroops(b.redeemed));
        println!("  unverified: {}", fmt_stroops(b.unverified));
        if b.spent_away > 0 {
            println!("  spent away: {}  (paid to someone else)", fmt_stroops(b.spent_away));
        }
        println!("  --------------------------");
        println!("  total held: {}", fmt_stroops(b.total_held));
        Ok(())
    })
}

/// `redeem` - redeem a held token to the ledger via Path B.
///
/// Drives `redeem_by_chain` / `redeem_by_chain_owned`: the holder presents the
/// token's committed chain bytes, plus (in spend mode) the current owner's
/// signature. No shard secrets, no node network: reconstructing the ephemeral
/// key would need either the shards (which a networked print never hands the
/// holder) or a live combiner, and this path needs neither.
///
/// The price of node-freedom is publicity: Path B writes the whole construction
/// chain on-chain, permanently linking the token to its construction nodes.
/// `redeem_by_key` (one signature, reveals nothing) becomes available once a
/// combiner driver exists.
///
/// The redeemed record is kept in the wallet, not deleted - `balance` then shows
/// it under `redeemed`, which is the honest picture. Use `forget` to drop it.
fn cmd_redeem(args: &[String]) -> Result<(), String> {
    refuse_argv_secrets(
        args,
        &[
            ("--secret", "KENTER_REDEEM_SECRET", "--secret-file"),
            ("--owner-secret", "KENTER_OWNER_SECRET", "--owner-secret-file"),
        ],
    )?;
    let mut wallet_dir: Option<String> = None;
    let mut secret_file: Option<String> = None;
    let mut owner_secret_file: Option<String> = None;
    let mut vault_path: Option<String> = None;
    let mut rpc_url = net_default()?.rpc;
    let mut contract = net_default()?.mint;
    let mut needle: Option<String> = None;
    // Where the escrow goes. Defaults to the redeemer; naming someone
    // else pays them directly, in one transaction.
    let mut to: Option<String> = None;
    // Price the redemption instead of making it. The contract still
    // runs -- against the live ledger, through `simulateTransaction` --
    // so a note that could not be redeemed fails here too; only the
    // submission is skipped, and the note stays live.
    let mut dry_run = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dry-run" => dry_run = true,
            "--wallet" => wallet_dir = Some(parse_next(args, &mut i, "--wallet")?),
            "--secret" => {
                return Err(argv_secret_refused("--secret", "KENTER_REDEEM_SECRET", "--secret-file"))
            }
            "--secret-file" => secret_file = Some(parse_next(args, &mut i, "--secret-file")?),
            "--owner-secret" => {
                return Err(argv_secret_refused(
                    "--owner-secret",
                    "KENTER_OWNER_SECRET",
                    "--owner-secret-file",
                ))
            }
            "--owner-secret-file" => {
                owner_secret_file = Some(parse_next(args, &mut i, "--owner-secret-file")?)
            }
            "--to" => to = Some(parse_next(args, &mut i, "--to")?),
            "--vault" => vault_path = Some(parse_next(args, &mut i, "--vault")?),
            "--rpc" => rpc_url = parse_next(args, &mut i, "--rpc")?,
            "--contract" => contract = parse_next(args, &mut i, "--contract")?,
            other if other.starts_with("--") => {
                return Err(format!("unexpected argument: {other:?}"));
            }
            _ => needle = Some(args[i].clone()),
        }
        i += 1;
    }
    let dir = resolve_wallet_dir(wallet_dir)?;
    let needle = needle.ok_or("redeem requires a <token-id> (or a unique prefix)")?;
    let secret = resolve_secret(secret_file, "KENTER_REDEEM_SECRET", "the payout recipient")?;
    let owner_secret = resolve_optional_secret(owner_secret_file, "KENTER_OWNER_SECRET")?;
    let holder_kp =
        StellarKeypair::from_stellar_secret(&secret).map_err(|e| format!("bad payout secret: {e}"))?;
    let owner_kp = match owner_secret {
        Some(s) => Some(
            StellarKeypair::from_stellar_secret(&s)
                .map_err(|e| format!("bad owner secret: {e}"))?,
        ),
        None => None,
    };

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
    rt.block_on(async move {
        let store = open_store(&dir, vault_path.clone())?;
        let held = find_held(&store, &needle).await?;

        // G1 - structural verification, offline, before anything touches the network.
        let token = held.to_bearer().map_err(|e| format!("stored bytes unusable: {e}"))?;
        token
            .verify_chain_integrity()
            .map_err(|e| format!("token failed offline verification: {e}"))?;

        let ek = token.ephemeral_public_key;
        let chain_data =
            serialize_token_chain_data(&token).map_err(|e| format!("chain_data: {e}"))?;

        let holder_addr = holder_kp.stellar_address();
        let recipient = to.clone().unwrap_or_else(|| holder_addr.clone());
        let recipient_xdr = kenter_client::tx::address_xdr(&recipient)
            .map_err(|e| format!("--to {recipient}: {e}"))?;
        let mut mint = MintClient::new(
            TxBuilder::new(
                cli_rpc(&rpc_url, &contract)?,
                holder_kp.clone(),
            ),
            &contract,
        );

        // G2 - the ledger must agree this token exists, is unredeemed, and is worth
        // what the bytes claim.
        let info = mint
            .get_token(token.slot_id)
            .await
            .map_err(|e| format!("get_token: {e}"))?
            .ok_or_else(|| {
                format!(
                    "{} is not registered on this contract - nothing to redeem",
                    short(&held.id)
                )
            })?;
        match info.state {
            TokenState::Active => {}
            TokenState::Redeemed => {
                return Err(format!("{} was already redeemed", short(&held.id)))
            }
            other => return Err(format!("{} is {other:?}, not Active", short(&held.id))),
        }

        println!("redeem {}", short(&held.id));
        println!("  value address : {}", token.ephemeral_address());
        println!(
            "  on-chain      : active, {}",
            fmt_stroops(info.amount.max(0) as u64)
        );
        if info.amount != held.amount as i128 {
            println!(
                "  ! face value {} differs from the on-chain amount - trusting the ledger",
                fmt_stroops(held.amount)
            );
        }
        println!(
            "  chain data    : {} bytes ({} pairs)",
            chain_data.len(),
            token.chain.total_pairs
        );
        println!("  payout to     : {recipient}");

        // Every owner and claim digest covers the mint's own address, so a
        // signature cannot be replayed against another deployment holding
        // the same escrow.
        let contract_xdr = kenter_client::tx::address_xdr(&contract)
            .map_err(|e| format!("contract xdr: {e}"))?;

        let payout = match info.mode {
            TokenMode::PureBearer => {
                if owner_kp.is_some() {
                    return Err(
                        "an owner key was given but this token is pure bearer (no owner check)".into(),
                    );
                }
                println!("  path          : redeem_by_chain (pure bearer, node-free)\n");
                // The chain alone is not the proof: sign the
                // recipient with the note's claim key, so a transaction
                // carrying this chain -- including one that fails and
                // leaves the note live -- is useless to anyone else.
                let claim_sig = token.sign_claim(&contract_xdr, &recipient_xdr);
                if dry_run {
                    let r = mint
                        .simulate_redeem_by_chain(
                            &recipient,
                            token.slot_id,
                            chain_data,
                            claim_sig,
                        )
                        .await
                        .map_err(|e| format!("simulate redeem_by_chain: {e}"))?;
                    report_sim("redeem_by_chain", token.chain.total_pairs, &r);
                    return Ok(());
                }
                mint.redeem_by_chain(&recipient, token.slot_id, chain_data, claim_sig)
                    .await
                    .map_err(|e| format!("redeem_by_chain: {e}"))?
            }
            TokenMode::Spend => {
                // Normal path: the wallet recorded which derived key owns this
                // token at receive, so the owner key never leaves the vault.
                // An owner key file remains for a key held outside the wallet.
                let proof = match (held.owner_index, &vault_path, owner_kp) {
                    (_, _, Some(owner)) => {
                        // Fail here rather than on-chain: a mismatch means this
                        // key is not the current owner (e.g. already paid away).
                        let mine = owner_commitment(&owner.raw_public());
                        if mine != info.owner_commitment {
                            return Err(format!(
                                "the given owner key does not own this token (live owner {}, yours {})",
                                short_hex(&info.owner_commitment),
                                short_hex(&mine)
                            ));
                        }
                        println!("  owner         : {} (raw key)", short_hex(&mine));
                        authorize_redeem(
                            &owner,
                            &contract_xdr,
                            token.slot_id,
                            &ek,
                            &info.owner_commitment,
                            info.spend_nonce,
                            &recipient_xdr,
                        )
                    }
                    (Some(index), Some(vp), None) => {
                        let mut vault = SoftVault::open(vp).map_err(|e| e.to_string())?;
                        if !vault.has_seed() {
                            return Err(format!("{vp} holds no seed"));
                        }
                        let pass = read_passphrase("vault passphrase: ")?;
                        let proof = kenter_wallet::owner::authorize_redeem(
                            &mut vault,
                            index,
                            &contract_xdr,
                            token.slot_id,
                            &ek,
                            &info.owner_commitment,
                            info.spend_nonce,
                            &recipient_xdr,
                            pass.as_bytes(),
                        )
                        .map_err(|e| e.to_string())?;
                        println!(
                            "  owner         : {} (derived, index {index})",
                            short_hex(&info.owner_commitment)
                        );
                        proof
                    }
                    (Some(_), None, None) => {
                        return Err(
                            "this token is owned by a key derived from your wallet seed - pass \
                             --vault <file> so it can be signed, or --owner-secret-file <path> for a \
                             key held elsewhere"
                                .into(),
                        )
                    }
                    (None, _, None) => {
                        return Err(
                            "this token is in spend mode but the wallet has no owner index for \
                             it, so it cannot derive the key - pass --owner-secret-file <path>"
                                .into(),
                        )
                    }
                };
                println!("  path          : redeem_by_chain_owned (spend mode, node-free)\n");
                if dry_run {
                    let r = mint
                        .simulate_redeem_by_chain_owned(
                            &recipient,
                            token.slot_id,
                            chain_data,
                            proof.owner_pubkey,
                            proof.signature,
                        )
                        .await
                        .map_err(|e| format!("simulate redeem_by_chain_owned: {e}"))?;
                    report_sim("redeem_by_chain_owned", token.chain.total_pairs, &r);
                    return Ok(());
                }
                mint.redeem_by_chain_owned(
                    &recipient,
                    token.slot_id,
                    chain_data,
                    proof.owner_pubkey,
                    proof.signature,
                )
                .await
                .map_err(|e| format!("redeem_by_chain_owned: {e}"))?
            }
        };

        let fees = (info.amount - payout).max(0);
        println!("✓ redeemed → {} paid to {recipient}", fmt_stroops(payout.max(0) as u64));
        println!("  node fees accrued: {}", fmt_stroops(fees as u64));
        println!();
        println!("  the record is kept locally and will now show as `redeemed` in");
        println!("  `kenter balance`. Use `kenter forget {}` to drop it.", short(&held.id));
        Ok::<(), String>(())
    })
}

/// Why the two in-process testbed commands below refuse to run.
///
/// Both name one funded key as both halves of every pair. The mint
/// exempts the depositor's two end pairs, but every interior pair must
/// still be two distinct roster nodes — and a solo print has no node in
/// it — so `request_print` would reject them with `NodesNotDistinct (31)`,
/// an error that reads as a bad argument rather than as "this way of
/// printing is not supported".
///
/// They carry no on-chain sequencing: a reader finding plausible
/// sequencing behind a dead entry point learns the wrong thing about
/// what works. Refusing here costs the operator nothing — the escrow
/// moves at `request_print`, which is the call that would fail.
fn solo_print_is_closed(pairs: &str, instead: &str) -> String {
    format!(
        "this command printed in process, naming one funded key as both \
         nodes of {pairs}. Every print needs at least one interior pair of \
         two distinct roster nodes, so it cannot escrow at all.\n\n{instead}"
    )
}

/// `register` — **removed.** It put an existing `.symtoken` on-chain with
/// the caller as the sole node, which the mint does not accept.
fn cmd_register(_args: &[String]) -> Result<(), String> {
    Err(solo_print_is_closed(
        "every pair",
        "Use `kenter print-net`, which walks the chain around live node \
         daemons over the tunnel and registers the note itself.",
    ))
}

/// Print what the network says a redemption would cost.
///
/// `instructions` against the per-transaction CPU limit is the figure
/// that decides how many pairs a note can carry, and it is the only
/// authoritative one. The contract test suite meters a different host
/// and reads about a third lower -- 9.88M against 13.05M at 3 pairs --
/// so a green budget assertion there is a regression tripwire, not a
/// promise that the redemption fits.
fn report_sim(path: &str, pairs: u16, r: &kenter_client::tx::SimResources) {
    // `tx_max_instructions` from the network's `contract_compute_v0`
    // config entry: 400,000,000 on both testnet and mainnet at the time
    // of writing. It is set by validator vote and can move, so a
    // percentage here is indicative; the instruction count above it is
    // the figure to compare against a freshly fetched limit.
    const TX_MAX_INSTRUCTIONS: u64 = 400_000_000;
    let pct = (r.instructions as f64 / TX_MAX_INSTRUCTIONS as f64) * 100.0;
    println!("dry run - nothing was submitted, the note is still live");
    println!("  path          : {path} at {pairs} pairs");
    println!(
        "  instructions  : {} ({pct:.1}% of the {}M limit)",
        r.instructions,
        TX_MAX_INSTRUCTIONS / 1_000_000
    );
    println!("  disk read     : {} bytes", r.disk_read_bytes);
    println!("  write         : {} bytes", r.write_bytes);
    println!(
        "  footprint     : {} read-only, {} read-write",
        r.read_only_entries, r.read_write_entries
    );
    println!("  resource fee  : {} stroops", r.min_resource_fee);
}

/// Abbreviate a long id (Stellar address) for display.
fn short(id: &str) -> String {
    kenter_wallet::short_note_id(id)
}

fn status_str(s: TokenStatus) -> &'static str {
    match s {
        TokenStatus::Active => "active (spendable)",
        TokenStatus::Redeemed => "redeemed",
        TokenStatus::NotFound => "not on chain",
        TokenStatus::Unknown => "unknown",
        TokenStatus::Counterfeit => "DISPUTED - the ledger's record is not this note",
        TokenStatus::OtherMint => "another mint - not checked here",
        TokenStatus::Unbound => "unconfirmed - no mint has vouched for these bytes",
        TokenStatus::NotOurs => "owned by someone else - the ledger names another owner",
    }
}

const USAGE: &str = "\
kenter - desktop reference client

USAGE:
    kenter print   [--denom <stroops>] [--pairs <n>] --out <file.symtoken>
    kenter print-net --out <file.symtoken> [--secret-file <path>] [--pairs <n>]
                   [--denom <stroops>] [--rpc <url>] [--contract <id>] [--roster <id>]
                   [--relay <host> [--insecure]]
    kenter inspect <file.symtoken>
    kenter import  <file.symtoken>... [--wallet <dir>]
    kenter held    [--wallet <dir>]
    kenter forget  <token-id> [--yes] [--wallet <dir>]
    kenter sync    [--wallet <dir>] [--rpc <url>] [--contract <id>]
    kenter backup  <export <file> | restore <file> | inspect <file>> --vault <file.vault>
                   [--wallet <dir>]
    kenter redeem  <token-id> [--secret-file <path>] [--vault <file.vault> | --owner-secret-file <path>]
                   [--to <G...>] [--dry-run] [--wallet <dir>] [--rpc <url>] [--contract <id>]
    kenter balance [--wallet <dir>] [--rpc <url>] [--contract <id>]
    kenter seed    <generate | restore | status> --vault <file.vault>
    kenter receive <new --vault <file.vault> | complete <file.symtoken> [--index n] [--wait secs] | list>
                   [--wallet <dir>] [--rpc <url>] [--contract <id>]
    kenter keygen  --vault <file.vault> [--label <name>]
    kenter keys    --vault <file.vault>
    kenter keycard <status | generate | sign --message <text>>
    kenter help

SECRETS:
    Funded keys never go on the command line. print-net reads the depositor key
    from $KENTER_DEPOSITOR_SECRET or --secret-file; redeem reads the payout key
    from $KENTER_REDEEM_SECRET or --secret-file, and an owner key held outside
    the wallet from $KENTER_OWNER_SECRET or --owner-secret-file.

THE WALLET:
    import/held/forget/balance operate on a persistent token store. Kenter has no
    balance query - a balance is the sum of the bearer tokens you hold, each
    reconciled against its on-chain status - so the wallet keeps the token bytes
    locally and reads the chain only for status.

    Store location: --wallet <dir>, else $KENTER_WALLET_DIR, else ~/.kenter/wallet.
    One JSON record per token under <dir>/tokens/, written atomically.

    sync reconciles ownership: it binds a token whose receive crashed before it
    was recorded, and flags one that has been paid away. The second matters -
    a token you paid someone is still Active on the ledger, so until sync runs
    your balance still counts it as spendable.

    import verifies each token offline (container parse + chain integrity) before
    storing it, and refuses duplicates. balance is the ONLINE command: it
    reconciles every held token against kenter-mint over Soroban RPC. forget
    deletes local bytes only - if the token is unredeemed and not backed up, the
    value goes with it, because a bearer token cannot be reissued.

NOTES:
    print mints IN-PROCESS (single machine plays all node roles) - a sovereign
    testbed convenience, not the real networked mint.

    print-net is the real one: the middle pairs are live nodes chosen by the
    network (a drand-seeded draw the nodes claim into), each reached through its own relay, extending the chain and confirming
    its own link on-chain. The
    depositor still opens and closes the chain - initiate needs both keys of
    pair 0 and there is no /kenter/initiate message, and assembly closes with
    the requestor's own pair by design, which is what keeps the token out of
    reach of any coalition of nodes. So a k-node print has k+2 pairs. The
    depositor's own pairs need no roster membership and no stake.

    redeem releases a held token via redeem_by_chain / redeem_by_chain_owned -
    node-free and secret-free, needing only the stored bytes plus, in spend mode,
    the current owner key. Normally that key is derived from --vault using the
    owner index the wallet recorded at receive, so it never leaves the vault;
    an owner key file is the fallback for a key held outside the wallet. The
    payout key is the funded key that submits the tx and receives the payout. The redeemed record is kept, so
    balance shows it under `redeemed`; forget drops it. The cost of node-freedom
    is publicity: Path B writes the whole construction chain on-chain.

    backup is the OTHER HALF OF RECOVERY. Your recovery phrase restores owner
    keys, not tokens: tokens cannot be found from the ledger, so without the
    blobs there is nothing to redeem. Export after EVERY receive - a backup
    taken before a payment does not contain it. The file is sealed under the
    wallet seed, so restoring needs the phrase and the file, not the vault.

    seed manages the BIP-39 HD seed that spend-mode OWNER keys derive from
    (m/44'/148'/n'). Nothing can receive or redeem a spend-mode
    token until a seed exists. generate shows the phrase once; restore reads one
    from stdin. The phrase restores your authority to spend and redeem - it does
    NOT restore your tokens, which cannot be found from the ledger, so back up
    the wallet's token files too.

    receive takes delivery of a spend-mode payment in two steps, because the CLI
    has no transport: `receive new` reserves an owner index and shows its
    commitment for the payer; `receive complete <file>` runs the mandatory gates
    (G1 structure, G2 on-ledger Active and amount, G3 ownership moved to you,
    G4 persist) against the bytes they sent. --wait polls while the spend lands.
    You are NOT paid until complete succeeds - holding the bytes is not owning
    the token.

    keygen/keys use the SoftVault (passphrase-encrypted Ed25519 keys at rest).
    The passphrase is read from stdin (never argv/env).

    keycard drives a stock Keycard applet over the reader (needs card + PC/SC
    reader). It is a secp256k1 signer, a distinct capability from the SoftVault's Ed25519 Stellar keys, not an
    interchangeable backend. PIN is read from stdin.";

fn print_usage() {
    println!("{USAGE}");
}

/// `print` — mint a bearer token offline and write the SYMTOKEN container to a file.
fn cmd_print(args: &[String]) -> Result<(), String> {
    let mut denom: u64 = 1_000_000; // 0.1 XLM in stroops, arbitrary default
    let mut pairs: u16 = 3;
    let mut out: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--denom" => {
                denom = parse_next(args, &mut i, "--denom")?
                    .parse()
                    .map_err(|_| "--denom must be a u64 (stroops)".to_string())?;
            }
            "--pairs" => {
                pairs = parse_next(args, &mut i, "--pairs")?
                    .parse()
                    .map_err(|_| "--pairs must be a u16".to_string())?;
            }
            "--out" => out = Some(parse_next(args, &mut i, "--out")?),
            other => return Err(format!("unexpected argument: {other:?}")),
        }
        i += 1;
    }

    let out = out.ok_or("--out <file> is required")?;

    let (token, requestor) = gen_token(denom, pairs)?;

    let container = serialize_bearer_token(&token, &requestor)
        .map_err(|e| format!("serialize failed: {e}"))?;

    std::fs::write(&out, &container).map_err(|e| format!("writing {out}: {e}"))?;

    println!("minted bearer token -> {out}");
    println!("  size         : {} bytes", container.len());
    println!("  pairs        : {}", token.chain.total_pairs);
    println!("  denomination : {denom} stroops");
    println!("  value address: {}", token.ephemeral_address());
    println!("  signer       : {}", requestor.stellar_address());
    Ok(())
}

/// Mint a bearer token in-process (one machine plays every node role). Returns
/// the token and the requestor keypair (needed to sign the SYMTOKEN container).
fn gen_token(denom: u64, pairs: u16) -> Result<(BearerToken, StellarKeypair), String> {
    if pairs < 2 {
        return Err("--pairs must be at least 2 (minimum daisy chain)".into());
    }
    let event_id: [u8; 32] = rand::random();
    let timestamp = unix_now();
    let requestor = StellarKeypair::random();

    let (n0a, n0b) = (StellarKeypair::random(), StellarKeypair::random());
    let (mut partial, _shard0) = PartialToken::initiate(
        event_id, timestamp, Some(denom), pairs, &n0a, &n0b, vec![],
    )
    .map_err(|e| format!("initiate failed: {e}"))?;
    for _ in 0..(pairs - 2) {
        let (na, nb) = (StellarKeypair::random(), StellarKeypair::random());
        partial.extend(&na, &nb).map_err(|e| format!("extend failed: {e}"))?;
    }
    let partner = StellarKeypair::random();
    let token = assemble_bearer_token(&partial, &requestor, &partner, 0, None)
        .map_err(|e| format!("assemble failed: {e}"))?;
    Ok((token, requestor))
}

/// `print-net` - mint a token across a live node network.
///
/// The networked counterpart to `print`, which fakes every node role in
/// process. Here the middle pairs are real separate processes reached over the
/// tunnel, each extending the chain and recording its own link on-chain.
///
/// The depositor still opens and closes the chain: `PartialToken::initiate`
/// needs both keys of pair 0 and there is no `/kenter/initiate` message, while
/// assembly closes with the requestor's own pair by design (that final link is
/// what keeps the token out of reach of any coalition of nodes; see
/// `docs/architecture/security-model.md`). So a k-node print has k+2 pairs.
fn cmd_print_net(args: &[String]) -> Result<(), String> {
    use kenter_print::{print_selected, DepositorPairs, NodeRelay, PrintOrder, Reach};

    refuse_argv_secrets(args, &[("--secret", "KENTER_DEPOSITOR_SECRET", "--secret-file")])?;
    let net = net_default()?;
    let mut secret_file: Option<String> = None;
    let mut total_pairs: u32 = 3;
    let mut relay: Option<String> = None;
    let mut secure = true;
    let mut rpc_url = net.rpc.clone();
    let mut contract = net.mint.clone();
    let mut roster = net.roster.clone();
    let mut denom: u64 = 1_000_000;
    let mut out: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--secret" => {
                return Err(argv_secret_refused("--secret", "KENTER_DEPOSITOR_SECRET", "--secret-file"))
            }
            "--secret-file" => secret_file = Some(parse_next(args, &mut i, "--secret-file")?),
            "--pairs" => {
                total_pairs = parse_next(args, &mut i, "--pairs")?
                    .parse()
                    .map_err(|_| "--pairs must be a number, at least 3".to_string())?
            }
            "--relay" => relay = Some(parse_next(args, &mut i, "--relay")?),
            "--insecure" => secure = false,
            "--rpc" => rpc_url = parse_next(args, &mut i, "--rpc")?,
            "--contract" => contract = parse_next(args, &mut i, "--contract")?,
            "--roster" => roster = parse_next(args, &mut i, "--roster")?,
            "--out" => out = Some(parse_next(args, &mut i, "--out")?),
            "--denom" => {
                denom = parse_next(args, &mut i, "--denom")?
                    .parse()
                    .map_err(|_| "--denom must be a u64 (stroops)".to_string())?
            }
            "--via" | "--tunnel" => {
                return Err(format!(
                    "{} is not supported: the network chooses a print's nodes                      (docs/architecture/node-selection.md). Use --pairs <n>; --relay <host> only for a local rig.",
                    args[i]
                ))
            }
            other => return Err(format!("unexpected argument: {other:?}")),
        }
        i += 1;
    }
    let secret = resolve_secret(secret_file, "KENTER_DEPOSITOR_SECRET", "the depositor")?;
    let out = out.ok_or("print-net requires --out <file.symtoken>")?;
    if total_pairs < 3 {
        return Err("--pairs must be at least 3: yours at both ends, and one chosen by the network".into());
    }
    let kp = StellarKeypair::from_stellar_secret(&secret).map_err(|e| format!("bad depositor secret: {e}"))?;
    let me = kp.stellar_address();

    println!("networked print, {total_pairs} pairs ({} chosen by the network)", total_pairs - 2);
    println!("  depositor : {me}");
    println!();

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
    rt.block_on(async move {
        let mut mint = MintClient::new(TxBuilder::new(cli_rpc(&rpc_url, &contract)?, kp.clone()), &contract);
        // The depositor reaches each selected node through the relay its
        // roster endpoint names, unless a fixed one is given for a local
        // rig whose relay advertises a domain it is not reachable at.
        let mut reach = match &relay {
            Some(host) => Reach::Fixed(NodeRelay::new(host, secure)?),
            None => Reach::Roster {
                roster: kenter_client::RosterClient::new(
                    TxBuilder::read_only(cli_rpc(&rpc_url, &contract)?, &me),
                    &roster,
                ),
                // Only this build's relays: a node names its relay in its
                // roster endpoint, and an operator free to name a host of
                // their own would learn every depositor's IP.
                relays: kenter_client::network::built().relays.iter().map(|r| r.to_string()).collect(),
            },
        };
        let beacon = kenter_client::Beacon::quicknet().map_err(|e| format!("beacon: {e}"))?;
        let order = PrintOrder {
            total_pairs,
            event_id: rand::random(),
            denomination: denom,
            timestamp: unix_now(),
            mode: TokenMode::PureBearer,
            owner_commitment: [0u8; 32],
        };
        let (token, container) = print_selected(
            &mut mint,
            &mut reach,
            &beacon,
            &DepositorPairs::testbed(&kp),
            &order,
            &|line: &str| println!("{line}"),
        )
        .await?;

        std::fs::write(&out, &container).map_err(|e| format!("writing {out}: {e}"))?;
        println!();
        println!("✓ printed across the network -> {out}");
        println!("  size          : {} bytes", container.len());
        println!("  pairs         : {}", token.chain.total_pairs);
        println!("  value address : {}", token.ephemeral_address());
        println!("  denomination  : {denom} stroops");
        Ok::<(), String>(())
    })
}

/// `spend-demo` — **removed.** It minted a token in process, registered it
/// in Spend mode owned by a fresh "Alice" key and moved the owner pointer
/// to a fresh "Bob" key, all behind one funded secret playing every node.
///
/// The spend half of that still works; the print in front of it does not.
fn cmd_spend_demo(_args: &[String]) -> Result<(), String> {
    Err(solo_print_is_closed(
        "both pairs",
        "The live spend-mode walkthrough needs a real print behind it now: \
         bring up the node daemons (`kenter-systest` drives them) and print \
         with `kenter print-net`, then spend the note that comes out.",
    ))
}

/// Abbreviate a 32-byte value (e.g. an owner commitment) for display.
fn short_hex(b: &[u8; 32]) -> String {
    let h = hex::encode(b);
    format!("{}…{}", &h[..6], &h[h.len() - 4..])
}

/// `inspect` — load a token file, verify it, and print its metadata.
fn cmd_inspect(args: &[String]) -> Result<(), String> {
    let path = args
        .first()
        .ok_or("inspect requires a <file.symtoken> argument")?;
    let bytes = std::fs::read(path).map_err(|e| format!("reading {path}: {e}"))?;

    if !is_symtoken(&bytes) {
        return Err(format!("{path} is not a SYMTOKEN container (bad magic)"));
    }

    let token = deserialize_bearer_token(&bytes).map_err(|e| format!("parse failed: {e}"))?;

    // Structural verification: chain consistency + per-link signatures + hash chain.
    let chain_ok = token.verify_chain_integrity().is_ok();

    println!("{path}");
    println!("  size          : {} bytes", bytes.len());
    println!("  token type    : {:?}", token.header.token_type);
    println!(
        "  denomination  : {}",
        token
            .header
            .denomination
            .map(|d| format!("{d} stroops"))
            .unwrap_or_else(|| "none".into())
    );
    println!("  pairs         : {}", token.chain.total_pairs);
    println!("  chain links   : {}", token.chain.links.len());
    println!("  value address : {}", token.ephemeral_address());
    println!(
        "  chain integrity: {}",
        if chain_ok { "OK" } else { "FAILED" }
    );

    // The container signature is verified against the signer embedded in the
    // final chain link (the requestor's public key).
    // The requestor (container signer) is node A of the final assembled pair.
    let signer_pub = token
        .chain
        .links
        .last()
        .map(|l| l.node_a_public)
        .ok_or("token has no chain links")?;
    let sig_ok = verify_bearer_signature(&bytes, &signer_pub).is_ok();
    println!("  signature      : {}", if sig_ok { "OK" } else { "FAILED" });

    if chain_ok && sig_ok {
        Ok(())
    } else {
        Err("token failed verification".into())
    }
}

/// `keygen` — generate a fresh Ed25519 key in a passphrase-encrypted SoftVault.
fn cmd_keygen(args: &[String]) -> Result<(), String> {
    let mut vault_path: Option<String> = None;
    let mut label = "default".to_string();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--vault" => vault_path = Some(parse_next(args, &mut i, "--vault")?),
            "--label" => label = parse_next(args, &mut i, "--label")?,
            other => return Err(format!("unexpected argument: {other:?}")),
        }
        i += 1;
    }
    let vault_path = vault_path.ok_or("--vault <file> is required")?;

    let mut vault = SoftVault::open(&vault_path).map_err(|e| e.to_string())?;
    // Twice on a vault with nothing in it yet: there is no existing
    // entry for the vault to check a typo against, and this key has no
    // recovery phrase behind it.
    let pass = if vault.list_keys().map(|k| k.is_empty()).unwrap_or(true) && !vault.has_seed() {
        read_new_passphrase("vault passphrase: ")?
    } else {
        read_passphrase("vault passphrase: ")?
    };
    if pass.is_empty() {
        return Err("passphrase must not be empty".into());
    }

    let slot = vault
        .generate_key(&label, pass.as_bytes())
        .map_err(|e| e.to_string())?;
    let addr = vault.stellar_address(slot).map_err(|e| e.to_string())?;

    println!("generated key in slot {slot}");
    println!("  label   : {label}");
    println!("  address : {addr}");
    println!("  vault   : {vault_path}");
    Ok(())
}

/// `keys` — list the keys in a SoftVault (no passphrase needed — public metadata).
fn cmd_keys(args: &[String]) -> Result<(), String> {
    let mut vault_path: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--vault" => vault_path = Some(parse_next(args, &mut i, "--vault")?),
            other => return Err(format!("unexpected argument: {other:?}")),
        }
        i += 1;
    }
    let vault_path = vault_path.ok_or("--vault <file> is required")?;

    let vault = SoftVault::open(&vault_path).map_err(|e| e.to_string())?;
    let keys = vault.list_keys().map_err(|e| e.to_string())?;
    if keys.is_empty() {
        println!("{vault_path}: (no keys)");
        return Ok(());
    }
    println!("{vault_path}: {} key(s)", keys.len());
    for k in keys {
        println!("  [{}] {:<16} {}", k.slot, k.label, k.stellar_address);
    }
    Ok(())
}

/// `receive` - take delivery of a spend-mode payment (`docs/architecture/spend-mode.md`).
///
/// Two steps, because a CLI has no transport of its own:
///
///   receive new                 reserve an owner index, show its commitment
///   receive complete <file>     run the gates against the bytes the payer sent
///
/// The gates (G1 structure, G2 on-ledger Active and amount, G3 ownership moved
/// to us, G4 persist) live in the wallet core, not here - a shell that skips one
/// is unsafe, so there is exactly one implementation of them.
///
/// **Until `complete` succeeds you have not been paid**, no matter what bytes
/// you are holding. Holding a token is not owning it in spend mode.
fn cmd_receive(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str);
    let mut wallet_dir: Option<String> = None;
    let mut vault_path: Option<String> = None;
    let mut rpc_url = net_default()?.rpc;
    let mut contract = net_default()?.mint;
    let mut wait_secs: u64 = 0;
    let mut file: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--wallet" => wallet_dir = Some(parse_next(args, &mut i, "--wallet")?),
            "--vault" => vault_path = Some(parse_next(args, &mut i, "--vault")?),
            "--rpc" => rpc_url = parse_next(args, &mut i, "--rpc")?,
            "--contract" => contract = parse_next(args, &mut i, "--contract")?,
            // Removed with the known-owner rule: the ledger names the index,
            // so a hand-picked one could only disagree with it. Named rather
            // than swallowed by the catch-all, which would say only
            // "unexpected argument".
            "--index" => {
                return Err(
                    "--index is not accepted: the owner index comes from the ledger"
                        .into(),
                )
            }
            "--wait" => {
                wait_secs = parse_next(args, &mut i, "--wait")?
                    .parse()
                    .map_err(|_| "--wait must be seconds (u64)".to_string())?
            }
            other if other.starts_with("--") => {
                return Err(format!("unexpected argument: {other:?}"))
            }
            _ => file = Some(args[i].clone()),
        }
        i += 1;
    }
    let dir = resolve_wallet_dir(wallet_dir)?;

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
    rt.block_on(async move {
        let store = open_store(&dir, vault_path.clone())?;
        let rpc = cli_rpc(&rpc_url, &contract)?;
        let mint = MintClient::new(TxBuilder::new(rpc, StellarKeypair::random()), &contract);

        match sub {
            Some("new") => {
                let vault_path = vault_path
                    .ok_or("receive new requires --vault <file> (it derives an owner key)")?;
                let vault = SoftVault::open(&vault_path).map_err(|e| e.to_string())?;
                if !vault.has_seed() {
                    return Err(format!(
                        "{vault_path} holds no seed - run `kenter seed generate --vault {vault_path}` first"
                    ));
                }
                let pass = read_passphrase("vault passphrase: ")?;
                let mut wallet = TokenWallet::with_vault(WalletChain::new(mint), store, vault);
                let pending = wallet
                    .start_receive(pass.as_bytes(), unix_now())
                    .await
                    .map_err(|e| e.to_string())?;

                println!();
                println!("  give this commitment to the payer:");
                println!();
                println!("    {}", hex::encode(pending.commitment));
                println!();
                println!("  owner index   : {}", pending.index);
                println!("  wallet        : {}", dir.display());
                println!();
                println!("  Then, once they have sent you the token file:");
                println!("    kenter receive complete <file.symtoken> --wallet {} --wait 120", dir.display());
                println!();
                println!("  You are NOT paid until that succeeds - holding the bytes is not");
                println!("  owning the token.");
                Ok::<(), String>(())
            }
            Some("list") => {
                let pending = store.pending().await.map_err(|e| e.to_string())?;
                println!("wallet: {}", dir.display());
                if pending.is_empty() {
                    println!("  (no receives awaiting completion)");
                    return Ok(());
                }
                println!("  {} awaiting completion\n", pending.len());
                println!("{:>5}  {:<20}  {}", "index", "commitment", "reserved (unix)");
                for p in &pending {
                    println!(
                        "{:>5}  {:<20}  {}",
                        p.index,
                        short_hex(&p.commitment),
                        p.created_at
                    );
                }
                Ok(())
            }
            Some("complete") => {
                let path = file.ok_or("receive complete requires a <file.symtoken>")?;
                let bytes = std::fs::read(&path).map_err(|e| format!("reading {path}: {e}"))?;

                // Which index owns it is the ledger's answer, not ours: the
                // core looks the live owner commitment up among the ones this
                // wallet can open. Nominating one by hand could only disagree
                // with the ledger, so there is no `--index`.
                let mut wallet = TokenWallet::new(WalletChain::new(mint), store);
                let known = wallet.known_owners().await.map_err(|e| e.to_string())?;
                if known.is_empty() {
                    return Err(
                        "no pay tag to complete against - run `kenter receive new` before \
                         accepting a payment"
                            .into(),
                    );
                }
                let deadline = std::time::Instant::now()
                    + std::time::Duration::from_secs(wait_secs);
                println!("completing against {} known owner index(es)", known.len());
                if wait_secs > 0 {
                    println!("  polling up to {wait_secs}s for the payer's spend to land...");
                }

                loop {
                    match wallet.complete_receive(bytes.clone(), unix_now()).await {
                        Ok(held) => {
                            println!();
                            println!("✓ payment received - {}", fmt_stroops(held.amount));
                            println!("  token       : {}", short(&held.id));
                            println!("  owner index : {}", held.owner_index.unwrap_or_default());
                            println!();
                            println!("  the ledger says this token is Active and owned by you.");
                            println!("  back up the wallet's token file: your recovery phrase");
                            println!("  restores the owner key, not the token itself.");
                            return Ok(());
                        }
                        // Keep waiting only where the core says waiting could
                        // change the answer (the spend may not have landed yet).
                        // A bad structure or a wrong amount never will.
                        Err(WalletError::ReceiveGate { retryable: true, gate, detail })
                            if std::time::Instant::now() < deadline =>
                        {
                            println!("  {gate}: {detail} - retrying");
                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                        }
                        Err(e) => return Err(e.to_string()),
                    }
                }
            }
            _ => Err(
                "usage: kenter receive <new --vault <file> | complete <file.symtoken> [--wait secs] | list> [--wallet <dir>]"
                    .into(),
            ),
        }
    })
}

/// `seed` - manage the HD seed that spend-mode owner keys derive from.
///
/// Nothing can receive or redeem a spend-mode token until a seed exists: owner
/// keys are derived at `m/44'/148'/n'`, never stored (`docs/architecture/custody.md`). The seed
/// is a BIP-39 phrase so the same backup restores onto a Keycard, which loads
/// BIP-39 seeds natively.
fn cmd_seed(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str);
    let mut vault_path: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--vault" => vault_path = Some(parse_next(args, &mut i, "--vault")?),
            other => return Err(format!("unexpected argument: {other:?}")),
        }
        i += 1;
    }
    let vault_path = vault_path.ok_or("--vault <file> is required")?;
    let mut vault = SoftVault::open(&vault_path).map_err(|e| e.to_string())?;

    match sub {
        Some("status") => {
            println!("vault: {vault_path}");
            if !vault.has_seed() {
                println!("  seed    : none  (`kenter seed generate --vault {vault_path}`)");
                return Ok(());
            }
            println!("  seed    : present");
            let pass = read_passphrase("vault passphrase: ")?;
            // Show the static receive address, which is the one index whose
            // commitment is meant to be published.
            let pk = vault
                .derive_public(kenter_wallet::STATIC_RECEIVE_INDEX, pass.as_bytes())
                .map_err(|e| e.to_string())?;
            println!(
                "  static receive (index {}): {}",
                kenter_wallet::STATIC_RECEIVE_INDEX,
                short_hex(&kenter_crypto::spend::owner_commitment(&pk))
            );
            println!("  (every payment sent to the static address is linkable to the others)");
            Ok(())
        }
        Some("generate") => {
            if vault.has_seed() {
                return Err(
                    "this vault already holds a seed; replacing it would orphan every token \
                     owned by a key derived from the old one"
                        .into(),
                );
            }
            // The phrase below is printed once and never again, so a
            // passphrase typo here can cost the whole wallet.
            let pass = read_new_passphrase("vault passphrase: ")?;
            let phrase = mnemonic::generate().map_err(|e| e.to_string())?;
            vault
                .set_seed_from_mnemonic(&phrase, "", pass.as_bytes())
                .map_err(|e| e.to_string())?;

            println!();
            println!("  RECOVERY PHRASE - write this down now, on paper:");
            println!();
            for (n, chunk) in phrase.split_whitespace().collect::<Vec<_>>().chunks(6).enumerate() {
                println!("    {:>2}. {}", n * 6 + 1, chunk.join("  "));
            }
            println!();
            println!("  It is shown once and cannot be recovered from the vault.");
            println!();
            println!("  It restores your OWNER KEYS - your authority to spend and redeem.");
            println!("  It does NOT restore your tokens. Tokens cannot be found from the");
            println!("  ledger, so the phrase alone redeems nothing: back up the wallet's");
            println!("  token files too, every time you receive one (`kenter backup`).");
            Ok(())
        }
        Some("restore") => {
            if vault.has_seed() {
                return Err("this vault already holds a seed; restore into a fresh vault".into());
            }
            let phrase = read_passphrase("recovery phrase: ")?;
            mnemonic::validate(&phrase).map_err(|e| e.to_string())?;
            let pass = read_passphrase("vault passphrase: ")?;
            if pass.is_empty() {
                return Err("passphrase must not be empty".into());
            }
            vault
                .set_seed_from_mnemonic(&phrase, "", pass.as_bytes())
                .map_err(|e| e.to_string())?;

            let pk = vault
                .derive_public(kenter_wallet::STATIC_RECEIVE_INDEX, pass.as_bytes())
                .map_err(|e| e.to_string())?;
            println!("seed restored into {vault_path} ({} words)", mnemonic::word_count(&phrase));
            println!(
                "  static receive (index {}): {}",
                kenter_wallet::STATIC_RECEIVE_INDEX,
                short_hex(&kenter_crypto::spend::owner_commitment(&pk))
            );
            println!();
            println!("  Check that commitment against your old wallet before relying on this");
            println!("  restore. A phrase that parses is not proof it is the right phrase -");
            println!("  a single wrong word passes a 12-word checksum about 1 time in 16.");
            Ok(())
        }
        _ => Err("usage: kenter seed <generate | restore | status> --vault <file>".into()),
    }
}

/// `keycard` — drive a Status Keycard over the reader (secp256k1 owner-key role).
fn cmd_keycard(args: &[String]) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    use stellar_keycard::{KeycardVault, DEFAULT_PAIRING_PASSWORD};

    let sub = args.first().map(String::as_str);
    let mut vault = KeycardVault::connect().map_err(|e| format!("connect: {e}"))?;

    match sub {
        Some("status") => {
            println!("keycard:");
            println!("  initialized : {}", vault.is_initialized());
            println!("  sc pubkey   : {}", hex::encode(vault.card_public_key()));
            Ok(())
        }
        Some("generate") => {
            if !vault.is_initialized() {
                return Err("card not initialized (init it first)".into());
            }
            vault
                .ensure_paired(DEFAULT_PAIRING_PASSWORD)
                .map_err(|e| format!("pair: {e}"))?;
            let pin = read_passphrase("card PIN: ")?;
            let uid = vault
                .generate_key(&pin)
                .map_err(|e| format!("generate_key: {e}"))?;
            println!("generated on-card key — uid {}", hex::encode(uid));
            Ok(())
        }
        Some("sign") => {
            // kenter keycard sign --message <text>
            let mut message: Option<String> = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--message" => message = Some(parse_next(args, &mut i, "--message")?),
                    other => return Err(format!("unexpected argument: {other:?}")),
                }
                i += 1;
            }
            let message = message.ok_or("--message <text> is required")?;
            if !vault.is_initialized() {
                return Err("card not initialized (init it first)".into());
            }
            vault
                .ensure_paired(DEFAULT_PAIRING_PASSWORD)
                .map_err(|e| format!("pair: {e}"))?;
            let pin = read_passphrase("card PIN: ")?;
            let hash: [u8; 32] = Sha256::digest(message.as_bytes()).into();
            let sig = vault
                .sign_ecdsa(&pin, &hash)
                .map_err(|e| format!("sign: {e}"))?;
            println!("signed SHA-256(message) with the on-card secp256k1 key:");
            println!("  message : {message:?}");
            println!("  hash    : {}", hex::encode(hash));
            println!("  pubkey  : {}", hex::encode(&sig.public_key));
            println!("  sig(DER): {}", hex::encode(&sig.der));
            Ok(())
        }
        _ => Err("usage: kenter keycard <status | generate | sign --message <text>>".into()),
    }
}

// -- helpers --

/// Read a passphrase from stdin (one line). Kept out of argv/env on purpose.
/// Note: not masked — a real client uses a no-echo prompt; acceptable for the
/// CLI testbed.
/// Read a passphrase that is about to **seal** something, asking twice.
///
/// The vault refuses a second, different passphrase outright, so a
/// typo here fails loudly rather than sealing a key nobody can open.
/// On the very first secret in a fresh vault there
/// is nothing to disagree with, though, and that is the dangerous case:
/// `seed generate` prints the recovery phrase once, and `keygen` makes
/// an account key that has no phrase at all. A mistyped passphrase
/// there takes the key with it.
///
/// So the typo is caught before anything is written, by asking twice.
fn read_new_passphrase(prompt: &str) -> Result<String, String> {
    let first = read_passphrase(prompt)?;
    if first.is_empty() {
        return Err("passphrase must not be empty".into());
    }
    let again = read_passphrase("confirm passphrase: ")?;
    if first != again {
        return Err("the two passphrases differ; nothing was written".into());
    }
    Ok(first)
}

fn read_passphrase(prompt: &str) -> Result<String, String> {
    use std::io::Write;
    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    let mut s = String::new();
    std::io::stdin()
        .read_line(&mut s)
        .map_err(|e| format!("reading passphrase: {e}"))?;
    Ok(s.trim_end_matches(['\n', '\r']).to_string())
}

fn parse_next(args: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// --------------------------------------------------------------------------
// REDEMPTION
//
// `redeem` is built on `redeem_by_chain(_owned)`: the holder presents the token's
// committed chain bytes (plus the owner proof in spend mode). It needs **no shard
// secrets and no node network**. The alternatives -- retaining every A-side
// secret, or contacting the nodes -- are two ways to reconstruct the ephemeral
// key for `redeem_by_key`, and Path B requires neither.
//
// Retaining shards would in any case be testbed-only: a token printed by the
// real node network never hands its shards to the holder — that is the point of
// the daisy chain.
//
// `redeem_by_key` is kept for later. Once a combiner driver exists it becomes
// the cheap, private path — one signature instead of publishing
// the whole construction chain — at the cost of a live network.
//
// Measured ceiling: Path B costs ~1.6M + 3.81M instructions per pair on a
// network, against a `tx_max_instructions` of 400M, so the 12-pair ceiling sits near 12%.
// `max_pairs` is still a redeemability safety parameter rather than policy --
// a note printed above the ceiling can never be redeemed by chain and the mint
// is immutable -- but the ceiling is not close (`docs/LEDGER_COSTS.md`).
// --------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed store keys, so a test can reopen what it wrote without a vault.
    fn test_creds() -> kenter_wallet::StoreCredentials {
        kenter_wallet::StoreCredentials {
            aead: zeroize::Zeroizing::new([3u8; 32]),
            name: zeroize::Zeroizing::new([4u8; 32]),
        }
    }

    fn tmp_dir(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("kenter-cli-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn held(id: &str) -> HeldToken {
        HeldToken {
            slot_id: 1,
            id: id.to_string(),
            ephemeral_public_key: [1u8; 32],
            event_id: [2u8; 32],
            amount: 10,
            blob: vec![0u8; 4],
            imported_at: 1,
            mint: None,
            label: None,
            owner_index: None,
            owner_commitment: None,
            spent_away: false,
            exports: Default::default(),
            marked_spent: false,
        }
    }

    /// Ids are 56 characters and `held` prints them abbreviated, so the commands
    /// that take one resolve any unambiguous prefix.
    #[tokio::test]
    async fn find_held_resolves_a_unique_prefix() {
        let dir = tmp_dir("prefix");
        let mut store = FileStore::open(&dir, test_creds()).unwrap();
        store.put(held("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).await.unwrap();
        store.put(held("GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")).await.unwrap();

        let t = find_held(&store, "GAAA").await.unwrap();
        assert!(t.id.starts_with("GAAA"));
        // The full id still works.
        let t = find_held(&store, "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
            .await
            .unwrap();
        assert!(t.id.starts_with("GBBB"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An ambiguous prefix must not silently pick one - redeeming or forgetting
    /// the wrong bearer token is unrecoverable.
    #[tokio::test]
    async fn find_held_refuses_an_ambiguous_prefix() {
        let dir = tmp_dir("ambiguous");
        let mut store = FileStore::open(&dir, test_creds()).unwrap();
        store.put(held("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).await.unwrap();
        store.put(held("GAAAZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")).await.unwrap();

        let err = find_held(&store, "GAAA").await.unwrap_err();
        assert!(err.contains("2 held tokens match"), "got {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn find_held_reports_no_match() {
        let dir = tmp_dir("nomatch");
        let store = FileStore::open(&dir, test_creds()).unwrap();
        let err = find_held(&store, "GZZZ").await.unwrap_err();
        assert!(err.contains("no held token matching"), "got {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// One key, two slots: the bare address is ambiguous and
    /// says so; each full id names its own note, even when one is a
    /// prefix of the other.
    #[tokio::test]
    async fn find_held_tells_slots_apart() {
        let dir = tmp_dir("slots");
        let mut store = FileStore::open(&dir, test_creds()).unwrap();
        let a = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        store.put(held(&format!("{a}-1"))).await.unwrap();
        store.put(held(&format!("{a}-12"))).await.unwrap();

        let err = find_held(&store, a).await.unwrap_err();
        assert!(err.contains("2 held tokens match"), "got {err}");
        assert_eq!(find_held(&store, &format!("{a}-1")).await.unwrap().id, format!("{a}-1"));
        assert_eq!(find_held(&store, &format!("{a}-12")).await.unwrap().id, format!("{a}-12"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wallet_dir_prefers_the_explicit_flag() {
        let p = resolve_wallet_dir(Some("D:/somewhere/custom".into())).unwrap();
        assert_eq!(p, PathBuf::from("D:/somewhere/custom"));
    }

    /// Secrets never come from the command line: each flag that once took
    /// one is refused before anything else runs, and the refusal names the
    /// way that does work.
    #[test]
    fn secrets_on_the_command_line_are_refused() {
        let s = "SAAQBILY3PPRCFEWR6TTF5EJSESRNQTHCXKY6IBQTKQVVQAJB2AXXF7N".to_string();
        let args = |v: &[&str]| v.iter().map(|a| a.to_string()).collect::<Vec<_>>();

        let err = cmd_print_net(&args(&["--secret", &s, "--out", "x"])).unwrap_err();
        assert!(err.contains("not accepted") && err.contains("KENTER_DEPOSITOR_SECRET"), "got {err}");

        let err = cmd_redeem(&args(&["GABC-1", "--secret", &s])).unwrap_err();
        assert!(err.contains("not accepted") && err.contains("KENTER_REDEEM_SECRET"), "got {err}");

        let err = cmd_redeem(&args(&["GABC-1", "--owner-secret", &s])).unwrap_err();
        assert!(err.contains("not accepted") && err.contains("--owner-secret-file"), "got {err}");
    }

    #[test]
    fn a_secret_file_is_read_and_trimmed() {
        let dir = tmp_dir("secret-file");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("key");
        std::fs::write(&f, "  SABC
").unwrap();
        let got = resolve_optional_secret(Some(f.display().to_string()), "KENTER_TEST_UNSET_VAR").unwrap();
        assert_eq!(got.as_deref(), Some("SABC"));
        std::fs::write(&f, "
").unwrap();
        assert!(resolve_optional_secret(Some(f.display().to_string()), "KENTER_TEST_UNSET_VAR").is_err());
        assert_eq!(resolve_optional_secret(None, "KENTER_TEST_UNSET_VAR").unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
