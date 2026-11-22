//! The tray: the node daemon with an icon.
//!
//! **One process, no window.** The daemon runs in-process on a tokio
//! runtime; the main thread runs a `winit` event loop, which is the message
//! pump the tray icon needs, and never opens a window. The menu is native
//! (`tray-icon`, which carries `muda`).
//!
//! **Settings is a separate process** (`kenter-node settings`, [`settings`]).
//! It edits `node.json`, then drops `reload.request`, which this process
//! polls and answers by restarting its node. Keeping the window out of this
//! process keeps the always-on process small, and means a crash in the GUI
//! cannot take the node down.
//!
//! What the menu can do in-process, and why some things are elsewhere:
//! - **Pause / Resume** stop and start the in-process daemon. Pausing
//!   leaves selection first, as any clean stop does.
//! - **Claim fees** runs only while paused, because the daemon serialises
//!   its own account's transactions and a second submitter would race it.
//! - **Leave and withdraw** live in Settings, behind confirmations, and
//!   need the node paused for the same reason.
//!
//! Windows and macOS. A Linux desktop tray needs a GTK main loop instead of
//! `winit`'s; until then Linux runs the node headless (`run`, `status`).

pub mod autostart;
pub mod icon;
pub mod settings;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::runtime::Runtime;
use tokio::sync::watch;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder, TrayIconEvent};
use winit::application::ApplicationHandler;
use winit::event::{StartCause, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
use winit::window::WindowId;

use crate::chain::{Chain, LOW_BALANCE, spendable, xlm};
use crate::config::NodeConfig;
use crate::home::Home;
use crate::keys::PairKeys;
use crate::status::{DaemonLock, DaemonStatus, Reporter, State};
use icon::Health;

const TICK: Duration = Duration::from_secs(2);
const FUNDS_EVERY: Duration = Duration::from_secs(60);
/// A clean stop is two roster transactions at up to 45 s each.
const QUIT_WAIT: Duration = Duration::from_secs(100);

enum UserEvent {
    Menu(MenuEvent),
}

/// What the tray shows about the pair's money, refreshed in the background.
#[derive(Debug, Clone, Default)]
struct Funds {
    known: bool,
    low: bool,
    balance: String,
    fees: String,
    volunteer: bool,
    owed: bool,
}

struct Items {
    status: MenuItem,
    balance: MenuItem,
    fees: MenuItem,
    toggle: MenuItem,
    claim: MenuItem,
    wallet: MenuItem,
    settings: MenuItem,
    quit: MenuItem,
}

struct Node {
    stop: watch::Sender<bool>,
    reporter: Reporter,
    handle: tokio::task::JoinHandle<Result<(), String>>,
}

struct TrayApp {
    home: Home,
    rt: Runtime,
    tray: Option<TrayIcon>,
    items: Items,
    menu: Option<Menu>,
    node: Option<Node>,
    paused: bool,
    /// Why the node is not running, when it is not and was not paused.
    halted: Option<String>,
    funds: Arc<Mutex<Funds>>,
    notice: Arc<Mutex<Option<String>>>,
    health: Option<Health>,
    last_funds: Option<Instant>,
}

/// Run the tray until Quit.
pub fn run(home: Home) -> Result<(), String> {
    let event_loop = EventLoop::<UserEvent>::with_user_event()
        .build()
        .map_err(|e| format!("starting the event loop: {e}"))?;
    let proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |e| {
        let _ = proxy.send_event(UserEvent::Menu(e));
    }));
    // Clicks on the icon itself mean nothing here; drain them so the
    // channel does not grow.
    TrayIconEvent::set_event_handler(Some(|_e| {}));

    let rt = Runtime::new().map_err(|e| format!("starting the runtime: {e}"))?;
    let items = Items {
        status: MenuItem::new("Starting…", false, None),
        balance: MenuItem::new("Fee balance: …", false, None),
        fees: MenuItem::new("Fees: …", false, None),
        toggle: MenuItem::new("Pause", true, None),
        claim: MenuItem::new("Claim fees", false, None),
        wallet: MenuItem::new("Open Kenter Wallet", true, None),
        settings: MenuItem::new("Settings…", true, None),
        quit: MenuItem::new("Quit", true, None),
    };
    let mut app = TrayApp {
        home,
        rt,
        tray: None,
        items,
        menu: None,
        node: None,
        paused: false,
        halted: None,
        funds: Arc::new(Mutex::new(Funds::default())),
        notice: Arc::new(Mutex::new(None)),
        health: None,
        last_funds: None,
    };
    event_loop.run_app(&mut app).map_err(|e| format!("event loop: {e}"))
}

impl TrayApp {
    fn build_tray(&mut self) -> Result<(), String> {
        let menu = Menu::new();
        let i = &self.items;
        menu.append_items(&[
            &i.status,
            &i.balance,
            &i.fees,
            &PredefinedMenuItem::separator(),
            &i.toggle,
            &i.claim,
            &PredefinedMenuItem::separator(),
            &i.wallet,
            &i.settings,
            &PredefinedMenuItem::separator(),
            &i.quit,
        ])
        .map_err(|e| format!("building the menu: {e}"))?;
        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu.clone()))
            .with_tooltip("Kenter node")
            .with_icon(icon_for(Health::Amber)?)
            .build()
            .map_err(|e| format!("creating the tray icon: {e}"))?;
        self.menu = Some(menu);
        self.tray = Some(tray);
        Ok(())
    }

    fn set_up(&self) -> bool {
        // An unreadable node.json counts as set up, so the load error is
        // what the tray shows, not an invitation to set up again (SC-1).
        crate::keys::has_pair(&self.home).unwrap_or(true)
    }

    fn start_node(&mut self) {
        if self.node.is_some() {
            return;
        }
        self.halted = None;
        let loaded = NodeConfig::load(&self.home).and_then(|c| PairKeys::load(&self.home).map(|k| (c, k)));
        let (cfg, keys) = match loaded {
            Ok(v) => v,
            Err(e) => {
                self.halted = Some(if self.set_up() { e } else { "Not set up — open Settings".into() });
                return;
            }
        };
        let reporter = Reporter::new(self.home.clone());
        let (tx, rx) = watch::channel(false);
        let handle = self.rt.spawn(crate::daemon::run(self.home.clone(), cfg, keys, reporter.clone(), rx));
        self.node = Some(Node { stop: tx, reporter, handle });
        self.paused = false;
    }

    /// Ask the node to stop and wait for it, up to `QUIT_WAIT`.
    fn stop_node(&mut self) {
        if let Some(node) = self.node.take() {
            let _ = node.stop.send(true);
            let _ = self.rt.block_on(async { tokio::time::timeout(QUIT_WAIT, node.handle).await });
        }
    }

    /// Notice a node that ended by itself (a failure, or another process
    /// holding the lock).
    fn reap(&mut self) {
        let finished = self.node.as_ref().is_some_and(|n| n.handle.is_finished());
        if !finished {
            return;
        }
        let node = self.node.take().expect("checked");
        match self.rt.block_on(node.handle) {
            Ok(Ok(())) => self.halted = Some("Stopped".into()),
            Ok(Err(e)) if e.contains("already running") => {
                self.halted = Some("Running in another process (see `kenter-node status`)".into())
            }
            Ok(Err(e)) => self.halted = Some(e),
            Err(e) => self.halted = Some(format!("node task: {e}")),
        }
    }

    fn poll_requests(&mut self) {
        if take_request(&self.home.reload_request()) {
            // New settings: restart unless the operator paused.
            if !self.paused {
                self.stop_node();
                self.start_node();
            }
        }
        if take_request(&self.home.stop_request()) && self.node.is_some() {
            self.stop_node();
            self.paused = true;
        }
    }

    fn refresh_funds(&mut self) {
        if self.last_funds.is_some_and(|t| t.elapsed() < FUNDS_EVERY) {
            return;
        }
        self.last_funds = Some(Instant::now());
        let home = self.home.clone();
        let funds = Arc::clone(&self.funds);
        self.rt.spawn(async move {
            if let Ok(f) = read_funds(&home).await {
                *funds.lock().unwrap_or_else(|p| p.into_inner()) = f;
            }
        });
    }

    fn render(&mut self) {
        let status = match &self.node {
            Some(n) => n.reporter.snapshot(),
            None => DaemonStatus::read(&self.home).unwrap_or_default(),
        };
        let funds = self.funds.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let backed_up = NodeConfig::load(&self.home).map(|c| c.backup_confirmed).unwrap_or(true);
        // A phrase file left by an interrupted move into the keystore (SC-2).
        let leftover = crate::keys::leftover_file(&self.home);

        let line = if self.paused {
            "Paused".to_string()
        } else if let Some(h) = &self.halted {
            h.clone()
        } else {
            describe(&status)
        };
        let line = match self.notice.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            Some(n) => format!("{line} — {n}"),
            None if leftover => format!("{line} — a leftover phrase file is on disk (Settings)"),
            None if !backed_up => format!("{line} — back up your recovery phrase (Settings)"),
            None => line,
        };

        let state = if self.halted.is_some() && !self.paused { State::Failed } else { status.state };
        let health = Health::of(state, self.paused, funds.known && funds.low, backed_up && !leftover);

        let i = &self.items;
        i.status.set_text(&line);
        i.balance.set_text(if funds.known { &funds.balance } else { "Fee balance: …" });
        i.fees.set_text(if funds.known { &funds.fees } else { "Fees: …" });
        i.toggle.set_text(if self.node.is_some() { "Pause" } else { "Resume" });
        i.toggle.set_enabled(self.set_up());
        i.claim.set_text(if self.node.is_some() { "Claim fees (pause first)" } else { "Claim fees" });
        i.claim.set_enabled(self.node.is_none() && funds.owed && !funds.volunteer);

        if let Some(tray) = &self.tray {
            let _ = tray.set_tooltip(Some(format!("Kenter node: {line}")));
            if self.health != Some(health) {
                if let Ok(icon) = icon_for(health) {
                    let _ = tray.set_icon(Some(icon));
                }
                self.health = Some(health);
            }
        }
    }

    fn on_menu(&mut self, event: &ActiveEventLoop, id: &tray_icon::menu::MenuId) {
        let i = &self.items;
        if id == i.toggle.id() {
            if self.node.is_some() {
                self.stop_node();
                self.paused = true;
            } else {
                self.start_node();
            }
        } else if id == i.claim.id() {
            self.claim();
        } else if id == i.wallet.id() {
            if let Err(e) = open_wallet() {
                self.say(e);
            }
        } else if id == i.settings.id() {
            if let Err(e) = open_settings() {
                self.say(e);
            }
        } else if id == i.quit.id() {
            self.items.status.set_text("Leaving selection…");
            self.stop_node();
            self.tray = None;
            event.exit();
            return;
        }
        self.render();
    }

    fn claim(&mut self) {
        if self.node.is_some() {
            return;
        }
        let home = self.home.clone();
        let notice = Arc::clone(&self.notice);
        self.last_funds = None;
        self.say("claiming…".into());
        self.rt.spawn(async move {
            let msg = match claim_both(&home).await {
                Ok(m) => m,
                Err(e) => format!("claim failed: {e}"),
            };
            *notice.lock().unwrap_or_else(|p| p.into_inner()) = Some(msg);
        });
    }

    fn say(&self, msg: String) {
        *self.notice.lock().unwrap_or_else(|p| p.into_inner()) = Some(msg);
    }
}

impl ApplicationHandler<UserEvent> for TrayApp {
    fn new_events(&mut self, event: &ActiveEventLoop, cause: StartCause) {
        if cause == StartCause::Init {
            // macOS wants the icon created once the loop is running.
            if let Err(e) = self.build_tray() {
                eprintln!("error: {e}");
                event.exit();
                return;
            }
            self.start_node();
        }
        self.reap();
        self.poll_requests();
        self.refresh_funds();
        self.render();
        event.set_control_flow(ControlFlow::WaitUntil(Instant::now() + TICK));
    }

    fn resumed(&mut self, _event: &ActiveEventLoop) {}

    fn window_event(&mut self, _event: &ActiveEventLoop, _id: WindowId, _e: WindowEvent) {}

    fn user_event(&mut self, event: &ActiveEventLoop, e: UserEvent) {
        match e {
            UserEvent::Menu(m) => self.on_menu(event, &m.id),
        }
    }
}

fn icon_for(h: Health) -> Result<Icon, String> {
    Icon::from_rgba(h.rgba(), icon::SIZE, icon::SIZE).map_err(|e| format!("tray icon: {e}"))
}

fn take_request(path: &std::path::Path) -> bool {
    if path.exists() {
        let _ = std::fs::remove_file(path);
        true
    } else {
        false
    }
}

/// The status line for a running node.
fn describe(s: &DaemonStatus) -> String {
    let base = match s.state {
        // Online but not registered with the mint: on the roster, and never
        // drawn. Said, because nothing else on the menu would show it.
        State::Online if !s.pair_registered => "Online · not yet registered for prints".into(),
        State::Online => format!("Online · {} prints served", s.links_confirmed),
        State::Starting => "Starting".into(),
        State::AwaitingFunds => "Waiting for funds".into(),
        State::Joining => "Joining the roster".into(),
        State::Reconnecting => "Reconnecting to a relay".into(),
        State::Stopping => "Leaving selection".into(),
        State::Stopped => "Stopped".into(),
        State::Failed => "Stopped: needs attention".into(),
    };
    match (&s.detail, s.state) {
        (Some(d), State::AwaitingFunds | State::Failed) => format!("{base}: {d}"),
        _ => base,
    }
}

async fn read_funds(home: &Home) -> Result<Funds, String> {
    let cfg = NodeConfig::load(home)?;
    let keys = PairKeys::load(home)?;
    let chain = Chain::new(cfg.network()?);
    let own = chain.view(&keys.own).await?;
    let partner = chain.view(&keys.partner).await?;
    let free = |v: &crate::chain::AccountView| v.native.map(|n| spendable(n, v.subentries));
    let low = [&own, &partner]
        .iter()
        .any(|v| v.node.is_some() && free(v).unwrap_or(0) < LOW_BALANCE);
    let volunteer = cfg.volunteer || [&own, &partner].iter().any(|v| v.node.as_ref().is_some_and(|n| n.volunteer));
    let owed: i128 = [&own, &partner].iter().filter_map(|v| v.accrued).sum();
    let show = |v: Option<i128>| v.map(xlm).unwrap_or_else(|| "unfunded".into());
    Ok(Funds {
        known: true,
        low,
        balance: format!(
            "Fee balance: {} / {} XLM{}",
            show(free(&own)),
            show(free(&partner)),
            if low { " — top up" } else { "" }
        ),
        fees: if volunteer {
            "Fees: burned (volunteer)".into()
        } else if owed > 0 {
            format!("Fees owed: {}", xlm(owed))
        } else {
            "Fees owed: none".into()
        },
        volunteer,
        owed: owed > 0,
    })
}

async fn claim_both(home: &Home) -> Result<String, String> {
    // Held for the whole claim, so a node cannot start mid-way (SA-2).
    let _lock = DaemonLock::acquire(home)?;
    let cfg = NodeConfig::load(home)?;
    let keys = PairKeys::load(home)?;
    let chain = Chain::new(cfg.network()?);
    let mut total = 0;
    let mut code = String::new();
    for kp in [&keys.own, &keys.partner] {
        let (got, c) = chain.claim(kp).await?;
        total += got;
        if !c.is_empty() {
            code = c;
        }
    }
    Ok(format!("claimed {} {code}", xlm(total)))
}

/// A sibling executable: next to this one, with the platform's suffix.
fn sibling(name: &str) -> Result<std::path::PathBuf, String> {
    let me = std::env::current_exe().map_err(|e| format!("locating kenter-node: {e}"))?;
    let dir = me.parent().ok_or("kenter-node has no directory")?;
    Ok(dir.join(format!("{name}{}", std::env::consts::EXE_SUFFIX)))
}

fn open_wallet() -> Result<(), String> {
    let wallet = sibling("kenter-ui")?;
    if !wallet.exists() {
        return Err("Kenter Wallet is not installed next to the node".into());
    }
    std::process::Command::new(&wallet)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("opening the wallet: {e}"))
}

fn open_settings() -> Result<(), String> {
    let me = std::env::current_exe().map_err(|e| format!("locating kenter-node: {e}"))?;
    std::process::Command::new(me)
        .arg("settings")
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("opening settings: {e}"))
}
