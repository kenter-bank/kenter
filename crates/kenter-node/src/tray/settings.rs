//! `kenter-node settings`: set a node up, and change it afterwards.
//! A separate, short-lived process with one egui window; the tray stays
//! windowless.
//!
//! **Setup** (no phrase yet): name, terms, relays, then create a new pair
//! or restore one. A new phrase is shown once and the window will not
//! finish until the operator confirms writing it down.
//!
//! **Edit**: the pair's addresses and what each needs; name, relays, RPC;
//! terms (volunteering is one-way and says so); start at login; the
//! recovery phrase behind a confirmation; and leaving the roster and
//! withdrawing the stake, which need the node paused.
//!
//! Saving writes `node.json` and drops `reload.request`, which a running
//! tray answers by restarting its node.

use std::sync::mpsc;

use eframe::egui::{self, Color32, RichText};
use zeroize::Zeroizing;

use crate::chain::{Chain, pair_funding_target, xlm};
use crate::config::{NodeConfig, Relay};
use crate::home::Home;
use crate::keys::{self, PairKeys};
use crate::status::DaemonLock;

use super::autostart;

pub fn run(home: Home) -> Result<(), String> {
    let app = SettingsApp::new(home);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Kenter node — Settings")
            .with_inner_size([560.0, 680.0]),
        ..Default::default()
    };
    eframe::run_native("Kenter node — Settings", options, Box::new(|_cc| Ok(Box::new(app))))
        .map_err(|e| format!("settings window: {e}"))
}

#[derive(PartialEq, Clone, Copy)]
enum Origin {
    Create,
    Restore,
}

enum Mode {
    Setup,
    /// A new phrase, shown once; finishing needs the backup confirmed.
    ShowNewPhrase(Zeroizing<String>),
    Edit,
}

struct SettingsApp {
    home: Home,
    mode: Mode,
    // Form fields.
    name: String,
    relays: String,
    insecure: bool,
    volunteer: bool,
    was_volunteer: bool,
    volunteer_ack: bool,
    rpc: String,
    origin: Origin,
    restore_phrase: Zeroizing<String>,
    backed_up: bool,
    autostart: bool,
    // Edit-mode extras.
    addresses: Option<[String; 2]>,
    need: Option<String>,
    phrase_shown: Option<Zeroizing<String>>,
    reveal_ok: bool,
    confirm_leave: bool,
    // Feedback.
    message: Option<(bool, String)>,
    /// A leave or withdraw in flight.
    pending: Option<mpsc::Receiver<Result<String, String>>>,
    /// The funding-target read in flight.
    need_rx: Option<mpsc::Receiver<Result<String, String>>>,
}

impl SettingsApp {
    fn new(home: Home) -> Self {
        let mut app = SettingsApp {
            home,
            mode: Mode::Setup,
            name: "kenter-node".into(),
            relays: crate::config::default_relays()
                .iter()
                .map(|r| r.host.clone())
                .collect::<Vec<_>>()
                .join("
"),
            insecure: false,
            volunteer: false,
            was_volunteer: false,
            volunteer_ack: false,
            rpc: String::new(),
            origin: Origin::Create,
            restore_phrase: Zeroizing::new(String::new()),
            backed_up: false,
            autostart: autostart::enabled(),
            addresses: None,
            need: None,
            phrase_shown: None,
            reveal_ok: false,
            confirm_leave: false,
            message: None,
            pending: None,
            need_rx: None,
        };
        if keys::has_pair(&app.home).unwrap_or(true) {
            app.load();
        }
        app
    }

    /// Fill the form from disk and switch to Edit.
    fn load(&mut self) {
        match NodeConfig::load(&self.home) {
            Ok(c) => {
                self.name = c.name.clone();
                self.relays = c.relays.iter().map(|r| r.host.clone()).collect::<Vec<_>>().join("\n");
                self.insecure = c.relays.iter().any(|r| !r.secure);
                self.volunteer = c.volunteer;
                self.was_volunteer = c.volunteer;
                self.rpc = c.rpc.clone().unwrap_or_default();
                self.backed_up = c.backup_confirmed;
            }
            Err(e) => self.message = Some((false, e)),
        }
        self.addresses = PairKeys::load(&self.home).ok().map(|k| k.addresses());
        self.mode = Mode::Edit;
        self.fetch_need();
    }

    /// The XLM each address needs to join, read in the background.
    fn fetch_need(&mut self) {
        let (Some([own, _]), Ok(cfg)) = (self.addresses.clone(), self.form_config()) else {
            return;
        };
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let r = block(async move {
                let net = cfg.network()?;
                let stake = Chain::new(net).min_stake(&own).await?;
                Ok(format!(
                    "Send {} XLM to this address. It covers both halves of the pair:                      the node funds its partner from it.",
                    xlm(pair_funding_target(stake, cfg.volunteer))
                ))
            });
            let _ = tx.send(r);
        });
        self.need_rx = Some(rx);
    }

    /// The saved config with the form's fields applied. Starting from what
    /// is on disk keeps the fields the form does not show (where the
    /// phrase is kept, a hand-set Horizon), so saving can never orphan a
    /// keystore entry.
    fn form_config(&self) -> Result<NodeConfig, String> {
        // An unreadable node.json is an error here, never a fresh config:
        // writing one would bury a keystore pair (SC-1).
        let mut c = NodeConfig::load_if_present(&self.home)?.unwrap_or_else(|| NodeConfig::new(&self.name));
        c.name = self.name.trim().to_string();
        c.relays = self
            .relays
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(|h| Relay { host: h.to_string(), secure: !self.insecure && !crate::config::is_loopback(h) })
            .collect();
        c.volunteer = self.volunteer;
        c.rpc = Some(self.rpc.trim().to_string()).filter(|s| !s.is_empty());
        c.backup_confirmed = self.backed_up;
        c.validate()?;
        Ok(c)
    }

    /// A new pair goes into the OS keystore when the build has one (the
    /// desktop default), else into its file.
    fn create(&mut self) {
        let result = (|| -> Result<Option<Zeroizing<String>>, String> {
            if keys::has_pair(&self.home)? {
                return Err("this install already has a pair".into());
            }
            let (phrase, new) = match self.origin {
                Origin::Create => (keys::new_phrase()?, true),
                Origin::Restore => (Zeroizing::new(self.restore_phrase.trim().to_string()), false),
            };
            PairKeys::from_phrase(&phrase)?;
            self.backed_up = !new;
            let mut cfg = self.form_config()?;
            if keys::os::supported() {
                keys::store_phrase_os(&mut cfg, &phrase)?;
                cfg.save(&self.home)?;
            } else {
                cfg.save(&self.home)?;
                keys::store_phrase(&self.home, &phrase)?;
            }
            self.restore_phrase = Zeroizing::new(String::new());
            Ok(new.then_some(phrase))
        })();
        match result {
            Ok(Some(phrase)) => self.mode = Mode::ShowNewPhrase(phrase),
            Ok(None) => {
                self.finish_setup();
            }
            Err(e) => self.message = Some((false, e)),
        }
    }

    fn finish_setup(&mut self) {
        self.load();
        reload(&self.home);
        self.message = Some((true, "Node set up. Fund both addresses below; the tray starts it.".into()));
    }

    fn save(&mut self) {
        let result = self.form_config().and_then(|c| c.save(&self.home));
        let auto = if autostart::supported() && self.autostart != autostart::enabled() {
            autostart::set(self.autostart)
        } else {
            Ok(())
        };
        self.message = Some(match (result, auto) {
            (Ok(()), Ok(())) => {
                reload(&self.home);
                self.was_volunteer = self.volunteer;
                self.volunteer_ack = false;
                (true, "Saved. The tray restarts the node with these settings.".into())
            }
            (Err(e), _) | (_, Err(e)) => (false, e),
        });
    }

    /// Move the phrase file into the OS keystore. Needs the node paused:
    /// the lock is held for the move.
    fn move_to_os(&mut self) {
        let result = DaemonLock::acquire(&self.home)
            .map_err(|e| {
                if e.contains("already running") {
                    "Pause the node from the tray first.".to_string()
                } else {
                    e
                }
            })
            .and_then(|_lock| keys::move_to_os(&self.home));
        self.message = Some(match result {
            Ok(()) => (true, "The phrase is in the OS keystore and its file is destroyed.".into()),
            Err(e) => (false, e),
        });
    }

    /// Destroy a phrase file left by an interrupted move (SC-2).
    fn wipe_leftover(&mut self) {
        let result = DaemonLock::acquire(&self.home)
            .map_err(|e| {
                if e.contains("already running") {
                    "Pause the node from the tray first.".to_string()
                } else {
                    e
                }
            })
            .and_then(|_lock| keys::wipe_leftover(&self.home));
        self.message = Some(match result {
            Ok(()) => (true, "The leftover phrase file has been destroyed.".into()),
            Err(e) => (false, e),
        });
    }

    /// Leave or withdraw, both addresses, in the background. Needs the
    /// node paused: the lock is held for the whole operation.
    fn roster_op(&mut self, withdraw: bool) {
        let home = self.home.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let r = block(async move {
                let _lock = DaemonLock::acquire(&home).map_err(|e| {
                    if e.contains("already running") {
                        "Pause the node from the tray first.".to_string()
                    } else {
                        e
                    }
                })?;
                let cfg = NodeConfig::load(&home)?;
                let keys = PairKeys::load(&home)?;
                let chain = Chain::new(cfg.network()?);
                let mut out = Vec::new();
                for kp in [&keys.own, &keys.partner] {
                    if withdraw {
                        match chain.view(kp).await?.node {
                            Some(n) if n.unbonding_at.is_some() => {
                                let got = chain.withdraw(kp).await?;
                                out.push(format!("{} XLM returned", xlm(got)));
                            }
                            Some(_) => return Err("Leave the roster first.".into()),
                            None => out.push("not on the roster".into()),
                        }
                    } else {
                        let at = chain.leave(kp).await?;
                        out.push(format!("withdrawable from ledger {at}"));
                    }
                }
                if withdraw {
                    // Gather the pair's XLM back on the node's own address.
                    match chain.sweep_partner(&keys.own, &keys.partner).await {
                        Ok(0) => {}
                        Ok(moved) => out.push(format!("{} XLM gathered from the partner", xlm(moved))),
                        Err(e) => out.push(format!("the partner's XLM stays there ({e})")),
                    }
                }
                Ok(out.join("; "))
            });
            let _ = tx.send(r);
        });
        self.pending = Some(rx);
        self.message = Some((true, "Working…".into()));
    }

    fn poll_pending(&mut self) {
        if let Some(r) = self.need_rx.as_ref().and_then(|rx| rx.try_recv().ok()) {
            self.need_rx = None;
            self.need = Some(r.unwrap_or_else(|e| format!("(could not read the stake: {e})")));
        }
        if let Some(r) = self.pending.as_ref().and_then(|rx| rx.try_recv().ok()) {
            self.pending = None;
            self.message = Some(match r {
                Ok(s) => (true, s),
                Err(e) => (false, e),
            });
        }
    }

    fn ui_common(&mut self, ui: &mut egui::Ui, setup: bool) {
        ui.label("Name (shown on the roster)");
        ui.text_edit_singleline(&mut self.name);
        ui.add_space(6.0);
        ui.label("Relays, one host per line, tried in order");
        ui.add(egui::TextEdit::multiline(&mut self.relays).desired_rows(3));
        ui.checkbox(&mut self.insecure, "Relays use plain ws:// (local development only)")
            .on_hover_text("A relay on this machine (127.0.0.1, localhost) always uses plain ws://.");
        ui.add_space(6.0);
        ui.label("RPC endpoint (blank: the build's default)");
        ui.text_edit_singleline(&mut self.rpc);
        ui.add_space(8.0);

        ui.label(RichText::new("Terms").strong());
        if self.was_volunteer && !setup {
            ui.label("Volunteer: this pair's fees are burned. Permanent for both addresses.");
            self.volunteer = true;
        } else {
            ui.radio_value(&mut self.volunteer, false, "Paid: fees are credited and claimable");
            ui.radio_value(&mut self.volunteer, true, "Volunteer: fees are burned");
            if self.volunteer {
                ui.label(
                    RichText::new(
                        "Volunteering is permanent for both addresses: leaving and \
                         rejoining does not undo it.",
                    )
                    .color(Color32::from_rgb(219, 140, 0)),
                );
                ui.checkbox(&mut self.volunteer_ack, "I understand");
            }
        }
    }

    fn volunteer_ok(&self) -> bool {
        volunteer_ok(self.volunteer, self.was_volunteer, self.volunteer_ack)
    }
}

/// May the form be submitted? Choosing to volunteer, which is permanent
/// for both addresses, needs the acknowledgement; keeping an existing
/// choice does not.
fn volunteer_ok(volunteer: bool, was_volunteer: bool, acknowledged: bool) -> bool {
    !volunteer || was_volunteer || acknowledged
}

impl eframe::App for SettingsApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_pending();
        if self.pending.is_some() || self.need_rx.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(250));
        }
        // Take what the arms need out of `self.mode` first, so they can
        // borrow `self` mutably.
        let new_phrase = match &self.mode {
            Mode::ShowNewPhrase(p) => Some(p.clone()),
            _ => None,
        };
        let editing = matches!(self.mode, Mode::Edit);
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                match (&new_phrase, editing) {
                    (None, false) => {
                        ui.heading("Set up this node");
                        ui.label(
                            "One install runs one pair: two keys from one recovery phrase. \
                             The phrase is the only way back to the stake.",
                        );
                        ui.add_space(8.0);
                        self.ui_common(ui, true);
                        ui.add_space(8.0);
                        ui.label(RichText::new("Keys").strong());
                        ui.radio_value(&mut self.origin, Origin::Create, "Create a new pair");
                        ui.radio_value(&mut self.origin, Origin::Restore, "Restore from a recovery phrase");
                        if self.origin == Origin::Restore {
                            ui.add(
                                egui::TextEdit::singleline(&mut *self.restore_phrase)
                                    .password(true)
                                    .hint_text("24 words"),
                            );
                        }
                        ui.add_space(10.0);
                        if ui.add_enabled(self.volunteer_ok(), egui::Button::new("Set up")).clicked() {
                            self.create();
                        }
                    }
                    (Some(phrase), _) => {
                        ui.heading("Your recovery phrase");
                        ui.label(
                            "Write these 24 words down, in order, and keep them offline. \
                             They restore both keys and with them the stake. Anyone who \
                             sees them can take it. They will not be shown again unless \
                             you ask in Settings.",
                        );
                        ui.add_space(8.0);
                        let words: Vec<&str> = phrase.split_whitespace().collect();
                        egui::Grid::new("words").num_columns(4).spacing([16.0, 6.0]).show(ui, |ui| {
                            for (i, w) in words.iter().enumerate() {
                                ui.monospace(format!("{:>2}. {w}", i + 1));
                                if i % 4 == 3 {
                                    ui.end_row();
                                }
                            }
                        });
                        ui.add_space(10.0);
                        ui.checkbox(&mut self.backed_up, "I have written down all 24 words");
                        if ui.add_enabled(self.backed_up, egui::Button::new("Done")).clicked() {
                            if let Ok(mut c) = NodeConfig::load(&self.home) {
                                c.backup_confirmed = true;
                                let _ = c.save(&self.home);
                            }
                            self.finish_setup();
                        }
                    }
                    (None, true) => {
                        ui.heading("Node settings");
                        if let Some([own, partner]) = self.addresses.clone() {
                            ui.add_space(4.0);
                            // One address to fund, with a
                            // QR code for a phone wallet.
                            ui.label(RichText::new("Fund the node").strong());
                            ui.horizontal(|ui| {
                                ui.monospace(&own);
                                if ui.small_button("Copy").clicked() {
                                    ui.ctx().copy_text(own.clone());
                                }
                            });
                            if let Some(n) = &self.need {
                                ui.label(n);
                            }
                            qr(ui, &own);
                            ui.label(
                                RichText::new(format!("Partner, funded by the node: {partner}"))
                                    .small()
                                    .weak(),
                            );
                        }
                        ui.add_space(8.0);
                        self.ui_common(ui, false);
                        ui.add_space(8.0);
                        if autostart::supported() {
                            ui.checkbox(&mut self.autostart, "Start the node when I log in");
                        }
                        ui.add_space(6.0);
                        if ui.add_enabled(self.volunteer_ok(), egui::Button::new("Save")).clicked() {
                            self.save();
                        }

                        ui.add_space(12.0);
                        ui.separator();
                        ui.label(RichText::new("Recovery phrase").strong());
                        let in_os = NodeConfig::load(&self.home)
                            .is_ok_and(|c| c.key_store == crate::config::KeyStore::Os);
                        if in_os {
                            ui.label("Kept in the OS keystore (protected by your login).");
                            if keys::leftover_file(&self.home) {
                                ui.label(
                                    RichText::new(format!(
                                        "{} is still on disk from an interrupted move.",
                                        self.home.phrase().display()
                                    ))
                                    .color(Color32::from_rgb(219, 140, 0)),
                                );
                                if ui
                                    .add_enabled(self.pending.is_none(), egui::Button::new("Destroy the leftover file"))
                                    .on_hover_text("Pause the node from the tray first. Only a file matching the keystore is destroyed.")
                                    .clicked()
                                {
                                    self.wipe_leftover();
                                }
                            }
                        } else {
                            ui.label(format!("Kept in {}", self.home.phrase().display()));
                            if keys::os::supported()
                                && ui
                                    .add_enabled(self.pending.is_none(), egui::Button::new("Move it into the OS keystore"))
                                    .on_hover_text("Pause the node from the tray first. The file is destroyed after the move.")
                                    .clicked()
                            {
                                self.move_to_os();
                            }
                        }
                        if !self.backed_up {
                            ui.label(
                                RichText::new("Not confirmed as backed up.")
                                    .color(Color32::from_rgb(219, 140, 0)),
                            );
                        }
                        match &self.phrase_shown {
                            None => {
                                // A deliberate second step: the phrase is
                                // the stake.
                                ui.checkbox(
                                    &mut self.reveal_ok,
                                    "Nobody else can see this screen",
                                );
                                if ui
                                    .add_enabled(self.reveal_ok, egui::Button::new("Show recovery phrase"))
                                    .clicked()
                                {
                                    self.reveal_ok = false;
                                    match keys::load_phrase(&self.home) {
                                        Ok(p) => self.phrase_shown = Some(p),
                                        Err(e) => self.message = Some((false, e)),
                                    }
                                }
                            }
                            Some(p) => {
                                ui.label("Anyone who sees this can take the stake.");
                                ui.monospace(p.as_str());
                                ui.horizontal(|ui| {
                                    if !self.backed_up && ui.button("I have written it down").clicked() {
                                        self.backed_up = true;
                                        if let Ok(mut c) = NodeConfig::load(&self.home) {
                                            c.backup_confirmed = true;
                                            let _ = c.save(&self.home);
                                        }
                                    }
                                    if ui.button("Hide").clicked() {
                                        self.phrase_shown = None;
                                    }
                                });
                            }
                        }

                        ui.add_space(12.0);
                        ui.separator();
                        ui.label(RichText::new("Selection for prints").strong());
                        match crate::status::DaemonStatus::read(&self.home) {
                            Some(st) if st.pair_registered => {
                                ui.label("This pair is registered with the mint and can be drawn for prints.");
                            }
                            Some(st) => {
                                ui.label(
                                    "This pair is on the roster but not yet registered with the mint,                                      so no print can choose it. The node retries every 30 seconds.",
                                );
                                if let Some(d) = st.detail.as_deref() {
                                    ui.label(RichText::new(d).weak());
                                }
                                if ui.button("Register now").clicked() {
                                    let _ = std::fs::write(self.home.register_request(), b"");
                                }
                            }
                            None => {
                                ui.label("Start the node to register it for prints.");
                            }
                        }

                        ui.add_space(12.0);
                        ui.separator();
                        ui.label(RichText::new("Leave the roster").strong());
                        ui.label(
                            "Pause the node from the tray first. Leaving starts the stake's \
                             unbonding (one week); withdraw it afterwards.",
                        );
                        ui.checkbox(&mut self.confirm_leave, "I want this pair to leave the roster");
                        ui.horizontal(|ui| {
                            let idle = self.pending.is_none();
                            if ui.add_enabled(idle && self.confirm_leave, egui::Button::new("Leave")).clicked() {
                                self.confirm_leave = false;
                                self.roster_op(false);
                            }
                            if ui.add_enabled(idle, egui::Button::new("Withdraw stake")).clicked() {
                                self.roster_op(true);
                            }
                        });
                    }
                }

                if let Some((ok, msg)) = &self.message {
                    ui.add_space(10.0);
                    let color = if *ok { Color32::from_rgb(46, 160, 67) } else { Color32::from_rgb(200, 40, 40) };
                    ui.label(RichText::new(msg).color(color));
                }
            });
        });
    }
}

fn reload(home: &Home) {
    let _ = std::fs::write(home.reload_request(), b"");
}

/// Run a future to completion on a throwaway runtime, off the UI thread.
fn block<T>(f: impl std::future::Future<Output = Result<T, String>>) -> Result<T, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?
        .block_on(f)
}

#[cfg(test)]
mod tests {
    use super::volunteer_ok;

    /// SB-5: choosing to volunteer needs the acknowledgement; staying paid,
    /// or keeping an earlier choice to volunteer, does not.
    #[test]
    fn volunteering_needs_the_acknowledgement() {
        assert!(volunteer_ok(false, false, false), "paid needs nothing");
        assert!(!volunteer_ok(true, false, false), "a new volunteer must acknowledge");
        assert!(volunteer_ok(true, false, true));
        assert!(volunteer_ok(true, true, false), "already volunteering");
    }
}

/// Draw `text` as a QR code: dark modules on a white field with the
/// standard four-module quiet zone, so a phone camera reads it on a dark
/// theme too. Plain address, no payment URI: every Stellar wallet scans an
/// address, and fewer agree on a URI scheme.
fn qr(ui: &mut egui::Ui, text: &str) {
    let Ok(code) = qrcode::QrCode::with_error_correction_level(text, qrcode::EcLevel::M) else {
        return;
    };
    let width = code.width();
    let quiet = 4;
    let cells = width + 2 * quiet;
    let module = 4.0_f32;
    let side = cells as f32 * module;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(side, side), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 0.0, Color32::WHITE);
    let colors = code.to_colors();
    for y in 0..width {
        for x in 0..width {
            if colors[y * width + x] == qrcode::Color::Dark {
                let min = rect.min + egui::vec2((x + quiet) as f32 * module, (y + quiet) as f32 * module);
                painter.rect_filled(egui::Rect::from_min_size(min, egui::vec2(module, module)), 0.0, Color32::BLACK);
            }
        }
    }
}
