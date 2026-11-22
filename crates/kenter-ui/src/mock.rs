//! Render one frame of the Kenter UI to a PNG — the fast visual-iteration loop.
//!
//! Run: `cargo run -p kenter-ui --bin kenter-ui-mock`  → writes `kenter-ui-mock.png`.
//! Restyle any file under `skins/kenter/` in Inkscape and re-run; no code changes.
//!
//! A screen name renders that page instead of the wallet, with sample content:
//! `wallet` (default), `wallet-open`, `locked`, `setup`, `phrase`, `done`, `deposit`, `pay`,
//! `receive`, `prompt`, `address`, `paid`, `failed`, `settings`. Only
//! the first is reachable without a vault, a passphrase, a payer and a ledger,
//! so the artist's loop needs a way to look at the rest. Second argument is a
//! hi-DPI scale.

use kenter_ui::{
    save_png, AccountView, DepositPreview, DepositState, DepositView, Interaction, LockedView,
    PayState, PayView, PayableRow, PromptView, ReceiveState, ReceiveView, Screen, SettingsView,
    SetupState, SetupView, Ui, WalletView, H, W,
};

/// A commitment that is not anybody's — it only has to make a plausible QR.
fn sample_commitment() -> [u8; 32] {
    let mut c = [0u8; 32];
    for (i, b) in c.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(11);
    }
    c
}

fn screen(name: &str) -> Screen {
    let c = sample_commitment();
    match name {
        "receive" => Screen::Receive(ReceiveView::idle("a seed is loaded; ready when you are")),
        "prompt" => Screen::Prompt {
            view: PromptView {
                title: "Create a pay tag".into(),
                why: "unlock your wallet to derive the key".into(),
                rows: vec![
                    ("owner index".into(), "7".into()),
                    (
                        "effect".into(),
                        "derives a fresh key; reveals nothing and moves nothing".into(),
                    ),
                ],
                entered: 9,
                error: None,
            },
            under: 1,
        },
        "locked" => Screen::Wallet(WalletView::locked()),
        // The card ceremony, up to the last screen before anything is
        // written.
        "card-intro" => Screen::Setup(SetupView {
            state: SetupState::CardIntro {
                card: "a new card, not set up yet - this will give it a PIN and a key".into(),
                blank: true,
            },
        }),
        "card-intro-used" => Screen::Setup(SetupView {
            state: SetupState::CardIntro {
                card: "a card is ready - applet 4.0".into(),
                blank: false,
            },
        }),
        // Not a real phrase, and it must not be: the mock renders to a PNG,
        // and a mock that writes a usable recovery phrase into an image file
        // is a mock that leaks one.
        "card-phrase" => Screen::Setup(SetupView {
            state: SetupState::CardPhrase {
                words: "alpha bravo charlie delta echo foxtrot golf hotel india juliet                         kilo lima mike november oscar papa quebec romeo sierra tango                         uniform victor whisky xray"
                    .split_whitespace()
                    .map(String::from)
                    .collect(),
                revealed: true,
            },
        }),
        "card-confirm" => Screen::Setup(SetupView {
            state: SetupState::CardConfirm {
                positions: vec![2, 12, 23],
                entered: 11,
                error: None,
            },
        }),
        "card-erase" => Screen::Setup(SetupView {
            state: SetupState::CardErase { confirmed: false, typed: "ERASE".into(), entered: 0, error: None },
        }),
        "card-erase-pin" => Screen::Setup(SetupView {
            state: SetupState::CardErase { confirmed: true, typed: String::new(), entered: 3, error: None },
        }),
        "card-pin" => Screen::Setup(SetupView {
            state: SetupState::CardPin { entered: 4, again: false, error: None },
        }),
        "card-pin-again" => Screen::Setup(SetupView {
            state: SetupState::CardPin {
                entered: 0,
                again: false,
                error: Some("those did not match - start again".into()),
            },
        }),
        "card-duress" => Screen::Setup(SetupView {
            state: SetupState::CardDuress { entered: 6, again: false, error: None },
        }),
        "card-puk" => Screen::Setup(SetupView {
            state: SetupState::CardPuk {
                // Not a real one: the mock renders to a PNG, and a PUK a
                // card actually holds has no business in an image file.
                puk: "4820 7391 5064".into(),
                entered: 0,
                confirming: false,
                error: None,
            },
        }),
        "card-puk-confirm" => Screen::Setup(SetupView {
            state: SetupState::CardPuk {
                puk: "482073915064".into(),
                entered: 7,
                confirming: true,
                error: None,
            },
        }),
        "setup" => Screen::Setup(SetupView { state: SetupState::Start }),
        // Rendered with a reader found and with none, because the two are
        // the screen's whole job: a holder must learn there is no card
        // before choosing the card, not after.
        "custody" => Screen::Setup(SetupView {
            state: SetupState::Custody {
                restoring: false,
                card: Some("a card is ready - applet 3.1".into()),
                card_ok: true,
                error: None,
            },
        }),
        "custody-no-card" => Screen::Setup(SetupView {
            state: SetupState::Custody {
                restoring: false,
                card: Some("no card reader found - plug one in and try again".into()),
                card_ok: false,
                error: None,
            },
        }),
        // The same screen asking the same question of someone who has
        // already answered it once and lost the card they answered it with.
        // Every line differs, so it is worth rendering on its own.
        "custody-restoring" => Screen::Setup(SetupView {
            state: SetupState::Custody {
                restoring: true,
                card: Some("a blank card is ready - applet 3.1".into()),
                card_ok: true,
                error: None,
            },
        }),
        // No note picker any more - Pay is reached from a note - so the
        // sample is the screen a bearer note actually lands on.
        "pay" => Screen::Pay(PayView {
            state: PayState::Export {
                row: PayableRow {
                    id: "a".into(),
                    short_id: "GD7MDB\u{2026}CLHR".into(),
                    amount: "$25.0000000".into(),
                    spend_mode: false,
                    exposure: 1,
                },
                written: None,
                error: None,
            },
        }),
        "deposit" => Screen::Deposit(DepositView {
            state: DepositState::Form {
                entered: 3,
                preview: Some(DepositPreview {
                    face: "2.5000000".into(),
                    redeems_for: "$2.4994000".into(),
                    fee: "$0.0006000".into(),
                }),
                spend: false,
                pairs: 3,
                printer: "1 node via 127.0.0.1:8000 - plus you at both ends".into(),
                error: None,
            },
        }),
        "phrase" => Screen::Setup(SetupView {
            state: SetupState::Phrase {
                // Not a real phrase, and it does not need to be - this is the
                // artist's loop, and a mock that renders a usable recovery
                // phrase is a mock that leaks one into a PNG.
                words: "alpha bravo charlie delta echo foxtrot golf hotel india juliet                         kilo lima mike november oscar papa quebec romeo sierra tango                         uniform victor whisky xray"
                    .split_whitespace()
                    .map(String::from)
                    .collect(),
                revealed: true,
            },
        }),
        "done" => Screen::Setup(SetupView {
            state: SetupState::Activate {
                address: "GDCBN2MNAYTRPSFLXHLUNO4BMGYN3UIGLW2T3JPIOAUX5VENSTTIDSVP".into(),
                copied: false,
                funded: false,
                trustline_needed: None,
                busy: None,
                error: None,
            },
        }),
        "activated" => Screen::Setup(SetupView {
            state: SetupState::Activate {
                address: "GDCBN2MNAYTRPSFLXHLUNO4BMGYN3UIGLW2T3JPIOAUX5VENSTTIDSVP".into(),
                copied: false,
                funded: true,
                trustline_needed: Some("USDC".into()),
                busy: None,
                error: None,
            },
        }),
        "address" => Screen::Receive(ReceiveView {
            state: ReceiveState::Ready {
                uri: kenter_wallet::receive_uri(&c),
                hex: hex::encode(c),
                index: 7,
                status: "watching for a token file (3)".into(),
                ledger: "https://soroban-testnet.stellar.org".into(),
                inbox: r"C:\Users\someone\.kenter\wallet\inbox".into(),
                note: None,
            },
        }),
        // Re-reading the ledger with figures already in hand. This is what
        // every visit to the page looks like for its first few seconds, and
        // rendered with `..Default::default()` it would show all six rows
        // present and every value blank.
        "account-busy" => Screen::Account(AccountView {
            address: "GDCBN2MNAYTRPSFLXHLUNO4BMGYN3UIGLW2T3JPIOAUX5VENSTTIDSVP".into(),
            xlm: "XLM 9.9999800".into(),
            xlm_spendable: "XLM 8.4999800".into(),
            asset_code: "USDC".into(),
            asset_balance: "USDC 42.5000000".into(),
            trustline: Some(true),
            busy: Some("reading the ledger".into()),
            ..Default::default()
        }),
        // The same arrival before the cache existed, for comparison.
        "account-blank" => Screen::Account(AccountView {
            address: "GDCBN2MNAYTRPSFLXHLUNO4BMGYN3UIGLW2T3JPIOAUX5VENSTTIDSVP".into(),
            busy: Some("reading the ledger".into()),
            ..Default::default()
        }),
        // The gate, as the app opens. ("locked" above is the locked
        // billfold, which `load_view(None)` can still produce.)
        "gate" => Screen::Locked(LockedView::default()),
        // A card wallet whose card is gone, and the way out of it.
        "gate-nocard" => Screen::Locked(LockedView {
            card: Some(kenter_ui::CardGate {
                hint: "a reader, but no card in it - place your card on it".into(),
                ready: false,
            }),
            ..Default::default()
        }),
        "reset" => Screen::Reset(kenter_ui::ResetView {
            archive: r"C:\Users\someone\.kenter\reset-1763190000".into(),
            moving: vec!["vault.json".into(), "wallet".into(), "kenter-backup-da7e4098.kbk".into()],
            backups: vec!["kenter-backup-da7e4098.kbk".into()],
            typed: "RES".into(),
            error: None,
        }),
        "gate-typed" => Screen::Locked(LockedView { entered: 14, ..Default::default() }),
        "gate-busy" => Screen::Locked(LockedView {
            entered: 14,
            busy: true,
            ..Default::default()
        }),
        "gate-wrong" => Screen::Locked(LockedView {
            error: Some("that passphrase did not open the store".into()),
            ..Default::default()
        }),
        // The indeterminate bar. A still PNG cannot show motion, so the
        // third argument picks the frame - render a few and flip through
        // them to judge the loop.
        "working" => Screen::Receive(ReceiveView {
            state: ReceiveState::Working { what: "opening the billfold".into() },
        }),
        "paid" => Screen::Receive(ReceiveView {
            state: ReceiveState::Received {
                id: "GD7MDB\u{2026}CLHR".into(),
                amount: "$2.5000000".into(),
                index: 7,
            },
        }),
        // The real message, not a short stand-in: this is the failure a new
        // install actually hits, and it is the longest text the page renders.
        // Sample rows rather than `settings::local`, which reads the real
        // machine - the artist's loop should render the same picture on any.
        // The RPC server field, open, with a refusal showing.
        "settings-rpc" => Screen::Settings(SettingsView {
            rpc_edit: Some(kenter_ui::RpcEdit {
                typed: "https://soroban-testnet.stellar.org".into(),
                error: Some(
                    "soroban-testnet.stellar.org serves \"Test SDF Network ; September 2015\",                      not mainnet".into(),
                ),
                busy: false,
                network: "mainnet".into(),
            }),
            ..Default::default()
        }),
        "settings" => Screen::Settings(SettingsView {
            rows: vec![
                ("wallet", r"C:\Users\someone\.kenter\wallet"),
                ("inbox", r"C:\Users\someone\.kenter\wallet\inbox"),
                ("vault", r"C:\Users\someone\.kenter\vault.json"),
                ("recovery seed", "present - owner keys derive from it"),
                (
                    "submitting account",
                    "slot 0 - GDCBN2MNAYTRPSFLXHLUNO4BMGYN3UIGLW2T3JPIOAUX5VENSTTIDSVP",
                ),
                ("network", "https://soroban-testnet.stellar.org"),
                ("mint contract", "CAYBAC252RAE7UWVRCVII2POV6DDCZ7YUFW64ERQ7HP6E2B7OTDSVOA7"),
                ("account status", "funded - this client can submit transactions"),
                ("escrow asset", "USDC - notes are a claim on this"),
                ("trustline", "missing - add one for USDC, or a redemption cannot pay you"),
                ("backup", "2 of 5 notes - last saved 11 days ago"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            note: None,
            trustline_needed: Some("USDC".into()),
            backup: Some(("2 of 5 notes - last saved 11 days ago".into(), true)),
            rpc_edit: None,
        }),
        "failed" => Screen::Receive(ReceiveView::failed(
            r"C:\Users\someone\.kenter\vault.json holds no seed - owner keys derive from one, so add it with: kenter seed generate --vault C:\Users\someone\.kenter\vault.json",
        )),
        // A note opened, so the verbs on the card are visible to the eye
        // that has to style them.
        "wallet-open" => Screen::Wallet(WalletView { expanded: Some(0), ..WalletView::sample() }),
        _ => Screen::Wallet(WalletView::sample()),
    }
}

fn main() {
    let name = std::env::args().nth(1).unwrap_or_else(|| "wallet".into());
    let scale: f32 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1.0);
    let frame: u32 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let (pw, ph) = ((W as f32 * scale) as u32, (H as f32 * scale) as u32);

    let ui = Ui::build_screen(&screen(&name));

    // Cold: rasterizes every element. Warm: all layers served from cache — this
    // is what a hover redraw costs (only the changed element misses the cache).
    let it = Interaction {
        frame,
        ..Default::default()
    };
    let t0 = std::time::Instant::now();
    let canvas = ui.render_scaled(&it, pw, ph);
    let cold = t0.elapsed();
    let t1 = std::time::Instant::now();
    let _ = ui.render_scaled(&it, pw, ph);
    let warm = t1.elapsed();

    // Frame in the filename, so a filmstrip does not overwrite itself.
    let suffix = if ui.has_animation() {
        format!("{name}-f{frame}")
    } else {
        name.clone()
    };
    let out = format!("{}/kenter-ui-mock-{suffix}.png", env!("CARGO_MANIFEST_DIR"));
    save_png(&canvas, pw, ph, &out).expect("write png");
    println!("wrote {out} ({pw}x{ph})  cold={cold:?} warm={warm:?}");
}
