//! # kenter-wallet
//!
//! The **wallet core** shared by the desktop and PWA shells — the token store
//! model, on-chain reconciliation, and read-only flow orchestration. It depends
//! only on wasm-safe crates (`kenter-crypto`, `kenter-vault`) and on **port
//! traits** ([`ChainRead`], [`Store`]) that each shell implements with its own
//! engine (native `kenter-client` + filesystem, or browser `fetch` + IndexedDB).
//! This crate never touches a socket, a file, or a card reader — that is what
//! keeps it compilable to `wasm32` for the PWA. See this crate's
//! `ARCHITECTURE.md`.
//!
//! **Authorization is a port too** ([`Authorizer`], `authz`). Every vault call
//! takes a credential; where that credential comes from and how often a human
//! is asked for it is the difference between the standard tier (one session
//! unlock) and the maximum-security tier (a card tap per value-moving action),
//! and it lives here so both shells answer it the same way. A [`Prompter`] is
//! handed a described [`AuthAction`], never just asked for a password, so
//! the holder can check what they are signing.
//!
//! **Custody is pluggable** via the `kenter-vault` ports: [`KeyVault`] for
//! Stellar account keys and [`DerivingVault`] for HD-derived spend-mode owner
//! keys (`docs/architecture/custody.md`). Software ([`SoftVault`]) on both
//! targets, hardware Keycard (native, in `stellar-keycard`) behind the same
//! traits.
//!
//! **The vault is threaded through the core** (`TokenWallet<C, S, V>`), not left
//! to the shell. The receive gates (G1–G4) and the owner-authorization
//! digest rule (`docs/architecture/spend-mode.md`) are protocol: a client
//! that skips a gate or signs the wrong bytes is unsafe, not merely
//! inconvenient. Implementing them
//! once here is what stops the PWA and the desktop drifting apart on exactly the
//! checks that decide whether someone has been paid. A wallet built with
//! [`TokenWallet::new`] has no vault ([`NoVault`]) and simply does not have those
//! operations — a compile error, not a runtime one.
//!
//! **Kenter has no balance query.** A holder's balance is the sum of the bearer
//! tokens they hold ([`HeldToken`]), each reconciled against its on-chain
//! [`TokenStatus`]. So the wallet persists tokens locally and reads the chain only
//! to learn status — see [`TokenWallet::balance`].
//!
//! ```no_run
//! # use kenter_wallet::{TokenWallet, MemoryStore, ports::ChainRead};
//! # async fn demo<C: ChainRead>(chain: C) -> kenter_wallet::Result<()> {
//! # let received_bytes: Vec<u8> = Vec::new();
//! let mut wallet = TokenWallet::new(chain, MemoryStore::new());
//! wallet.import(received_bytes, 1_720_000_000).await?; // verifies offline, stores
//! let balance = wallet.balance().await?;               // reconciles vs chain
//! # let _ = balance;
//! # Ok(()) }
//! ```

pub mod authz;
pub mod backup;
pub mod error;
#[cfg(feature = "fs")]
pub mod fsstore;
pub mod models;
pub mod owner;
/// A backup on paper: the same file, as QR symbols.
pub mod paper;
pub mod ports;
pub mod sealed;
pub mod store;
/// Real notes for tests and demos. See the module docs for what they are
/// and are not.
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod uri;
pub mod wallet;

pub use authz::{
    AuthAction, Authorization, Authorizer, NoAuthorizer, Policy, PreAuthorized, Prompter,
    SessionAuthorizer, Why,
};
pub use error::{Gate, Result, WalletError};
pub use models::{
    fmt_amount, fmt_stroops, ExportKind, ExportLog, DEFAULT_SYMBOL, Balance, HeldToken, OnChainToken, PendingReceive, ReconciledToken, SyncReport,
    KnownOwner, TokenStatus, FIRST_FRESH_INDEX, STATIC_RECEIVE_INDEX, note_id, short_note_id,
};
pub use ports::{ChainRead, Store, StoreGuard};
pub use sealed::{is_sealed, record_name, seal, unseal};
pub use store::MemoryStore;
pub use uri::{parse_receive_uri, receive_uri};
#[cfg(feature = "fs")]
pub use fsstore::FileStore;
pub use wallet::{NoVault, OwnershipReport, TokenWallet};

/// Re-export the custody traits so shells can name the vault ports from one place.
pub use kenter_vault::{DerivingVault, KeyVault, StoreCredentials};
