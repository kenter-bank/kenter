//! Asking a human to authorize a signature.
//!
//! Every vault operation already takes a `credential` — a passphrase for
//! [`SoftVault`](kenter_vault::SoftVault), a PIN for a card. What the vault
//! traits do *not* say is where that credential comes from or how often a human
//! is asked for it, and that question is the whole difference between the two
//! security tiers. This module is that seam.
//!
//! ## A prompt is handed an action, not asked for a password
//!
//! [`Prompter::prompt`] receives an [`AuthAction`] and cannot be implemented as
//! a bare password box, because a box that only asks for a passphrase proves
//! that *someone is present*, not that they consent to **this** transfer. The
//! action carries [`AuthAction::summary`] and [`AuthAction::rows`] precisely so
//! a shell has the text to show, and so a new kind of signature cannot be added
//! without someone writing down what it says to the holder — [`AuthAction`] is
//! deliberately **not** `#[non_exhaustive]`, so adding a variant breaks every
//! shell until it does.
//!
//! What the holder is shown still depends on the display showing the truth. A
//! Keycard Shell has its own screen, which a compromised host cannot lie
//! through; a bare card in a desktop reader is read through the host, so the
//! host could show one thing and send another. Weaker, and worth saying out
//! loud rather than letting the two look equivalent.
//!
//! ## Two tiers
//!
//! - [`Policy::Session`] — the standard. One unlock covers the session. The
//!   passphrase's two jobs come apart here: at rest it encrypts the vault, and
//!   at signing time it is meant to prove intent. Caching keeps the first and
//!   gives up the second, which is a real loss, but a per-signature passphrase
//!   is unusable and unusable controls get worked around.
//! - [`Policy::PerAction`] — maximum security. Every value-moving action is
//!   proved again. On software custody that means retyping, which most people
//!   will not accept; with a card it is a tap, which is both low-friction and a
//!   genuine intent proof — something a passphrase cannot be at the same time.
//!   Note that a cached PIN is still cached under this policy: the tap is the
//!   proof, not the PIN.
//!
//! Which actions count as "meaningful" is [`AuthAction::moves_value`], not a
//! list in the shell, so the two desktop surfaces and the PWA cannot disagree
//! about which operations are allowed to go unprompted.

use zeroize::Zeroizing;

use crate::error::{Result, WalletError};
use crate::models::fmt_stroops;

/// What is about to be signed, in terms the holder can check against what they
/// believe they are doing.
///
/// Not `#[non_exhaustive]` on purpose: see the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthAction {
    /// Derive a fresh owner key and show its commitment to a payer.
    Receive { index: u32 },

    /// Move a token's owner pointer to someone else. Irreversible.
    Spend {
        token_id: String,
        amount: u64,
        to_commitment: [u8; 32],
    },

    /// Burn a token and pay its escrow out to a Stellar account. Irreversible,
    /// against an immutable adminless mint: there is no clawback.
    Redeem {
        token_id: String,
        amount: u64,
        to_account: String,
    },

    /// Seal or open an encrypted token backup.
    Backup { seal: bool },
}

impl AuthAction {
    /// One line naming what is being authorized.
    pub fn summary(&self) -> String {
        match self {
            AuthAction::Receive { .. } => "Create a pay tag".into(),
            AuthAction::Spend { amount, .. } => {
                format!("Pay away {}", fmt_stroops(*amount))
            }
            AuthAction::Redeem { amount, .. } => {
                format!("Redeem {}", fmt_stroops(*amount))
            }
            AuthAction::Backup { seal: true } => "Export an encrypted backup".into(),
            AuthAction::Backup { seal: false } => "Restore from a backup".into(),
        }
    }

    /// The fields a prompt must show, so the holder can check them. A shell may
    /// lay them out how it likes, but it may not decide to show none of them.
    pub fn rows(&self) -> Vec<(&'static str, String)> {
        match self {
            AuthAction::Receive { index } => vec![
                ("owner index", index.to_string()),
                (
                    "effect",
                    "derives a fresh key; reveals nothing and moves nothing".into(),
                ),
            ],
            AuthAction::Spend {
                token_id,
                amount,
                to_commitment,
            } => vec![
                ("amount", fmt_stroops(*amount)),
                ("token", token_id.clone()),
                ("to", hex::encode(to_commitment)),
                ("effect", "the new owner can spend it; you cannot".into()),
            ],
            AuthAction::Redeem {
                token_id,
                amount,
                to_account,
            } => vec![
                ("amount", fmt_stroops(*amount)),
                ("token", token_id.clone()),
                ("to account", to_account.clone()),
                ("effect", "the token is burned; this cannot be undone".into()),
            ],
            AuthAction::Backup { seal: true } => vec![(
                "effect",
                "writes your tokens to a file, encrypted under your seed".into(),
            )],
            AuthAction::Backup { seal: false } => {
                vec![("effect", "reads tokens back from a backup file".into())]
            }
        }
    }

    /// Whether this is a "meaningful action" in the sense [`Policy::PerAction`]
    /// uses: does authorizing it move, or let someone else move, value?
    ///
    /// Receiving does not — it derives a public key, which reveals nothing and
    /// risks nothing, so prompting for it would spend the holder's patience on
    /// the one step where nothing can go wrong. Sealing a backup does: the blob
    /// is useless without the seed, but a backup file plus a recovery phrase is
    /// exactly the pair an attacker wants, and writing one out is a deliberate
    /// act worth confirming.
    pub fn moves_value(&self) -> bool {
        match self {
            AuthAction::Receive { .. } => false,
            AuthAction::Spend { .. } | AuthAction::Redeem { .. } => true,
            AuthAction::Backup { seal } => *seal,
        }
    }
}

/// Why the holder is being asked right now. Shells show different wording for
/// each: "unlock your wallet" is not the same sentence as "confirm this
/// payment", and "that passphrase was wrong" must not look like either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// Nothing is unlocked yet.
    Unlock,
    /// Already unlocked, but this action needs its own proof of intent.
    PerAction,
    /// The vault rejected what was given last time.
    Retry,
}

/// A granted authorization: the credential to hand the vault, and nothing else.
///
/// Owning the bytes rather than borrowing them is what makes
/// [`Policy::PerAction`] mean anything — the credential dies with the value at
/// the end of the operation instead of living in the authorizer.
pub struct Authorization(Zeroizing<Vec<u8>>);

impl Authorization {
    pub fn new(credential: Zeroizing<Vec<u8>>) -> Self {
        Authorization(credential)
    }

    /// The credential to pass to [`KeyVault`](kenter_vault::KeyVault) /
    /// [`DerivingVault`](kenter_vault::DerivingVault).
    pub fn credential(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Authorization {
    /// Never prints the credential. An authorization lands in error paths and
    /// log lines, and a `#[derive(Debug)]` here would eventually put a
    /// passphrase in a crash report.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Authorization(<{} bytes>)", self.0.len())
    }
}

/// How much proof of intent each action needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Policy {
    /// One unlock covers the session. The standard setting.
    #[default]
    Session,
    /// Every value-moving action is proved again. The maximum-security setting,
    /// intended for card custody where the proof is a tap.
    PerAction,
}

/// What a shell supplies: it shows the request and returns what the human gave.
///
/// Async because every real implementation waits on a person — a modal in the
/// GUI event loop, a prompt on a terminal, a card presented to a reader.
#[allow(async_fn_in_trait)]
pub trait Prompter {
    /// Show `action` and collect the credential.
    ///
    /// Return [`WalletError::Declined`] when the holder refuses or dismisses the
    /// prompt. That is a decision, not a failure, and callers must treat it as a
    /// clean stop rather than something to retry.
    async fn prompt(&mut self, action: &AuthAction, why: Why) -> Result<Zeroizing<Vec<u8>>>;
}

/// Obtain the credential for an action, under some policy.
#[allow(async_fn_in_trait)]
pub trait Authorizer {
    async fn authorize(&mut self, action: &AuthAction) -> Result<Authorization>;

    /// Forget anything cached. Call this when the session ends, when the wallet
    /// is locked by hand, and on any path where the holder should have to prove
    /// themselves again.
    fn lock(&mut self);

    /// The vault rejected the last credential: forget it, and make the next
    /// prompt say so rather than silently asking again.
    fn rejected(&mut self);
}

/// The two-tier authorizer: [`Policy::Session`] or [`Policy::PerAction`] over
/// any [`Prompter`].
pub struct SessionAuthorizer<P> {
    prompter: P,
    policy: Policy,
    held: Option<Zeroizing<Vec<u8>>>,
    last_rejected: bool,
}

impl<P: Prompter> SessionAuthorizer<P> {
    pub fn new(prompter: P, policy: Policy) -> Self {
        SessionAuthorizer {
            prompter,
            policy,
            held: None,
            last_rejected: false,
        }
    }

    pub fn policy(&self) -> Policy {
        self.policy
    }

    /// Change tier at runtime. Switching *to* [`Policy::PerAction`] does not
    /// clear the cached credential: under that policy the cache is simply not
    /// consulted for anything that moves value, and dropping it would force an
    /// unlock for operations that never needed one.
    pub fn set_policy(&mut self, policy: Policy) {
        self.policy = policy;
    }

    /// Take the prompter back. For tests that inspect what was asked, and for
    /// a shell that needs its prompt handle returned when the flow ends.
    pub fn into_prompter(self) -> P {
        self.prompter
    }

    /// Whether a credential is currently cached — for a lock indicator in the
    /// UI. Says nothing about what it is.
    pub fn is_unlocked(&self) -> bool {
        self.held.is_some()
    }
}

impl<P: Prompter> Authorizer for SessionAuthorizer<P> {
    async fn authorize(&mut self, action: &AuthAction) -> Result<Authorization> {
        let per_action = self.policy == Policy::PerAction && action.moves_value();

        if !per_action {
            if let Some(held) = &self.held {
                return Ok(Authorization::new(held.clone()));
            }
        }

        let why = if self.last_rejected {
            Why::Retry
        } else if per_action {
            Why::PerAction
        } else {
            Why::Unlock
        };
        let credential = self.prompter.prompt(action, why).await?;
        self.last_rejected = false;

        // Cache even under PerAction: a later Receive should not need a prompt
        // just because the last thing authorized was a payment.
        self.held = Some(credential.clone());
        Ok(Authorization::new(credential))
    }

    fn lock(&mut self) {
        self.held = None;
        self.last_rejected = false;
    }

    fn rejected(&mut self) {
        self.held = None;
        self.last_rejected = true;
    }
}

/// An authorizer over a credential obtained some other way — the CLI's own
/// terminal prompt, or a test.
///
/// It exists so a shell that already asks for a passphrase can adopt the port
/// without changing its behaviour, and so the core's call sites can take an
/// [`Authorizer`] everywhere instead of an `&[u8]` in some places and a port in
/// others. It never prompts, so [`Policy::PerAction`] has no meaning for it.
pub struct PreAuthorized(Zeroizing<Vec<u8>>);

impl PreAuthorized {
    pub fn new(credential: impl Into<Vec<u8>>) -> Self {
        PreAuthorized(Zeroizing::new(credential.into()))
    }
}

impl Authorizer for PreAuthorized {
    async fn authorize(&mut self, _action: &AuthAction) -> Result<Authorization> {
        Ok(Authorization::new(self.0.clone()))
    }

    fn lock(&mut self) {
        self.0 = Zeroizing::new(Vec::new());
    }

    /// Nothing to re-ask: the credential came from somewhere this type cannot
    /// reach. Clearing it turns the next attempt into a clean failure rather
    /// than a second try with the same wrong bytes.
    fn rejected(&mut self) {
        self.lock();
    }
}

/// An authorizer that always refuses — the honest stand-in for a shell with no
/// prompt wired up yet. A screen that cannot ask must not sign.
pub struct NoAuthorizer;

impl Authorizer for NoAuthorizer {
    async fn authorize(&mut self, _action: &AuthAction) -> Result<Authorization> {
        Err(WalletError::PromptFailed(
            "no authorization prompt is available in this shell".into(),
        ))
    }
    fn lock(&mut self) {}
    fn rejected(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counts prompts and records what it was shown.
    #[derive(Default)]
    struct Spy {
        seen: Vec<(String, Why)>,
        answer: Vec<u8>,
        decline: bool,
    }

    impl Prompter for Spy {
        async fn prompt(&mut self, action: &AuthAction, why: Why) -> Result<Zeroizing<Vec<u8>>> {
            self.seen.push((action.summary(), why));
            if self.decline {
                return Err(WalletError::Declined);
            }
            Ok(Zeroizing::new(self.answer.clone()))
        }
    }

    fn spend() -> AuthAction {
        AuthAction::Spend {
            token_id: "GD7MDB".into(),
            amount: 25_000_000,
            to_commitment: [7u8; 32],
        }
    }

    fn receive() -> AuthAction {
        AuthAction::Receive { index: 3 }
    }

    #[test]
    fn session_policy_prompts_once_for_everything() {
        let spy = Spy {
            answer: b"hunter2".to_vec(),
            ..Default::default()
        };
        let mut a = SessionAuthorizer::new(spy, Policy::Session);
        pollster::block_on(async {
            assert_eq!(a.authorize(&receive()).await.unwrap().credential(), b"hunter2");
            a.authorize(&spend()).await.unwrap();
            a.authorize(&spend()).await.unwrap();
        });
        assert_eq!(a.prompter.seen.len(), 1);
        assert_eq!(a.prompter.seen[0].1, Why::Unlock);
    }

    #[test]
    fn per_action_policy_prompts_for_every_value_moving_action() {
        let spy = Spy {
            answer: b"hunter2".to_vec(),
            ..Default::default()
        };
        let mut a = SessionAuthorizer::new(spy, Policy::PerAction);
        pollster::block_on(async {
            a.authorize(&spend()).await.unwrap();
            a.authorize(&spend()).await.unwrap();
            // Receiving moves nothing, so the cached credential covers it.
            a.authorize(&receive()).await.unwrap();
        });
        // Both payments read as confirmations, including the first. Under this
        // policy a value-moving action is never "just unlocking", even when
        // nothing is unlocked yet - what is being asked for is consent to the
        // payment, and the wording should say so. `Why::Unlock` reaches a
        // PerAction shell only for an action that moves nothing.
        let whys: Vec<Why> = a.prompter.seen.iter().map(|(_, w)| *w).collect();
        assert_eq!(whys, vec![Why::PerAction, Why::PerAction]);
    }

    #[test]
    fn per_action_policy_still_unlocks_plainly_for_a_harmless_action() {
        let spy = Spy { answer: b"hunter2".to_vec(), ..Default::default() };
        let mut a = SessionAuthorizer::new(spy, Policy::PerAction);
        pollster::block_on(a.authorize(&receive())).unwrap();
        assert_eq!(a.prompter.seen[0].1, Why::Unlock);
    }

    #[test]
    fn a_rejected_credential_is_dropped_and_the_next_prompt_says_so() {
        let spy = Spy {
            answer: b"wrong".to_vec(),
            ..Default::default()
        };
        let mut a = SessionAuthorizer::new(spy, Policy::Session);
        pollster::block_on(async {
            a.authorize(&spend()).await.unwrap();
            a.rejected();
            assert!(!a.is_unlocked());
            a.authorize(&spend()).await.unwrap();
        });
        assert_eq!(a.prompter.seen.len(), 2);
        assert_eq!(a.prompter.seen[1].1, Why::Retry);
    }

    #[test]
    fn declining_stops_the_operation_and_leaves_nothing_unlocked() {
        let spy = Spy {
            decline: true,
            ..Default::default()
        };
        let mut a = SessionAuthorizer::new(spy, Policy::Session);
        let err = pollster::block_on(a.authorize(&spend())).unwrap_err();
        assert!(matches!(err, WalletError::Declined));
        assert!(!a.is_unlocked());
    }

    #[test]
    fn locking_forces_a_fresh_unlock() {
        let spy = Spy {
            answer: b"hunter2".to_vec(),
            ..Default::default()
        };
        let mut a = SessionAuthorizer::new(spy, Policy::Session);
        pollster::block_on(async {
            a.authorize(&spend()).await.unwrap();
            a.lock();
            a.authorize(&spend()).await.unwrap();
        });
        let whys: Vec<Why> = a.prompter.seen.iter().map(|(_, w)| *w).collect();
        assert_eq!(whys, vec![Why::Unlock, Why::Unlock]);
    }

    /// Every action must give a shell something to show. A variant added with
    /// no rows would silently become a prompt that asks for a passphrase and
    /// says nothing about what it signs.
    #[test]
    fn every_action_describes_itself() {
        let actions = [
            receive(),
            spend(),
            AuthAction::Redeem {
                token_id: "GD7MDB".into(),
                amount: 1,
                to_account: "GABC".into(),
            },
            AuthAction::Backup { seal: true },
            AuthAction::Backup { seal: false },
        ];
        for a in actions {
            assert!(!a.summary().is_empty(), "{a:?} has no summary");
            assert!(!a.rows().is_empty(), "{a:?} has no rows");
        }
    }

    #[test]
    fn a_debug_print_of_an_authorization_does_not_contain_the_credential() {
        let a = Authorization::new(Zeroizing::new(b"hunter2".to_vec()));
        assert!(!format!("{a:?}").contains("hunter2"));
    }

    #[test]
    fn no_authorizer_refuses_rather_than_signing_unprompted() {
        let err = pollster::block_on(NoAuthorizer.authorize(&spend())).unwrap_err();
        assert!(matches!(err, WalletError::PromptFailed(_)));
    }
}
