//! One vault type for a client that supports two custodies.
//!
//! `TokenWallet<C, S, V>` is already generic over `V: DerivingVault`, and
//! both backends implement it — so the only thing that ever tied the GUI to
//! software custody was `GuiWallet`'s alias naming `SoftVault` concretely.
//!
//! Making every caller generic instead would push a type parameter through
//! the whole client for a choice made once at startup. An enum keeps the
//! dispatch in one file, at the cost of two forwarding arms.
//!
//! **What the credential means differs by arm**, and callers do not need to
//! care: it is the passphrase for a software wallet and the PIN for a card.
//! Both are "the secret that authorises an owner-key operation", which is
//! the only property `DerivingVault` depends on.

use kenter_vault::{
    BackupCredentials, Custody, DerivingVault, Result, SoftVault, StoreCredentials,
};
use stellar_keycard::{StellarKeycard, Transport};

/// The store and backup keys for a session, derived the way this wallet's
/// custody says.
///
/// One function because the choice is easy to get wrong and silent when it
/// is: both derivations take the same arguments, return the same types, and
/// succeed. The only symptom of picking the wrong one is a store that will
/// not open and a backup that claims to belong to someone else.
///
/// [`Custody::Card`] is absent on purpose. A card derives these on the card,
/// through `card_setup::unlock`, and a `SoftVault` for a card wallet holds
/// no seed to derive from.
pub fn session_credentials(
    soft: &mut SoftVault,
    custody: Option<&Custody>,
    credential: &[u8],
) -> Result<(StoreCredentials, BackupCredentials)> {
    match custody {
        // The card's own derivation, run off-card from the recovered seed.
        Some(Custody::RecoveredCard { .. }) => {
            kenter_vault::vault_bound_credentials(soft, credential)
        }
        _ => Ok((
            soft.store_credentials(credential)?,
            soft.backup_credentials(credential)?,
        )),
    }
}

/// The vault behind whichever custody this installation uses.
pub enum GuiVault {
    /// Seed in the vault file, behind a passphrase.
    Soft(SoftVault),
    /// Seed on a card, behind a PIN.
    Card(Box<StellarKeycard<Transport>>),
}

impl GuiVault {
    /// Open whichever the vault record names.
    ///
    /// A card wallet needs the card *now* — every owner-key operation is a
    /// round trip to it, so there is no useful half-open state and failing
    /// here is better than failing on the first signature.
    pub fn open(custody: Option<&kenter_vault::Custody>, soft: SoftVault) -> Result<Self> {
        match custody {
            Some(kenter_vault::Custody::Card { card_identity, .. }) => {
                let expected = hex::decode(card_identity).map_err(|_| {
                    kenter_vault::VaultError::Hardware(
                        "the recorded card identity is not readable; the vault record is damaged"
                            .into(),
                    )
                })?;
                let t = Transport::connect().map_err(|e| {
                    kenter_vault::VaultError::Hardware(format!(
                        "{} ({e})",
                        crate::card::readiness().message()
                    ))
                })?;
                // The recorded identity is passed in, not dropped.
                //
                // Not `connect`, which takes the card's word for who it
                // is. Were the identity matched only elsewhere, in
                // `presence()`, over a separate PC/SC connection, a
                // device could answer that one honestly and this one as
                // itself, and the PIN would go to whatever answered this
                // one.
                //
                // `DEV_CA_PUBLIC_KEY` is a placeholder and says so where
                // it is defined: its private key is in the repository,
                // so today this proves a card came from this workbench.
                // A shipping build pins the real CA.
                let card = StellarKeycard::connect_expecting(
                    t,
                    &expected,
                    crate::card::PINNED_CAS,
                )
                .map_err(|e| kenter_vault::VaultError::Hardware(e.to_string()))?;
                Ok(GuiVault::Card(Box::new(card)))
            }
            _ => Ok(GuiVault::Soft(soft)),
        }
    }
}

impl DerivingVault for GuiVault {
    fn derive_public(&mut self, index: u32, credential: &[u8]) -> Result<[u8; 32]> {
        match self {
            GuiVault::Soft(v) => v.derive_public(index, credential),
            GuiVault::Card(c) => c.derive_public(index, credential),
        }
    }

    fn sign_derived(&mut self, index: u32, message: &[u8], credential: &[u8]) -> Result<[u8; 64]> {
        match self {
            GuiVault::Soft(v) => v.sign_derived(index, message, credential),
            GuiVault::Card(c) => c.sign_derived(index, message, credential),
        }
    }
}
