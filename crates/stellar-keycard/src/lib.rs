pub mod apdu;
pub mod error;
pub mod secure_channel;
pub mod secure_channel_v2;
pub mod sim;
pub mod stellar;
pub mod transport;
pub mod vault;

pub use error::{KeycardError, Result};
pub use secure_channel::{
    CardSignature, DEFAULT_PAIRING_PASSWORD, Pairing, SecureChannel, init_card, pair,
    pairing_secret_from_password, parse_signature_template,
};
pub use secure_channel_v2::{
    CaPublicKey, DEV_CA_PUBLIC_KEY, SecureChannelV2, card_identity_certificate,
    verify_identity_certificate_any,
    card_identity_pubkey, verify_identity_certificate,
};
pub use sim::{DEFAULT_SIM_ADDR, SimTransport};
pub use stellar::{
    DecoratedSignature, DuressPin, InitParams, PIN_LEN, PIN_RETRIES, PUK_LEN, PUK_RETRIES,
    StellarKeycard, network_id, transaction_hash, verify_ed25519,
};
pub use transport::{ApplicationInfo, CardTransport, Transport};
pub use vault::KeycardVault;
