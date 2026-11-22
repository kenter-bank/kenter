use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeycardError {
    #[error("no PC/SC context available: {0}")]
    PcscContext(String),

    #[error("no card reader found")]
    NoReader,

    #[error("no card present in reader")]
    NoCard,

    #[error("card communication error: {0}")]
    CardComm(String),

    #[error("APDU error: SW={sw:#06x}")]
    Apdu { sw: u16 },

    #[error("not a Keycard (unexpected AID response)")]
    NotKeycard,

    #[error("card not initialized")]
    NotInitialized,

    #[error("card already initialized")]
    AlreadyInitialized,

    #[error("secure channel not open")]
    NoSecureChannel,

    #[error("secure channel error: {0}")]
    SecureChannel(String),

    #[error("pairing failed: {0}")]
    PairingFailed(String),

    #[error("authentication failed")]
    AuthFailed,

    #[error("PIN required")]
    PinRequired,

    #[error("wrong PIN ({attempts_remaining} attempts remaining)")]
    WrongPin { attempts_remaining: u8 },

    #[error("card blocked (PIN attempts exhausted)")]
    CardBlocked,

    #[error("slot {0} not found")]
    SlotNotFound(u8),

    #[error("slot storage full")]
    StorageFull,

    #[error("key wrapping error: {0}")]
    WrapError(String),

    #[error("invalid slot data: {0}")]
    InvalidSlotData(String),

    #[error("crypto error: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, KeycardError>;

/// Map pcsc::Error to KeycardError
impl From<pcsc::Error> for KeycardError {
    fn from(e: pcsc::Error) -> Self {
        match e {
            pcsc::Error::NoReadersAvailable => KeycardError::NoReader,
            pcsc::Error::RemovedCard => KeycardError::NoCard,
            pcsc::Error::ReaderUnavailable => KeycardError::NoReader,
            _ => KeycardError::CardComm(e.to_string()),
        }
    }
}
