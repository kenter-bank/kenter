use thiserror::Error;

#[derive(Debug, Error)]
pub enum TunnlerError {
    #[error("config: {0}")]
    Config(String),

    #[error("auth failed: {0}")]
    AuthFailed(String),

    #[error("rate limited")]
    RateLimited,

    #[error("connection not found: {0}")]
    ConnectionNotFound(String),

    #[error("timeout: {0}")]
    Timeout(String),

    #[error("protocol: {0}")]
    Protocol(String),

    #[error("roster check failed: {0}")]
    RosterCheckFailed(String),

    #[error("not on roster: {0}")]
    NotOnRoster(String),
}

pub type Result<T> = std::result::Result<T, TunnlerError>;
