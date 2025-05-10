// Error types for the Authentic Time Service
use std::fmt;
use thiserror::Error;

/// Errors that can occur in the Authentic Time Service
#[derive(Error, Debug)]
pub enum TimeServiceError {
    /// Error when signature verification fails
    #[error("Invalid signature")]
    InvalidSignature,

    /// Error when a nonce is reused (replay attack attempt)
    #[error("Nonce has been used before")]
    NonceReused,

    /// Error when client authentication fails
    #[error("Client authentication failed")]
    AuthenticationFailed,

    /// Error when an authority is not found
    #[error("Authority not found: {0}")]
    AuthorityNotFound(String),

    /// Error when timestamp request is rejected
    #[error("Timestamp request rejected: {0}")]
    RequestRejected(String),

    /// Error in serialization/deserialization
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// Generic error with message
    #[error("{0}")]
    Generic(String),
}

impl TimeServiceError {
    /// Create a new generic error with the provided message
    pub fn generic<T: fmt::Display>(message: T) -> Self {
        TimeServiceError::Generic(message.to_string())
    }
}

// Instead of implementing From<T> for all T, we'll implement it just for specific types
// that we know we'll need to convert from
impl From<&str> for TimeServiceError {
    fn from(err: &str) -> Self {
        TimeServiceError::Generic(err.to_string())
    }
}

impl From<String> for TimeServiceError {
    fn from(err: String) -> Self {
        TimeServiceError::Generic(err)
    }
}
