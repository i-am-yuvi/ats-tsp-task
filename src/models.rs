// Data models for the Authentic Time Service

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// represents a signed timestamp from a time authority
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticTimestamp {
    /// time as reported by the authority
    pub timestamp: DateTime<Utc>,

    /// unique identifier for this timestamp
    pub nonce: String,

    /// authority that issued this timestamp
    pub authority_id: String,

    /// digital signature of the timestamp + nonce by the authority
    pub signature: Vec<u8>,
}

/// Represents a request for an authentic timestamp
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimestampRequest {
    /// client-generated unique identifier for this request
    pub nonce: String,

    /// optional client signature to authenticate the request
    pub client_signature: Option<Vec<u8>>,

    /// Optional client public key or identifier
    pub client_id: Option<String>,
}

/// Represents a response to a timestamp request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimestampResponse {
    /// The authentic timestamp
    pub timestamp: AuthenticTimestamp,

    /// Status of the request
    pub status: TimestampStatus,
}

/// Status codes for timestamp operations
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum TimestampStatus {
    /// Request succeeded
    Success,

    /// Client authentication failed
    AuthenticationFailed,

    /// Client exceeded rate limit or reused a nonce
    RateLimitExceeded,

    /// Server encountered an error
    ServerError,
}

impl AuthenticTimestamp {
    /// Format the message that would be signed (for verification purposes)
    pub fn format_message(&self) -> String {
        format!("{}{}", self.timestamp.to_rfc3339(), self.nonce)
    }
}

impl TimestampRequest {
    /// Create a new timestamp request with the given nonce
    pub fn new(nonce: String) -> Self {
        Self {
            nonce,
            client_signature: None,
            client_id: None,
        }
    }

    /// Create a new authenticated timestamp request
    pub fn new_authenticated(nonce: String, client_id: String, signature: Vec<u8>) -> Self {
        Self {
            nonce,
            client_signature: Some(signature),
            client_id: Some(client_id),
        }
    }
}
