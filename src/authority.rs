// Implementation of the Time Authority

use async_trait::async_trait;
use chrono::Utc;
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crate::error::TimeServiceError;
use crate::models::{AuthenticTimestamp, TimestampRequest, TimestampResponse, TimestampStatus};

/// Interface for time authority
#[async_trait]
pub trait TimeAuthority: Send + Sync {
    /// get the identifier
    fn get_id(&self) -> String;

    /// issue a signed timestamp in response to a request
    async fn issue_timestamp(
        &self,
        request: TimestampRequest,
    ) -> Result<TimestampResponse, TimeServiceError>;

    /// verify a timestamp that was allegedly issued by this authority
    fn verify_timestamp(&self, timestamp: &AuthenticTimestamp) -> bool;

    /// get the public key of this authority - for verification by clients
    fn get_public_key(&self) -> Vec<u8>;
}

/// Implementation of a time authority
pub struct TimeAuthorityImpl {
    /// unique identifier for this authority
    id: String,

    /// keypair used for signing timestamps
    keypair: Keypair,

    /// cache of recently issued timestamps to prevent replay
    recent_requests: Arc<Mutex<HashMap<String, SystemTime>>>,

    /// time after which a nonce expires from the cache
    nonce_expiry: Duration,

    /// optional list of trusted client IDs
    trusted_clients: Option<HashMap<String, PublicKey>>,
}

impl TimeAuthorityImpl {
    /// create a new time authority with the given identifier
    pub fn new(id: String) -> Self {
        let mut csprng = OsRng {};
        let keypair = Keypair::generate(&mut csprng);

        Self {
            id,
            keypair,
            recent_requests: Arc::new(Mutex::new(HashMap::new())),
            nonce_expiry: Duration::from_secs(300), // 5 minutes for example
            trusted_clients: None,
        }
    }

    /// create a new time authority with an existing keypair
    pub fn with_keypair(id: String, keypair: Keypair) -> Self {
        Self {
            id,
            keypair,
            recent_requests: Arc::new(Mutex::new(HashMap::new())),
            nonce_expiry: Duration::from_secs(300), // 5 minutes
            trusted_clients: None,
        }
    }

    /// Set the nonce expiry duration
    pub fn set_nonce_expiry(&mut self, expiry: Duration) {
        self.nonce_expiry = expiry;
    }

    /// add trusted client to this authority
    pub fn add_trusted_client(&mut self, client_id: String, client_pubkey: PublicKey) {
        if self.trusted_clients.is_none() {
            self.trusted_clients = Some(HashMap::new());
        }

        if let Some(clients) = &mut self.trusted_clients {
            clients.insert(client_id, client_pubkey);
        }
    }

    /// clean expired nonces from the cache
    fn clean_expired_nonces(&self) {
        let now = SystemTime::now();
        let mut cache = self.recent_requests.lock().unwrap();

        cache.retain(|_, &mut timestamp| {
            now.duration_since(timestamp)
                .unwrap_or(Duration::from_secs(0))
                < self.nonce_expiry
        });
    }

    /// Check if client is authorized - if authorization is enabled
    fn is_client_authorized(&self, request: &TimestampRequest) -> bool {
        // If we have no trusted clients list, we accept all clients
        if self.trusted_clients.is_none() {
            return true;
        }

        // Otherwise, check if this client is authorized
        match (&request.client_id, &request.client_signature) {
            (Some(client_id), Some(signature)) => {
                if let Some(clients) = &self.trusted_clients {
                    if let Some(pubkey) = clients.get(client_id) {
                        // Verify signature
                        let sig = match Signature::from_bytes(signature) {
                            Ok(s) => s,
                            Err(_) => return false,
                        };

                        return pubkey.verify(request.nonce.as_bytes(), &sig).is_ok();
                    }
                }
                false
            }
            _ => false,
        }
    }
}

#[async_trait]
impl TimeAuthority for TimeAuthorityImpl {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    async fn issue_timestamp(
        &self,
        request: TimestampRequest,
    ) -> Result<TimestampResponse, TimeServiceError> {
        // Clean expired nonces
        self.clean_expired_nonces();

        // Check for replay attacks
        {
            let mut cache = self.recent_requests.lock().unwrap();
            if cache.contains_key(&request.nonce) {
                return Ok(TimestampResponse {
                    timestamp: AuthenticTimestamp {
                        timestamp: Utc::now(),
                        nonce: request.nonce,
                        authority_id: self.id.clone(),
                        signature: vec![],
                    },
                    status: TimestampStatus::RateLimitExceeded,
                });
            }

            // Add nonce to cache
            cache.insert(request.nonce.clone(), SystemTime::now());
        }

        // If client authorization is enabled, check if client is authorized
        if !self.is_client_authorized(&request) {
            return Ok(TimestampResponse {
                timestamp: AuthenticTimestamp {
                    timestamp: Utc::now(),
                    nonce: request.nonce,
                    authority_id: self.id.clone(),
                    signature: vec![],
                },
                status: TimestampStatus::AuthenticationFailed,
            });
        }

        // Create timestamp
        let timestamp = Utc::now();

        // Create message to sign (timestamp + nonce)
        let message = format!("{}{}", timestamp.to_rfc3339(), request.nonce);

        // Sign message
        let signature = self.keypair.sign(message.as_bytes());

        // Create response
        let authentic_timestamp = AuthenticTimestamp {
            timestamp,
            nonce: request.nonce,
            authority_id: self.id.clone(),
            signature: signature.to_bytes().to_vec(),
        };

        Ok(TimestampResponse {
            timestamp: authentic_timestamp,
            status: TimestampStatus::Success,
        })
    }

    fn verify_timestamp(&self, timestamp: &AuthenticTimestamp) -> bool {
        // Check if this timestamp was issued by this authority
        if timestamp.authority_id != self.id {
            return false;
        }

        // Create message that was signed
        let message = timestamp.format_message();

        // Create signature object
        let signature = match Signature::from_bytes(&timestamp.signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // Verify signature
        self.keypair
            .public
            .verify(message.as_bytes(), &signature)
            .is_ok()
    }

    fn get_public_key(&self) -> Vec<u8> {
        self.keypair.public.to_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_issue_and_verify_timestamp() {
        let authority = TimeAuthorityImpl::new("test.authority".to_string());
        let request = TimestampRequest::new("test-nonce-12345".to_string());

        let response = authority.issue_timestamp(request).await.unwrap();
        assert_eq!(response.status, TimestampStatus::Success);

        let is_valid = authority.verify_timestamp(&response.timestamp);
        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_nonce_reuse_prevention() {
        let authority = TimeAuthorityImpl::new("test.authority".to_string());
        let request = TimestampRequest::new("test-nonce-reuse".to_string());

        // First request should succeed
        let response1 = authority.issue_timestamp(request.clone()).await.unwrap();
        assert_eq!(response1.status, TimestampStatus::Success);

        // Second request with same nonce should fail
        let response2 = authority.issue_timestamp(request).await.unwrap();
        assert_eq!(response2.status, TimestampStatus::RateLimitExceeded);
    }
}
