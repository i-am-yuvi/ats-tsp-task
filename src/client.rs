// Client implementation for the Authentic Time Service

use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use std::collections::HashMap;

use crate::error::TimeServiceError;
use crate::models::{AuthenticTimestamp, TimestampRequest};

/// Client for interacting with time authorities
pub struct TimeClient {
    /// Client identifier
    id: Option<String>,

    /// Client keypair for authentication
    keypair: Option<Keypair>,

    /// Cache of known authority public keys
    authority_keys: HashMap<String, PublicKey>,
}

impl TimeClient {
    /// Create a new anonymous time client
    pub fn new_anonymous() -> Self {
        Self {
            id: None,
            keypair: None,
            authority_keys: HashMap::new(),
        }
    }

    /// Create a new authenticated time client
    pub fn new_authenticated(id: String) -> Self {
        let mut csprng = OsRng {};
        let keypair = Keypair::generate(&mut csprng);

        Self {
            id: Some(id),
            keypair: Some(keypair),
            authority_keys: HashMap::new(),
        }
    }

    /// Create a new authenticated time client with an existing keypair
    pub fn with_keypair(id: String, keypair: Keypair) -> Self {
        Self {
            id: Some(id),
            keypair: Some(keypair),
            authority_keys: HashMap::new(),
        }
    }

    /// Get the client's public key (for registration with authorities)
    pub fn get_public_key(&self) -> Option<Vec<u8>> {
        self.keypair
            .as_ref()
            .map(|kp| kp.public.to_bytes().to_vec())
    }

    /// Add a known authority public key
    pub fn add_authority(
        &mut self,
        authority_id: String,
        public_key_bytes: &[u8],
    ) -> Result<(), TimeServiceError> {
        let public_key = PublicKey::from_bytes(public_key_bytes)
            .map_err(|_| TimeServiceError::InvalidSignature)?;

        self.authority_keys.insert(authority_id, public_key);
        Ok(())
    }

    /// Generate a new timestamp request
    pub fn create_request(&self) -> TimestampRequest {
        let nonce = format!("{:x}", rand::random::<u128>());

        // If we have a keypair, sign the request
        let (client_signature, client_id) = match (&self.keypair, &self.id) {
            (Some(kp), Some(id)) => {
                let signature = kp.sign(nonce.as_bytes()).to_bytes().to_vec();
                (Some(signature), Some(id.clone()))
            }
            _ => (None, None),
        };

        TimestampRequest {
            nonce,
            client_signature,
            client_id,
        }
    }

    /// Verify a timestamp from an authority
    pub fn verify_timestamp(
        &self,
        timestamp: &AuthenticTimestamp,
    ) -> Result<bool, TimeServiceError> {
        // Look up the authority's public key
        let pubkey = match self.authority_keys.get(&timestamp.authority_id) {
            Some(pk) => pk,
            None => {
                return Err(TimeServiceError::AuthorityNotFound(
                    timestamp.authority_id.clone(),
                ))
            }
        };

        // Create message that was signed
        let message = timestamp.format_message();

        // Create signature object
        let signature = Signature::from_bytes(&timestamp.signature)
            .map_err(|_| TimeServiceError::InvalidSignature)?;

        // Verify signature
        Ok(pubkey.verify(message.as_bytes(), &signature).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::TimeAuthorityImpl;
    use crate::models::TimestampRequest;

    #[test]
    fn test_client_request_creation() {
        let client = TimeClient::new_authenticated("test-client".to_string());
        let request = client.create_request();

        assert!(request.client_id.is_some());
        assert!(request.client_signature.is_some());
        assert!(!request.nonce.is_empty());
    }

    #[test]
    fn test_anonymous_client_request_creation() {
        let client = TimeClient::new_anonymous();
        let request = client.create_request();

        assert!(request.client_id.is_none());
        assert!(request.client_signature.is_none());
        assert!(!request.nonce.is_empty());
    }
}
