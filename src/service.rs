// High-level service implementation that integrates with TSP

use async_trait::async_trait;
use ed25519_dalek::{PublicKey, Signature};
use std::collections::HashMap;

use crate::authority::{TimeAuthority, TimeAuthorityImpl};
use crate::client::TimeClient;
use crate::error::TimeServiceError;
use crate::models::{AuthenticTimestamp, TimestampStatus};

/// Trait for TSP communication (would be implemented by actual TSP client)
#[async_trait]
pub trait TspCommunication: Send + Sync {
    /// Send a request to a remote endpoint and get a response
    async fn send_request<T, R>(
        &self,
        endpoint: &str,
        method: &str,
        request: &T,
    ) -> Result<R, TimeServiceError>
    where
        T: serde::Serialize + Send + Sync,
        R: for<'de> serde::Deserialize<'de> + Send;
}

/// Example time service implementation that builds on top of the Trust Spanning Protocol
pub struct TspTimeService {
    // Reference to the underlying TSP implementation (would be provided in real implementation)
    // tsp_client: Box<dyn TspCommunication>,

    // Our time authority implementation
    authority: Option<Box<dyn TimeAuthority>>,

    // Our time client implementation
    client: TimeClient,

    // Cache of authority endpoints (ID -> endpoint mapping)
    authority_endpoints: HashMap<String, String>,
}

impl TspTimeService {
    // Create a new time service
    pub fn new() -> Self {
        Self {
            // tsp_client: Box::new(TspClient::new()),
            authority: None,
            client: TimeClient::new_anonymous(),
            authority_endpoints: HashMap::new(),
        }
    }

    // Configure this service as a time authority
    pub fn as_authority(&mut self, id: String) {
        self.authority = Some(Box::new(TimeAuthorityImpl::new(id)));
    }

    // Configure this service as an authenticated client
    pub fn as_authenticated_client(&mut self, id: String) {
        self.client = TimeClient::new_authenticated(id);
    }

    // Add an authority's public key for verification
    pub fn add_authority_key(
        &mut self,
        authority_id: String,
        public_key: &[u8],
    ) -> Result<(), TimeServiceError> {
        self.client.add_authority(authority_id, public_key)
    }

    // Add an authority endpoint mapping
    pub fn add_authority_endpoint(&mut self, authority_id: String, endpoint: String) {
        self.authority_endpoints.insert(authority_id, endpoint);
    }

    // Get the public key of this service's authority (if configured as an authority)
    pub fn get_authority_public_key(&self) -> Option<Vec<u8>> {
        self.authority.as_ref().map(|auth| auth.get_public_key())
    }

    // Get the client's public key (if configured as an authenticated client)
    pub fn get_client_public_key(&self) -> Option<Vec<u8>> {
        self.client.get_public_key()
    }

    // Request a timestamp from a remote authority
    pub async fn request_timestamp(
        &self,
        authority_id: &str,
    ) -> Result<AuthenticTimestamp, TimeServiceError> {
        let request = self.client.create_request();

        // In a real implementation, we would look up the authority endpoint
        // and use the TSP client to send the request
        /*
        if let Some(endpoint) = self.authority_endpoints.get(authority_id) {
            let response = self.tsp_client
                .send_request(endpoint, "time/request", &request)
                .await?;

            if response.status == TimestampStatus::Success {
                return Ok(response.timestamp);
            } else {
                return Err(TimeServiceError::RequestRejected(format!("{:?}", response.status)));
            }
        }
        */

        // For demonstration purposes, we'll simulate the request locally if we have an authority
        if let Some(authority) = &self.authority {
            if authority.get_id() == authority_id {
                let response = authority.issue_timestamp(request).await?;

                if response.status == TimestampStatus::Success {
                    return Ok(response.timestamp);
                } else {
                    return Err(TimeServiceError::RequestRejected(format!(
                        "{:?}",
                        response.status
                    )));
                }
            }
        }

        Err(TimeServiceError::AuthorityNotFound(
            authority_id.to_string(),
        ))
    }

    // Verify a timestamp received from an authority
    pub fn verify_timestamp(
        &self,
        timestamp: &AuthenticTimestamp,
    ) -> Result<bool, TimeServiceError> {
        self.client.verify_timestamp(timestamp)
    }

    // Process a timestamp request (when acting as an authority)
    pub async fn process_timestamp_request(
        &self,
        request: crate::models::TimestampRequest,
    ) -> Result<crate::models::TimestampResponse, TimeServiceError> {
        if let Some(authority) = &self.authority {
            authority.issue_timestamp(request).await
        } else {
            Err(TimeServiceError::generic("Not configured as an authority"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_local_request_and_verify() {
        let mut service = TspTimeService::new();
        service.as_authority("test.authority".to_string());

        // Request a timestamp from our local authority
        let timestamp = service.request_timestamp("test.authority").await.unwrap();

        // Add the authority's public key to our client
        let auth_pubkey = service.get_authority_public_key().unwrap();
        service
            .add_authority_key("test.authority".to_string(), &auth_pubkey)
            .unwrap();

        // Verify the timestamp
        let is_valid = service.verify_timestamp(&timestamp).unwrap();
        assert!(is_valid);
    }
}
