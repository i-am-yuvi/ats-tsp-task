// High-level service implementation that integrates with TSP

use async_trait::async_trait;
use ed25519_dalek::{PublicKey, Signature};
use std::collections::HashMap;

use crate::authority::{TimeAuthority, TimeAuthorityImpl};
use crate::client::TimeClient;
use crate::error::TimeServiceError;
use crate::models::{AuthenticTimestamp, TimestampStatus};

/// trait for TSP communication - would be implemented by actual TSP client
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

/// an example time service implementation that builds on top of the tsp
pub struct TspTimeService {
    // Reference to the underlying TSP implementation (would be provided in real implementation)
    // tsp_client: Box<dyn TspCommunication>,

    // Our time authority implementation
    authority: Option<TimeAuthorityImpl>,

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

    // configure this service as a time authority
    pub fn as_authority(&mut self, id: String) {
        println!("DEBUG: Setting up authority with ID: {}", id);
        self.authority = Some(TimeAuthorityImpl::new(id));
    }

    // configure this service as an authenticated client
    pub fn as_authenticated_client(&mut self, id: String) {
        self.client = TimeClient::new_authenticated(id);
    }

    // add an authority's public key for verification
    pub fn add_authority_key(
        &mut self,
        authority_id: String,
        public_key: &[u8],
    ) -> Result<(), TimeServiceError> {
        self.client.add_authority(authority_id, public_key)
    }

    // add an authority endpoint mapping
    pub fn add_authority_endpoint(&mut self, authority_id: String, endpoint: String) {
        self.authority_endpoints.insert(authority_id, endpoint);
    }

    // Get the public key of this service's authority (if configured as an authority)
    pub fn get_authority_public_key(&self) -> Option<Vec<u8>> {
        self.authority.as_ref().map(|auth| auth.get_public_key())
    }

    // get the client's public key (if configured as an authenticated client)
    pub fn get_client_public_key(&self) -> Option<Vec<u8>> {
        self.client.get_public_key()
    }

    // request a timestamp from a remote authority
    pub async fn request_timestamp(
        &self,
        authority_id: &str,
    ) -> Result<AuthenticTimestamp, TimeServiceError> {
        println!(
            "DEBUG: Requesting timestamp from authority: {}",
            authority_id
        );

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

        // for demonstration purposes, we'll simulate the request locally if we have an authority
        if let Some(authority) = &self.authority {
            // Check if this is a request for our local authority
            let auth_id = authority.get_id();
            println!("DEBUG: Local authority ID: {}", auth_id);
            println!("DEBUG: Requested authority ID: {}", authority_id);

            if auth_id == authority_id {
                println!("DEBUG: IDs match, issuing timestamp");
                let response = authority.issue_timestamp(request).await?;

                if response.status == TimestampStatus::Success {
                    println!("DEBUG: Timestamp issued successfully");
                    return Ok(response.timestamp);
                } else {
                    println!("DEBUG: Request rejected: {:?}", response.status);
                    return Err(TimeServiceError::RequestRejected(format!(
                        "{:?}",
                        response.status
                    )));
                }
            } else {
                println!(
                    "DEBUG: Authority IDs don't match! '{}' != '{}'",
                    auth_id, authority_id
                );
            }
        } else {
            println!("DEBUG: No local authority configured");
        }

        println!("DEBUG: Authority not found: {}", authority_id);
        Err(TimeServiceError::AuthorityNotFound(
            authority_id.to_string(),
        ))
    }

    // verify a timestamp received from an authority
    pub fn verify_timestamp(
        &self,
        timestamp: &AuthenticTimestamp,
    ) -> Result<bool, TimeServiceError> {
        self.client.verify_timestamp(timestamp)
    }

    // process a timestamp request (when acting as an authority)
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

        // request a timestamp from our local authority
        let timestamp = service.request_timestamp("test.authority").await.unwrap();

        // add the authority's public key to our client
        let auth_pubkey = service.get_authority_public_key().unwrap();
        service
            .add_authority_key("test.authority".to_string(), &auth_pubkey)
            .unwrap();

        // verify the timestamp
        let is_valid = service.verify_timestamp(&timestamp).unwrap();
        assert!(is_valid);
    }
}
