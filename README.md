# Authentic Time Service for Trust Spanning Protocol (TSP)

## Overview

The Authentic Time Service is a trust task implementation for the Trust over IP (ToIP) Trust Spanning Protocol (TSP). It provides a secure and verifiable way to establish trusted timestamps between participants in a decentralized network. This service enables parties to prove that specific events occurred at certain points in time with cryptographic assurance.

## Technical Details

### Core Components

1. **Time Authority**: A trusted entity that issues signed timestamps in response to requests
   - Uses Ed25519 signatures for high-security digital signatures
   - Maintains a nonce cache to prevent replay attacks

2. **Time Client**: Requests and verifies timestamps from authorities
   - Can operate anonymously or with authentication
   - Maintains a store of trusted authority public keys
   - Verifies timestamps using cryptographic signatures

3. **Authentic Timestamp**: A data structure containing:
   - The timestamp value (UTC datetime)
   - A nonce (random value to prevent replay)
   - The authority identifier
   - A cryptographic signature binding these elements together

### Trust Model

The Authentic Time Service implements a hierarchical trust model where:

1. Time Authorities are trusted by clients who possess their public keys
2. Time Authorities can restrict service to only authenticated clients
3. Timestamps are cryptographically verifiable by any party with the Authority's public key
4. Multiple Time Authorities can be used to establish consensus on time (quorum-based trust)

## Integration with Trust Spanning Protocol

The Trust Spanning Protocol provides the communication layer for this trust task. In a complete implementation:

1. TSP would handle secure message delivery between parties
2. TSP would provide the DID (Decentralized Identifier) resolution to locate Time Authorities
3. TSP would ensure message integrity and authenticity
4. TSP would provide the framework for discovery of Time Authorities

## Usage Examples

### Setting Up a Time Authority

```rust
// Create a time service
let mut authority_service = TspTimeService::new();

// Configure it as a time authority with a DID or domain identifier
authority_service.as_authority("did:example:123456789abcdefghi");

// The authority is now ready to respond to timestamp requests
```

### Requesting a Timestamp as a Client

```rust
// Create a time client service
let mut client_service = TspTimeService::new();

// Optionally authenticate the client with its own identifier
client_service.as_authenticated_client("did:example:client123456");

// Request a timestamp from an authority
let timestamp = client_service
    .request_timestamp("did:example:123456789abcdefghi")
    .await?;

// Verify the timestamp
let is_valid = client_service.verify_timestamp(&timestamp);
```

### Verifying a Timestamp from a Third Party

```rust
// A third party that receives a document with an attached timestamp
// can verify it independently

// Create a verification service
let mut verifier = TspTimeService::new();

// Add the public key of the time authority
verifier.add_authority_key(
    "did:example:123456789abcdefghi",
    authority_public_key
);

// Verify the timestamp
let is_valid = verifier.verify_timestamp(&received_timestamp);
```

## Dependencies

- `async-trait`: For async trait implementations
- `chrono`: For datetime handling
- `ed25519-dalek`: For public key cryptography
- `rand`: For secure random number generation
- `serde`: For serialization/deserialization
- `tokio`: For async runtime (used in examples)
