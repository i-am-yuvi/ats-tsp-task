// Example application demonstrating the Authentic Time Service
use authentic_time_service::{
    AuthenticTimestamp, TimeAuthority, TimeAuthorityImpl, TimeServiceError, TspTimeService,
};
use std::time::Duration;

// Main function to demonstrate the Authentic Time Service
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("==========================================");
    println!("Authentic Time Service - Example Application");
    println!("==========================================\n");

    // Create a time authority service
    println!("1. Creating Time Authority service...");
    let mut authority_service = TspTimeService::new();

    // Explicitly use the same service for both roles
    let auth_id = "time.authority.example.com".to_string();
    authority_service.as_authority(auth_id.clone());
    println!("   - Authority ID: {}", auth_id);
    println!("   - Authority created successfully");

    // Get the authority's public key for sharing
    let authority_pubkey = authority_service
        .get_authority_public_key()
        .expect("Failed to get authority public key");
    println!("   - Authority public key: {:?}", &authority_pubkey[0..4]);
    println!();

    // Use the SAME instance for both authority and client
    // This ensures we're using the same service with its configured authority
    println!("2. Configuring service as authenticated client...");
    authority_service.as_authenticated_client("client.example.com".to_string());
    println!("   - Client ID: client.example.com");
    println!("   - Client configured successfully");
    println!();

    // Add the authority's public key to the client
    println!("3. Adding authority's public key to client's trust store...");
    authority_service.add_authority_key(auth_id.clone(), &authority_pubkey)?;
    println!("   - Authority key added successfully");
    println!();

    // Request a timestamp from the authority (using the same service instance)
    println!("4. Requesting an authentic timestamp from the authority...");
    let timestamp = authority_service.request_timestamp(&auth_id).await?;
    println!("   - Timestamp received: {}", timestamp.timestamp);
    println!("   - Nonce: {}", timestamp.nonce);
    println!();

    // Verify the timestamp
    println!("5. Verifying the timestamp with client's trust store...");
    let is_valid = authority_service.verify_timestamp(&timestamp)?;
    if is_valid {
        println!("   - Timestamp VERIFIED successfully! ✅");
    } else {
        println!("   - Timestamp verification FAILED! ❌");
    }
    println!();

    // Create a third-party verifier (new instance)
    println!("6. Creating a third-party verifier service...");
    let mut verifier_service = TspTimeService::new();
    println!("   - Verifier service created");

    // Add the authority's public key to the verifier
    println!("7. Adding authority's public key to verifier's trust store...");
    verifier_service.add_authority_key(auth_id.clone(), &authority_pubkey)?;
    println!("   - Authority key added to verifier");
    println!();

    // Verify the timestamp with the third-party verifier
    println!("8. Verifying the timestamp with third-party verifier...");
    let is_valid = verifier_service.verify_timestamp(&timestamp)?;
    if is_valid {
        println!("   - Timestamp VERIFIED by third party! ✅");
    } else {
        println!("   - Timestamp verification by third party FAILED! ❌");
    }
    println!();

    // Example of timestamp expiration check
    println!("9. Demonstrating timestamp freshness check...");
    println!("   - Current timestamp: {}", timestamp.timestamp);

    // For demonstration, we'll consider timestamps valid for 5 minutes
    let valid_duration = Duration::from_secs(300); // 5 minutes
    let age = chrono::Utc::now()
        .signed_duration_since(timestamp.timestamp)
        .to_std()
        .unwrap_or(Duration::from_secs(0));

    if age > valid_duration {
        println!("   - Timestamp is TOO OLD (age: {:?})! ❌", age);
    } else {
        println!("   - Timestamp is FRESH (age: {:?})! ✅", age);
    }
    println!();

    // Example of attempting to use a different authority ID
    println!("10. Testing authority ID mismatch detection...");
    let mut tampered_timestamp = timestamp.clone();
    tampered_timestamp.authority_id = "fake.authority.example.com".to_string();

    let is_valid = verifier_service.verify_timestamp(&tampered_timestamp);
    match is_valid {
        Ok(true) => println!("   - SECURITY ISSUE: Tampered timestamp verified! ❌"),
        Ok(false) => println!("   - Tampered timestamp correctly rejected! ✅"),
        Err(e) => println!("   - Verification error: {} ✅", e),
    }
    println!();

    println!("==========================================");
    println!("Authentic Time Service - Demo Complete");
    println!("==========================================");

    Ok(())
}
