// Main library file for Authentic Time Service

// Module declarations
pub mod authority;
pub mod client;
pub mod error;
pub mod models;
pub mod service;

// Re-exports for convenient access
pub use models::{AuthenticTimestamp, TimestampRequest, TimestampResponse, TimestampStatus};

pub use authority::{TimeAuthority, TimeAuthorityImpl};

pub use client::TimeClient;
pub use error::TimeServiceError;
pub use service::TspTimeService;
