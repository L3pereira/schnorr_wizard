/// This module implements interactive zero-knowledge (ZK) proofs,
/// specifically designed for use within cryptographic protocols
/// that require proving knowledge of a secret without revealing it.
pub mod interactive_zk;

/// This module implements non interactive zero-knowledge (ZK) proofs,
/// specifically designed for use within cryptographic protocols
/// that require proving knowledge of a secret without revealing it.
pub mod non_interactive_zk;

/// # Utils Module
///
/// This module provides utility functions and structures that are commonly used across the cryptographic library, especially within the zero-knowledge proofs implementations.
///
/// ## Overview
/// The `utils` module includes a variety of helper functions and types that facilitate cryptographic computations, d
/// ata manipulation, and error handling. These utilities are designed to support the core functionalities of the library,
/// making the implementation of cryptographic protocols more efficient and readable.
pub mod utils;

/// # Errors Module
///
/// This module defines error types and handling mechanisms used throughout the cryptographic library, particularly
/// within the zero-knowledge proofs implementations.
///
pub mod errors;
