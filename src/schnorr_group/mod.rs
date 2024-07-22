/// This module implements interactive zero-knowledge (ZK) proofs,
/// specifically designed for use within cryptographic protocols
/// that require proving knowledge of a secret without revealing it.
pub mod interactive_zk;

/// This module implements non interactive zero-knowledge (ZK) proofs,
/// specifically designed for use within cryptographic protocols
/// that require proving knowledge of a secret without revealing it.
pub mod non_interactive_zk;

/// A module containing implementations for Schnorr signatures.
///
/// This module provides structures and functions for generating and verifying Schnorr signatures,
/// a digital signature scheme known for its simplicity and efficiency. The `signatures` module
/// includes the `Signer` struct for creating signatures and a function for verifying them.
pub mod signatures;

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
