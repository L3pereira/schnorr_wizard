//! # Schnorr Cryptography Library
//!
//! This library is designed to provide implementations for the Schnorr signature scheme and identification protocol, along with necessary cryptographic primitives and utilities.
//!
//! ## Warnings and Lints
//! The library is configured to warn on several lints to ensure code quality, including:
//! - Use of `unwrap` which should be avoided for better error handling.
//! - Missing documentation to ensure all public items are well-documented.
//! - Missing implementations of the `Debug` and `Copy` traits for public structs and enums.
//! - Adherence to Rust 2018 idioms and avoidance of trivial casts and unused qualifications.
#![warn(
    clippy::unwrap_used,
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_qualifications
)]

/// - `schnorr_group`: Defines the mathematical group used in the Schnorr signature scheme.
pub mod schnorr_group;
