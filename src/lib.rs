#![forbid(unsafe_code)]
//! Public, verification-only SDK for `ksl1` Ed25519 licenses.
//!
//! Embed one application-specific public key in each product binary. This crate deliberately
//! contains no signing API, private-key parser, key generator, or server credential support.

mod error;

pub use error::{KeySystemError, Result};
