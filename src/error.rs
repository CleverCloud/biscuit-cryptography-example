//! error types
//!

use std::convert::{From, Infallible};
use thiserror::Error;

/// Signature errors
#[derive(Error, Clone, Debug, PartialEq)]
pub enum Signature {
    #[error("could not parse the signature elements")]
    InvalidFormat,
    #[error("the signature did not match")]
    InvalidSignature,
}

