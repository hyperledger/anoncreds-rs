#[cfg(any(feature = "serde", test))]
pub extern crate serde;

/// Common macros
#[macro_use]
mod macros;

mod error;
pub use error::{ConversionError, EncryptionError, UnexpectedError, ValidationError};

/// Trait definition for validatable data types
#[macro_use]
mod validation;
pub use validation::Validatable;

/// base58 encoding and decoding
pub mod base58;

/// Hash algorithms
#[cfg(feature = "hash")]
pub mod hash;

// Query
#[cfg(feature = "query")]
pub mod query;
