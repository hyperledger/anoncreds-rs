#[macro_use]
extern crate lazy_static;

#[cfg(feature = "serde")]
#[macro_use]
pub extern crate serde;

#[cfg(feature = "serde")]
#[macro_use]
pub extern crate serde_json;

#[macro_use]
pub extern crate zeroize;

/// Common macros
#[macro_use]
pub mod macros;

mod error;
pub use error::{ConversionError, EncryptionError, UnexpectedError, ValidationError};

/// Trait for qualifiable identifier types, having an optional prefix and method
#[macro_use]
pub mod qualifier;

/// Trait definition for validatable data types
#[macro_use]
mod validation;
pub use validation::Validatable;

pub mod base58;
pub mod did;
pub mod keys;

#[cfg(feature = "base64")]
pub mod base64;
#[cfg(feature = "hash")]
pub mod hash;

#[cfg(feature = "pack")]
pub mod pack;

#[cfg(feature = "txn_signature")]
pub mod txn_signature;

#[cfg(feature = "wallet_key")]
pub mod wallet_key;

#[cfg(feature = "wql")]
pub mod wql;

/// Re-export ursa to avoid version conflicts
#[cfg(any(
    feature = "cl",
    feature = "cl_native",
    feature = "ed25519",
    feature = "hash",
    feature = "pack",
    feature = "wallet_key"
))]
pub use ursa;
