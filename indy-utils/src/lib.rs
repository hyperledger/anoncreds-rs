#[macro_use]
extern crate lazy_static;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_derive;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_json;

/// Common macros
#[macro_use]
pub mod macros;

pub mod error;
pub mod types;

/// Trait for qualifiable identifier types, having an optional prefix and method
#[macro_use]
pub mod qualifier;

/// Trait and error definition for validatable data types
#[macro_use]
pub mod validation;

pub mod base58;
pub mod did;
pub mod keys;

#[cfg(feature = "base64")]
pub mod base64;
#[cfg(feature = "hash")]
pub mod hash;

#[cfg(feature = "pack")]
pub mod pack;

#[cfg(feature = "wql")]
pub mod wql;

/// Re-export ursa to avoid version conflicts
pub use ursa;
