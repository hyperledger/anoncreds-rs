#[macro_use]
extern crate lazy_static;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_json;

/// Common macros
#[macro_use]
pub mod macros;

/// Trait for qualifiable identifier types, having an optional prefix and method
#[macro_use]
pub mod qualifier;

/// Trait and error definition for validatable data types
#[macro_use]
pub mod validation;

#[cfg(feature = "base58")]
pub mod base58;
#[cfg(feature = "ed25519")]
pub mod ed25519;
#[cfg(feature = "hash")]
pub mod hash;

#[cfg(feature = "wql")]
pub mod wql;
