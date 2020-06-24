#[macro_use]
extern crate lazy_static;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_derive;

#[cfg(all(feature = "serde", any(test, feature = "cl", feature = "cl_native")))]
#[macro_use]
extern crate serde_json;

mod utils {
    pub use indy_utils::base58;
    pub use indy_utils::hash;
    pub use indy_utils::qualifier;
}

pub use indy_utils::did::*;
pub use indy_utils::keys::*;
pub use indy_utils::ursa;
pub use indy_utils::{ConversionError, TryClone, Validatable, ValidationError};

pub mod compat;

mod anoncreds;
mod identifiers;
mod merkle_tree;

#[cfg(any(feature = "cl", feature = "cl_native"))]
pub use anoncreds::cred_def::*;
#[cfg(any(feature = "cl", feature = "cl_native"))]
pub use anoncreds::rev_reg::*;
#[cfg(any(feature = "cl", feature = "cl_native"))]
pub use anoncreds::rev_reg_def::*;
pub use anoncreds::schema::*;

pub use identifiers::cred_def::*;
pub use identifiers::rev_reg::*;
pub use identifiers::schema::*;
