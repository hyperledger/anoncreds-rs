#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

#[cfg(all(feature = "serde", test))]
#[macro_use]
extern crate serde_json;

#[macro_use]
mod macros;

mod embed_json;
pub use embed_json::EmbedJson;
#[cfg(feature = "serde")]
pub use embed_json::{embed_json, EmbedExtract};

mod utils {
    pub use indy_utils::base58;
    #[cfg(feature = "hash")]
    pub use indy_utils::hash;
    pub use indy_utils::{qualifiable, Qualifiable};
}

pub use indy_utils::did::*;
pub use indy_utils::keys::*;
pub use indy_utils::{ConversionError, Validatable, ValidationError};

#[cfg(any(feature = "cl", feature = "cl_native", feature = "hash"))]
pub use indy_utils::ursa;

pub mod anoncreds;
mod identifiers;
#[cfg(feature = "merkle_tree")]
pub mod merkle_tree;

pub use identifiers::cred_def::*;
pub use identifiers::rev_reg::*;
pub use identifiers::schema::*;

#[cfg(any(feature = "rich_schema", test))]
pub use identifiers::rich_schema::*;

pub use identifiers::DELIMITER as IDENT_DELIMITER;
