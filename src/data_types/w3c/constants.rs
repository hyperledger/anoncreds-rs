use std::collections::HashSet;
use once_cell::sync::Lazy;

use crate::data_types::w3c::credential::{Contexts, Types};
use crate::data_types::w3c::uri::URI;

// Contexts
pub const W3C_CONTEXT: &'static str = "https://www.w3.org/2018/credentials/v1";
pub const W3C_ANONCREDS_CONTEXT: &'static str = "https://github.io/anoncreds-w3c/context.json";

// Types
pub const W3C_CREDENTIAL_TYPE: &'static str = "VerifiableCredential";
pub const W3C_ANONCREDS_CREDENTIAL_TYPE: &'static str = "AnonCredsCredential";

pub(crate) static ANONCREDS_CONTEXTS: Lazy<Contexts> = Lazy::new(||
    Contexts(
        HashSet::from([
            URI::from(W3C_CONTEXT),
            URI::from(W3C_ANONCREDS_CONTEXT)
        ])
    )
);

pub(crate) static ANONCREDS_TYPES: Lazy<Types> = Lazy::new(||
    Types(
        HashSet::from([
            String::from(W3C_CREDENTIAL_TYPE),
            String::from(W3C_ANONCREDS_CREDENTIAL_TYPE)
        ])
    )
);


