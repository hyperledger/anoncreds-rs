use crate::data_types::w3c::context::{Context, Contexts};
use once_cell::sync::Lazy;
use serde_json::{json, Value};
use std::collections::HashSet;

use crate::data_types::w3c::credential::Types;
use crate::data_types::w3c::uri::URI;

// Contexts
pub const W3C_VC_1_1_BASE_CONTEXT: &str = "https://www.w3.org/2018/credentials/v1";
pub const W3C_VC_2_0_BASE_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";
pub const W3C_DATA_INTEGRITY_CONTEXT: &str = "https://w3id.org/security/data-integrity/v2";

pub static ISSUER_DEPENDENT_VOCABULARY: Lazy<Value> = Lazy::new(|| {
    json!({
        "@vocab": "https://www.w3.org/ns/credentials/issuer-dependent#"
    })
});

pub(crate) static ANONCREDS_VC_1_1_CONTEXTS: Lazy<Contexts> = Lazy::new(|| {
    Contexts(vec![
        Context::URI(URI::from(W3C_VC_1_1_BASE_CONTEXT)),
        Context::URI(URI::from(W3C_DATA_INTEGRITY_CONTEXT)),
        Context::Object(ISSUER_DEPENDENT_VOCABULARY.clone()),
    ])
});

pub(crate) static ANONCREDS_VC_2_0_CONTEXTS: Lazy<Contexts> = Lazy::new(|| {
    Contexts(vec![
        Context::URI(URI::from(W3C_VC_2_0_BASE_CONTEXT)),
        Context::Object(ISSUER_DEPENDENT_VOCABULARY.clone()),
    ])
});

// Types
pub const W3C_CREDENTIAL_TYPE: &str = "VerifiableCredential";
pub const W3C_PRESENTATION_TYPE: &str = "VerifiablePresentation";

pub(crate) static ANONCREDS_CREDENTIAL_TYPES: Lazy<Types> =
    Lazy::new(|| Types(HashSet::from([String::from(W3C_CREDENTIAL_TYPE)])));

pub(crate) static ANONCREDS_PRESENTATION_TYPES: Lazy<Types> =
    Lazy::new(|| Types(HashSet::from([String::from(W3C_PRESENTATION_TYPE)])));
