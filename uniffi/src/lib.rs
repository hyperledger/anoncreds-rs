mod types;
// mod issuer;
mod prover;
mod issuer;

pub use anoncreds_core::data_types::cred_def::CredentialDefinitionId;
pub use anoncreds_core::data_types::issuer_id::IssuerId;
pub use anoncreds_core::data_types::rev_reg::RevocationRegistryId;
pub use anoncreds_core::data_types::rev_reg_def::RevocationRegistryDefinitionId;
pub use anoncreds_core::data_types::schema::{Schema, SchemaId};
pub use anoncreds_core::types::{AttributeNames, CredentialDefinitionConfig, SignatureType, RegistryType};
pub use crate::types::cred_def::{CredentialDefinition, CredentialDefinitionData, CredentialKeyCorrectnessProof};
pub use crate::types::link_secret::LinkSecret;
pub use crate::types::nonce::Nonce;
pub use crate::types::error::AnoncredsError;
pub use crate::types::cred_offer::CredentialOffer;
pub use crate::types::cred_req::{CredentialRequest, CredentialRequestMetadata};
pub use crate::types::credential::Credential;
pub use crate::types::rev_reg_def::RevocationRegistryDefinitionPrivate;
pub use crate::types::rev_reg_def::RevocationRegistryDefinition;
pub use crate::types::rev_reg_def::RevocationRegistryDefinitionValuePublicKeys;
pub use crate::types::rev_reg_def::RevocationRegistryDefinitionValue;
pub use crate::types::rev_status_list::RevocationStatusList;
pub use crate::cred_def::CredentialDefinitionPrivate;
pub use crate::custom_types::{AttributeValues, CredentialValues};

pub use types::*;
pub use issuer::CredentialRevocationConfig;
pub use prover::*;
pub use issuer::*;

// fn x() -> AttributeValues

uniffi_macros::include_scaffolding!("anoncreds");
