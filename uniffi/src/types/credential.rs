use crate::types::error::AnoncredsError;
use crate::types::nonce::Nonce;
pub use crate::custom_types::CredentialValues;
use anoncreds_core::data_types::schema::SchemaId;
use anoncreds_core::data_types::cred_def::{
    CredentialDefinitionId,
    SignatureType
};
use anoncreds_core::data_types::rev_reg::RevocationRegistryId;
use anoncreds_core::data_types::credential::Credential as AnoncredsCredential;

pub struct Credential {
    pub core: AnoncredsCredential
}

impl Credential {
    pub fn new(jsonString: String) -> Result<Self, AnoncredsError> {
        let core_def: AnoncredsCredential = serde_json::from_str(&jsonString).map_err(|_| AnoncredsError::ConversionError)?;
        return Ok(Credential { core: core_def })
    }

    pub fn get_schema_id(&self) -> SchemaId {
        self.core.schema_id.clone()
    }

    pub fn get_cred_def_id(&self) -> CredentialDefinitionId {
        self.core.cred_def_id.clone()
    }

    pub fn get_rev_reg_id(&self) -> Option<RevocationRegistryId> {
        self.core.rev_reg_id.clone()
    }

    pub fn get_values(&self) -> CredentialValues {
        self.core.values.clone().into()
    }

    pub fn get_signature_json(&self) -> String {
        serde_json::to_string(&self.core.signature).unwrap()
    }

    pub fn get_signature_correctness_proof_json(&self) -> String {
        serde_json::to_string(&self.core.signature_correctness_proof).unwrap()
    }

    pub fn get_rev_reg_json(&self) -> Option<String> {
        serde_json::to_string(&self.core.rev_reg).ok()
    }

    pub fn get_witness_json(&self) -> Option<String> {
        serde_json::to_string(&self.core.witness).ok()
    }

    pub fn get_json(&self) -> Result<String, AnoncredsError> {
        serde_json::to_string(&self.core).map_err(|_| AnoncredsError::ConversionError)
    }
}