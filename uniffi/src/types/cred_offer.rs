use crate::types::error::AnoncredsError;
use crate::types::nonce::Nonce;
use anoncreds_core::data_types::schema::SchemaId;
use anoncreds_core::data_types::cred_def::{
    CredentialDefinitionId,
    SignatureType
};
use anoncreds_core::data_types::cred_offer::{CredentialOffer as AnoncredsCredentialOffer};
use std::convert::TryFrom;
use std::convert::TryInto;
use serde::{Deserialize, Serialize};
use serde_json::Result as SerdeResult;
use std::sync::Arc;

pub struct CredentialOffer {
    pub core: AnoncredsCredentialOffer,
}

impl CredentialOffer {
    pub fn new(jsonString: String) -> Result<Self, AnoncredsError> {
        let core_def: AnoncredsCredentialOffer = serde_json::from_str(&jsonString).map_err(|_| AnoncredsError::ConversionError)?;
        return Ok(CredentialOffer { core: core_def })
    }

    pub fn get_schema_id(&self) -> SchemaId {
        self.core.schema_id.clone()
    }

    pub fn get_cred_def_id(&self) -> CredentialDefinitionId {
        self.core.cred_def_id.clone()
    }

    pub fn get_key_correctness_proof(&self) -> String {
        serde_json::to_string(&self.core.key_correctness_proof).unwrap()
    }

    pub fn get_nonce(&self) -> Arc<Nonce> {
        let original = self.core.nonce.try_clone().unwrap();
        return Arc::new(Nonce { anoncreds_nonce: original })
    }

    pub fn get_method_name(&self) -> Option<String> {
        self.core.method_name.clone()
    }
}

impl Clone for CredentialOffer {
    fn clone(&self) -> Self {
        let cloned_schema_id = self.core.schema_id.clone();
        let cloned_cred_def = self.core.cred_def_id.clone();
        let cloned_get_key_correctness_proof = self.core.key_correctness_proof.try_clone().unwrap();
        let cloned_nonce = self.core.nonce.try_clone().unwrap();
        let cloned_method_name = self.core.method_name.clone();
        let cloned_offer = AnoncredsCredentialOffer {
            schema_id: cloned_schema_id,
            cred_def_id: cloned_cred_def,
            key_correctness_proof: cloned_get_key_correctness_proof,
            nonce: cloned_nonce,
            method_name: cloned_method_name
        };
        return CredentialOffer { core: cloned_offer }
    }
}

impl TryFrom<AnoncredsCredentialOffer> for CredentialOffer {
    type Error = AnoncredsError;

    fn try_from(acr: AnoncredsCredentialOffer) -> Result<Self, Self::Error> {
        Ok(CredentialOffer { core: acr })
    }
}

impl TryFrom<&CredentialOffer> for AnoncredsCredentialOffer {
    type Error = AnoncredsError;

    fn try_from(acr: &CredentialOffer) -> Result<Self, Self::Error> {
        let cloned_schema_id = acr.core.schema_id.clone();
        let cloned_cred_def = acr.core.cred_def_id.clone();
        let cloned_get_key_correctness_proof = acr.core.key_correctness_proof.try_clone().unwrap();
        let cloned_nonce = acr.core.nonce.try_clone().unwrap();
        let cloned_method_name = acr.core.method_name.clone();
        let cloned_offer = AnoncredsCredentialOffer {
            schema_id: cloned_schema_id,
            cred_def_id: cloned_cred_def,
            key_correctness_proof: cloned_get_key_correctness_proof,
            nonce: cloned_nonce,
            method_name: cloned_method_name
        };
        Ok(cloned_offer)
    }
}