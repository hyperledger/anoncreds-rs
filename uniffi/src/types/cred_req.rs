use crate::types::error::AnoncredsError;
use crate::types::nonce::Nonce;
use anoncreds_core::data_types::cred_request::{CredentialRequest as AnoncredsCredentialRequest, CredentialRequestMetadata as AnoncredsCredentialRequestMetadata};
use std::sync::Arc;

pub struct CredentialRequest {
    pub core: AnoncredsCredentialRequest
}

impl CredentialRequest {
    pub fn new(json_string: String) -> Result<Self, AnoncredsError> {
        let core_def: AnoncredsCredentialRequest =
            serde_json::from_str(&json_string).map_err(|_| AnoncredsError::ConversionError)?;
        return Ok(CredentialRequest { core: core_def });
    }

    pub fn get_blinded_credential_secrets_json(&self) -> String {
        serde_json::to_string(&self.core.blinded_ms).unwrap()
    }

    pub fn get_blinded_credential_secrets_correctness_proof_json(&self) -> String {
        serde_json::to_string(&self.core.blinded_ms_correctness_proof).unwrap()
    }

    pub fn get_nonce(&self) -> Arc<Nonce> {
        return Arc::new(Nonce { anoncreds_nonce: self.core.nonce.try_clone().unwrap() })
    }

    pub fn get_json(&self) -> Result<String, AnoncredsError> {
        serde_json::to_string(&self.core).map_err(|_| AnoncredsError::ConversionError)
    }
}

pub struct CredentialRequestMetadata {
    pub link_secret_blinding_data: String,
    pub nonce: Arc<Nonce>,
    pub link_secret_name: String,
}

// impl CredentialRequestMetadata {
//     pub fn new(json_string: String) -> Result<Self, AnoncredsError> {
//         let core_def: AnoncredsCredentialRequest =
//             serde_json::from_str(&json_string).map_err(|_| AnoncredsError::ConversionError)?;
//         return Ok(CredentialRequestMetadata { core: core_def });
//     }

//     pub fn get_json(&self) -> Result<String, AnoncredsError> {
//         serde_json::to_string(&self.core).map_err(|_| AnoncredsError::ConversionError)
//     }
// }

impl Into<AnoncredsCredentialRequestMetadata> for CredentialRequestMetadata {
    fn into(self) -> AnoncredsCredentialRequestMetadata {
        let link_secret_core: ursa::cl::CredentialSecretsBlindingFactors = serde_json::from_str(&self.link_secret_blinding_data).unwrap();
        let nonce_unwrap = (*self.nonce).clone();
        let nonce_core = nonce_unwrap.anoncreds_nonce;
        AnoncredsCredentialRequestMetadata {
            link_secret_blinding_data: link_secret_core,
            nonce: nonce_core,
            link_secret_name: self.link_secret_name
        }
    }
}

impl From<AnoncredsCredentialRequestMetadata> for CredentialRequestMetadata {
    fn from(acr: AnoncredsCredentialRequestMetadata) -> Self {
        let link_secret_blinding_data_str = serde_json::to_string(&acr.link_secret_blinding_data).expect("Failed to serialize link_secret_blinding_data");
        let nonce_core = Arc::new(Nonce { anoncreds_nonce: acr.nonce});
        return CredentialRequestMetadata {
            link_secret_blinding_data: link_secret_blinding_data_str,
            nonce: nonce_core,
            link_secret_name: acr.link_secret_name
        }
    }
}