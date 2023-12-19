use crate::data_types::pres_request::{PredicateInfo, PredicateTypes};
use serde::{Deserialize, Serialize};

use crate::data_types::w3c::constants::ANONCREDS_PRESENTATION_TYPES;
use crate::data_types::w3c::context::Contexts;
use crate::data_types::w3c::credential::Types;
use crate::data_types::w3c::proof::PresentationProofValue;
use crate::data_types::w3c::proof::{CryptoSuite, DataIntegrityProof};
use crate::data_types::w3c::{
    constants::W3C_PRESENTATION_TYPE, credential::W3CCredential, VerifiableCredentialSpecVersion,
};
use crate::Result;

/// AnonCreds W3C Presentation definition
/// Note, that this definition is tied to AnonCreds W3C form
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct W3CPresentation {
    #[serde(rename = "@context")]
    pub context: Contexts,
    #[serde(alias = "@type")]
    #[serde(rename = "type")]
    pub type_: Types,
    pub verifiable_credential: Vec<W3CCredential>,
    pub proof: DataIntegrityProof,
}

impl W3CPresentation {
    pub fn new(
        verifiable_credential: Vec<W3CCredential>,
        proof: DataIntegrityProof,
        version: Option<VerifiableCredentialSpecVersion>,
    ) -> Self {
        let version = version.unwrap_or_default();
        Self {
            context: Contexts::get(version),
            type_: ANONCREDS_PRESENTATION_TYPES.clone(),
            verifiable_credential,
            proof,
        }
    }

    pub fn version(&self) -> Result<VerifiableCredentialSpecVersion> {
        self.context.version()
    }

    pub fn get_presentation_proof(&self) -> Result<PresentationProofValue> {
        if self.proof.cryptosuite != CryptoSuite::AnonCredsPresVp2023 {
            return Err(err_msg!(
                "Credential does not contain anoncredspresvc-2023 proof"
            ));
        }
        self.proof.get_proof_value()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.context.validate()?;
        if !self.type_.0.contains(&W3C_PRESENTATION_TYPE.to_string()) {
            return Err(err_msg!(
                "Credential does not contain w3c presentation type"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct PredicateAttribute {
    #[serde(rename = "type")]
    pub type_: PredicateAttributeType,
    pub predicate: PredicateTypes,
    pub value: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PredicateAttributeType {
    #[serde(rename = "AnonCredsPredicate")]
    AnonCredsPredicate,
}

impl Default for PredicateAttributeType {
    fn default() -> Self {
        PredicateAttributeType::AnonCredsPredicate
    }
}

impl From<PredicateInfo> for PredicateAttribute {
    fn from(info: PredicateInfo) -> Self {
        PredicateAttribute {
            type_: PredicateAttributeType::AnonCredsPredicate,
            predicate: info.p_type,
            value: info.p_value,
        }
    }
}
