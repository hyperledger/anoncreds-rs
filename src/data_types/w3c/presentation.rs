use serde::{Deserialize, Serialize};

use crate::data_types::w3c::constants::{ANONCREDS_PRESENTATION_TYPES, W3C_PRESENTATION_TYPE};
use crate::data_types::w3c::context::Contexts;
use crate::data_types::w3c::credential::{Types, W3CCredential};
use crate::data_types::w3c::proof::{DataIntegrityProof, PresentationProofValue};
use crate::data_types::w3c::VerifiableCredentialSpecVersion;
use crate::Result;

/// AnonCreds W3C Presentation definition
/// Note, that this definition is tied to AnonCreds W3C form
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
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
        version: Option<&VerifiableCredentialSpecVersion>,
    ) -> Self {
        let version = version.cloned().unwrap_or_default();
        Self {
            context: Contexts::get(&version),
            type_: ANONCREDS_PRESENTATION_TYPES.clone(),
            verifiable_credential,
            proof,
        }
    }

    pub fn version(&self) -> Result<VerifiableCredentialSpecVersion> {
        self.context.version()
    }

    pub fn get_presentation_proof(&self) -> Result<&PresentationProofValue> {
        self.proof.get_presentation_proof()
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

#[cfg(test)]
mod tests {
    use super::W3CPresentation;

    #[test]
    fn serde_w3c_presentation() {
        let pres_json = include_str!("sample_presentation.json");
        let pres1: W3CPresentation =
            serde_json::from_str(&pres_json).expect("Error deserializing w3c presentation");
        let out_json = serde_json::to_string(&pres1).expect("Error serializing w3c presentation");
        let pres2: W3CPresentation =
            serde_json::from_str(&out_json).expect("Error deserializing w3c presentation");
        assert_eq!(pres1, pres2);
    }

    #[test]
    fn serde_w3c_presentation_deny_unknown() {
        let pres_json = include_str!("sample_presentation.json");
        let mut pres: serde_json::Value =
            serde_json::from_str(pres_json).expect("Error deserializing w3c presentation");
        pres.as_object_mut()
            .unwrap()
            .insert("prop".into(), "val".into());
        let res = serde_json::from_value::<W3CPresentation>(pres);
        assert!(res.is_err());
    }
}
