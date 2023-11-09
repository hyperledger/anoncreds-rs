use serde::{Deserialize, Serialize};

use crate::data_types::w3c::credential::{Contexts, Types};
use crate::data_types::w3c::presentation_proof::PresentationProof;
use crate::data_types::w3c::{
    constants::{
        W3C_ANONCREDS_CONTEXT, W3C_ANONCREDS_CREDENTIAL_TYPE, W3C_CONTEXT, W3C_CREDENTIAL_TYPE,
    },
    credential::W3CCredential,
    uri::URI,
};
use crate::Result;

/// AnonCreds W3C Presentation definition
/// Note, that this definition is tied to AnonCreds W3C form
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct W3CPresentation {
    #[serde(rename = "@context")]
    pub context: Contexts,
    #[serde(rename = "type")]
    pub type_: Types,
    pub verifiable_credential: Vec<W3CCredential>,
    pub proof: PresentationProof,
}

impl W3CPresentation {
    pub fn validate(&self) -> Result<()> {
        if !self.context.0.contains(&URI(W3C_CONTEXT.to_string())) {
            return Err(err_msg!("Credential does not contain w3c context"));
        }
        if !self
            .context
            .0
            .contains(&URI(W3C_ANONCREDS_CONTEXT.to_string()))
        {
            return Err(err_msg!(
                "Credential does not contain w3c anoncreds context"
            ));
        }
        if !self.type_.0.contains(W3C_CREDENTIAL_TYPE) {
            return Err(err_msg!("Credential does not contain w3c credential type"));
        }
        if !self.type_.0.contains(W3C_ANONCREDS_CREDENTIAL_TYPE) {
            return Err(err_msg!(
                "Credential does not contain w3c anoncreds credential type"
            ));
        }
        Ok(())
    }
}
