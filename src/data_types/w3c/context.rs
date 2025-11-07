use crate::data_types::w3c::VerifiableCredentialSpecVersion;
use crate::data_types::w3c::constants::{
    ANONCREDS_VC_1_1_CONTEXTS, ANONCREDS_VC_2_0_CONTEXTS, ISSUER_DEPENDENT_VOCABULARY,
    W3C_DATA_INTEGRITY_CONTEXT, W3C_VC_1_1_BASE_CONTEXT, W3C_VC_2_0_BASE_CONTEXT,
};
use crate::data_types::w3c::uri::URI;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Context {
    URI(URI),
    Object(serde_json::Value),
}

impl Context {
    pub fn uri(&self) -> crate::Result<&URI> {
        match self {
            Context::URI(uri) => Ok(uri),
            Context::Object(_) => Err(err_msg!("Unable to get URI context")),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Contexts(pub Vec<Context>);

impl Contexts {
    pub fn get(version: &VerifiableCredentialSpecVersion) -> Contexts {
        match version {
            VerifiableCredentialSpecVersion::V1_1 => ANONCREDS_VC_1_1_CONTEXTS.clone(),
            VerifiableCredentialSpecVersion::V2_0 => ANONCREDS_VC_2_0_CONTEXTS.clone(),
        }
    }

    pub fn version(&self) -> crate::Result<VerifiableCredentialSpecVersion> {
        // First context defines the version of verifiable credential
        let first_context = self
            .0
            .get(0)
            .ok_or_else(|| err_msg!("Credential does not contain any context"))?
            .uri()?;

        if first_context.0 == W3C_VC_1_1_BASE_CONTEXT {
            return Ok(VerifiableCredentialSpecVersion::V1_1);
        }
        if first_context.0 == W3C_VC_2_0_BASE_CONTEXT {
            return Ok(VerifiableCredentialSpecVersion::V2_0);
        }

        Err(err_msg!("Unexpected context {:?}", first_context))
    }

    pub fn validate(&self) -> crate::Result<()> {
        let vc_version = self.version()?;
        if vc_version == VerifiableCredentialSpecVersion::V1_1 {
            // for VC 1.1 credential context must include extra context for data integrity proofs
            // for VC 2.0 it's included in the main one
            if !self
                .0
                .contains(&Context::URI(URI::from(W3C_DATA_INTEGRITY_CONTEXT)))
            {
                return Err(err_msg!(
                    "Credential does not contain w3c data integrity context"
                ));
            }
        }

        if !self
            .0
            .contains(&Context::Object(ISSUER_DEPENDENT_VOCABULARY.clone()))
        {
            return Err(err_msg!(
                "Credential does not contain issuer vocabulary context"
            ));
        }
        Ok(())
    }
}
