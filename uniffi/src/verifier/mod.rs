use crate::error::AnoncredsError;
use crate::presentation::{Presentation, PresentationRequest};
use crate::CredentialDefinition;
use anoncreds_core::data_types::cred_def::CredentialDefinitionId;
use anoncreds_core::data_types::schema::{Schema, SchemaId};
use anoncreds_core::verifier;
use std::collections::HashMap;
use std::sync::Arc;

//https://mozilla.github.io/uniffi-rs/udl/builtin_types.html

pub struct Verifier {}

impl Verifier {
    /// Create a new instance of [Verifier]
    pub fn new() -> Self {
        Verifier {}
    }

    /// Verify an incoming proof presentation
    pub fn verify_presentation(
        &self,
        presentation: Arc<Presentation>,
        presentation_request: Arc<PresentationRequest>,
        schemas: HashMap<SchemaId, Schema>,
        credential_definitions: HashMap<CredentialDefinitionId, Arc<CredentialDefinition>>,
        //     rev_reg_defs: Option<
        //         &HashMap<&RevocationRegistryDefinitionId, &RevocationRegistryDefinition>,
        //     >,
        //     rev_status_lists: Option<Vec<&RevocationStatusList>>,
        //     nonrevoke_interval_override: Option<
        //         &HashMap<&RevocationRegistryDefinitionId, HashMap<u64, u64>>,
        //     >,
    ) -> Result<bool, AnoncredsError> {
        let schemas_anoncreds = schemas.iter().map(|(k, v)| (k, v)).collect();
        let cred_defs = credential_definitions
            .iter()
            .map(|(k, v)| {
                let tmp = &v.core;
                (k, tmp)
            })
            .collect();

        let ret = verifier::verify_presentation(
            &presentation.core, //&(*presentation_core).core
            &presentation_request.core,
            &schemas_anoncreds,
            &cred_defs,
            None, //TODO
            None, //TODO
            None, //TODO
        )
        .map_err(|err| AnoncredsError::ProcessCredentialError(format!("Error: {}", err)))?;

        return Ok(ret);
    }
}
