use crate::error::AnoncredsError;
use crate::types::cred_def::CredentialDefinition;
use crate::types::cred_offer::CredentialOffer;
use crate::types::cred_req::{CredentialRequest, CredentialRequestMetadata};
use crate::types::link_secret::LinkSecret;
use crate::PresentationRequest;
use crate::RevocationRegistryDefinition;
use crate::{Credential, Presentation};
use anoncreds_core::data_types::cred_def::CredentialDefinitionId;
use anoncreds_core::data_types::schema::{Schema, SchemaId};
use anoncreds_core::prover;
use anoncreds_core::types::PresentCredentials as AnoncredsPresentCredentials;
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::Arc;

pub struct CreateCrendentialRequestResponse {
    pub request: Arc<CredentialRequest>,
    pub metadata: CredentialRequestMetadata,
}

pub struct RequestedAttribute {
    pub referent: String,
    pub revealed: bool,
}
pub struct RequestedPredicate {
    pub referent: String,
}
pub struct CredentialRequests {
    pub credential: Arc<Credential>,
    pub requested_attribute: Vec<RequestedAttribute>,
    pub requested_predicate: Vec<RequestedPredicate>,
}

pub struct Prover {}

impl Prover {
    pub fn new() -> Self {
        Prover {}
    }

    pub fn create_link_secret(&self) -> Arc<LinkSecret> {
        let secret = LinkSecret::new();
        Arc::new(secret)
    }

    pub fn create_credential_request(
        &self,
        entropy: Option<String>,
        prover_did: Option<String>,
        cred_def: Arc<CredentialDefinition>,
        link_secret: Arc<LinkSecret>,
        link_secret_id: String,
        credential_offer: Arc<CredentialOffer>,
    ) -> Result<CreateCrendentialRequestResponse, AnoncredsError> {
        let cred_def_clone = Arc::clone(&cred_def);
        let cred_def_inner = cred_def_clone.as_ref();
        let cred_def_core = cred_def_inner.clone().try_into()?;
        let link_secret_core = (*link_secret).clone().secret;
        let cred_offer_core = (*credential_offer).clone().core;

        let (request, metadata) = anoncreds_core::prover::create_credential_request(
            entropy.as_ref().map(|s| s.as_str()),
            prover_did.as_ref().map(|s| s.as_str()),
            &cred_def_core,
            &link_secret_core,
            link_secret_id.as_str(),
            &cred_offer_core,
        )
        .map_err(|err| AnoncredsError::CreateCrentialRequestError(format!("Error: {}", err)))?;

        return Ok(CreateCrendentialRequestResponse {
            request: Arc::new(CredentialRequest { core: request }),
            metadata: CredentialRequestMetadata::from(metadata),
        });
    }

    pub fn process_credential(
        &self,
        credential: Arc<Credential>,
        cred_request_metadata: CredentialRequestMetadata,
        link_secret: Arc<LinkSecret>,
        cred_def: Arc<CredentialDefinition>,
        rev_reg_def: Option<Arc<RevocationRegistryDefinition>>,
    ) -> Result<Arc<Credential>, AnoncredsError> {
        let mut mutable_credential = (*credential)
            .core
            .try_clone()
            .map_err(|_| AnoncredsError::ConversionError)?;
        prover::process_credential(
            &mut mutable_credential,
            &cred_request_metadata.into(),
            &(*link_secret).secret,
            &(*cred_def).core,
            rev_reg_def.as_ref().map(|def| &(*def).core),
        )
        .map_err(|err| AnoncredsError::ProcessCredential(format!("Error: {}", err)));

        return Ok(Arc::new(Credential { core: mutable_credential }))
    }

    pub fn create_presentation(
        &self,
        presentation_request: Arc<PresentationRequest>,
        credentials: Vec<CredentialRequests>,
        self_attested: Option<HashMap<String, String>>,
        link_secret: Arc<LinkSecret>,
        schemas: HashMap<SchemaId, Schema>,
        credential_definitions: HashMap<CredentialDefinitionId, Arc<CredentialDefinition>>,
    ) -> Result<Arc<Presentation>, AnoncredsError> {
        let pres_req = &presentation_request.core;

        let mut present_credentials = AnoncredsPresentCredentials::default();
        let timestamp = None; // TODO
        let rev_state = None; //TODO

        credentials.iter().for_each(|c| {
            let cred = &c.credential.core;
            let mut tmp = present_credentials.add_credential(cred, timestamp, rev_state);

            c.requested_attribute.iter().for_each(|attribute| {
                tmp.add_requested_attribute(attribute.referent.to_string(), attribute.revealed);
            });

            c.requested_predicate.iter().for_each(|predicate| {
                tmp.add_requested_predicate(predicate.referent.to_string());
            });
        });

        let schemas_anoncreds = schemas.iter().map(|(k, v)| (k, v)).collect();
        let cred_defs = credential_definitions
            .iter()
            .map(|(k, v)| {
                let tmp = &v.core;
                (k, tmp)
            })
            .collect();

        return prover::create_presentation(
            pres_req,
            present_credentials,
            self_attested,
            &link_secret.secret,
            &schemas_anoncreds,
            &cred_defs,
        )
        .map_err(|err| AnoncredsError::CreatePresentationError(format!("Error: {}", err)))
        .map(|e| Arc::new(Presentation { core: e }));
    }
}
