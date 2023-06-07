use anoncreds_core::prover::*;
use anoncreds_core::data_types::cred_request::{CredentialRequest as AnoncredsCredentialRequest, CredentialRequestMetadata as AnoncredsCredentialRequestMetadata};
use super::types::*;
use std::sync::Arc;
use std::convert::TryInto;

pub struct CreateCrendentialRequestResponse {
    pub request: Arc<CredentialRequest>,
    pub metadata: CredentialRequestMetadata,
}

pub struct Prover {
    str: String,
}

impl Prover {
    pub fn new() -> Self {
        Prover {
            str: String::from("Hello world!"),
        }
    }

    pub fn create_credential_request(
        &self,
        entropy: &str,
        prover_did: &str,
        cred_def: &Arc<CredentialDefinition>,
        link_secret: &LinkSecret,
        link_secret_id: &str,
        credential_offer: &CredentialOffer,
    ) -> Result<CreateCrendentialRequestResponse, AnoncredsError> {
        let cred_def_clone = Arc::clone(&cred_def);
        let cred_def_inner = cred_def_clone.as_ref();
        let cred_def_core = cred_def_inner.clone().try_into()?;
        let link_secret_core = link_secret.try_into()?;
        let cred_offer_core = credential_offer.try_into()?;

        let (request, metadata) = anoncreds_core::prover::create_credential_request(
            Some(entropy),
            Some(prover_did),
            &cred_def_core,
            &link_secret_core,
            link_secret_id,
            &cred_offer_core
        ).map_err(|_| AnoncredsError::CreateCrentialRequestError)?;

        return Ok(CreateCrendentialRequestResponse {
            request: Arc::new(CredentialRequest { anoncreds_request: request }),
            metadata: CredentialRequestMetadata::from(metadata)
        })
    }

    pub fn create_link_secret(&self) -> Arc<LinkSecret> {
        let secret = LinkSecret::new();
        Arc::new(secret)
    }
}