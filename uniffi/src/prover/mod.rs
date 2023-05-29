use anoncreds_core::prover::*;
use super::types::*;

enum AnoncredsError {
    CreateCrentialRequestError
}

pub struct CreateCrendentialRequestResponse {
    pub request: String,
    pub metadata: String,
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

    // pub fn create_credential_request(&self, schema_id: &SchemaID) -> String {
    //     return self.str.clone();
    // }

    pub fn create_credential_request(
        &self,
        entropy: &str,
        prover_did: &str,
        cred_def: &CredentialDefinition,
        link_secret: &SecretLink,
        link_secret_id: &str,
        credential_offer: &CredentialOffer,
    ) -> String {
        let cred_def_core = cred_def.to_core().unwrap();
        let link_secret_core = link_secret.to_core().unwrap();
        let cred_offer_core = credential_offer.to_core().unwrap();

        let result = anoncreds_core::prover::create_credential_request(
            Some(entropy),
            Some(prover_did),
            &cred_def_core,
            &link_secret_core,
            link_secret_id,
            &cred_offer_core
        );

        return String::from("Hello world!")
    }
}