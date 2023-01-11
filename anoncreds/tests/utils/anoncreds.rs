use anoncreds::types::{CredentialDefinitionPrivate, CredentialKeyCorrectnessProof};

use anoncreds::data_types::anoncreds::cred_def::CredentialDefinition;
use anoncreds::data_types::anoncreds::credential::Credential;
use anoncreds::data_types::anoncreds::master_secret::MasterSecret;

pub struct StoredCredDef {
    pub public: CredentialDefinition,
    pub private: CredentialDefinitionPrivate,
    pub key_proof: CredentialKeyCorrectnessProof,
}

impl
    From<(
        CredentialDefinition,
        CredentialDefinitionPrivate,
        CredentialKeyCorrectnessProof,
    )> for StoredCredDef
{
    fn from(
        parts: (
            CredentialDefinition,
            CredentialDefinitionPrivate,
            CredentialKeyCorrectnessProof,
        ),
    ) -> Self {
        let (public, private, key_proof) = parts;
        Self {
            public,
            private,
            key_proof,
        }
    }
}

// A struct for keeping all issuer-related objects together
pub struct IssuerWallet {
    pub cred_defs: Vec<StoredCredDef>,
}

impl Default for IssuerWallet {
    fn default() -> Self {
        Self { cred_defs: vec![] }
    }
}

// A struct for keeping all issuer-related objects together
pub struct ProverWallet {
    pub credentials: Vec<Credential>,
    pub master_secret: MasterSecret,
}

impl Default for ProverWallet {
    fn default() -> Self {
        let master_secret = MasterSecret::new().expect("Error creating prover master secret");
        Self {
            credentials: vec![],
            master_secret,
        }
    }
}
