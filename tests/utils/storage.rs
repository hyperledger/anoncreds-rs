use anoncreds::data_types::cred_def::{CredentialDefinition, CredentialDefinitionId};
use anoncreds::data_types::rev_reg_def::RevocationRegistryDefinitionId;
use anoncreds::data_types::schema::{Schema, SchemaId};
use anoncreds::data_types::w3c::credential::W3CCredential;
use anoncreds::types::{
    Credential, CredentialDefinitionPrivate, CredentialKeyCorrectnessProof, CredentialOffer,
    CredentialRequest, CredentialRequestMetadata, CredentialRevocationState, LinkSecret,
    RevocationRegistryDefinition, RevocationRegistryDefinitionPrivate, RevocationStatusList,
};
use std::collections::HashMap;

#[derive(Debug)]
pub struct StoredCredDef {
    pub public: CredentialDefinition,
    pub private: CredentialDefinitionPrivate,
    pub key_proof: CredentialKeyCorrectnessProof,
}

#[derive(Debug)]
pub struct StoredRevDef {
    pub public: RevocationRegistryDefinition,
    pub private: RevocationRegistryDefinitionPrivate,
}

#[derive(Debug, Default)]
pub struct Ledger<'a> {
    pub cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition>,
    pub schemas: HashMap<SchemaId, Schema>,
    pub rev_reg_defs: HashMap<RevocationRegistryDefinitionId, RevocationRegistryDefinition>,
    pub revocation_list: HashMap<&'a str, HashMap<u64, RevocationStatusList>>,
}

// A struct for keeping all issuer-related objects together
#[derive(Debug, Default)]
pub struct IssuerWallet {
    // cred_def_id: StoredRevDef
    pub cred_defs: HashMap<String, StoredCredDef>,
    // revocation_reg_id: StoredRevDef
    pub rev_defs: HashMap<String, StoredRevDef>,
}

// A struct for keeping all issuer-related objects together
#[derive(Debug)]
pub struct ProverWallet<'a> {
    pub entropy: &'static str,
    pub link_secret_id: &'static str,
    pub credentials: HashMap<String, Credential>,
    pub w3c_credentials: HashMap<String, W3CCredential>,
    pub rev_states: HashMap<String, (Option<CredentialRevocationState>, Option<u64>)>,
    pub link_secret: LinkSecret,
    pub cred_offers: HashMap<&'a str, CredentialOffer>,
    pub cred_reqs: Vec<(CredentialRequest, CredentialRequestMetadata)>,
}

impl<'a> Default for ProverWallet<'a> {
    fn default() -> Self {
        let link_secret = LinkSecret::new().expect("Error creating prover link secret");
        Self {
            entropy: "entropy",
            link_secret_id: "default",
            credentials: HashMap::new(),
            rev_states: HashMap::new(),
            link_secret,
            cred_offers: HashMap::new(),
            cred_reqs: vec![],
            w3c_credentials: HashMap::new(),
        }
    }
}

// A struct for keeping all verifier-related objects together
#[derive(Debug, Default)]
pub struct VerifierWallet {}
