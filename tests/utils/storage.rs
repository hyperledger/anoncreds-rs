use anoncreds::data_types::cred_def::{CredentialDefinition, CredentialDefinitionId};
use anoncreds::data_types::credential::Credential;
use anoncreds::data_types::link_secret::LinkSecret;
use anoncreds::data_types::rev_reg::RevocationRegistryId;
use anoncreds::data_types::rev_reg_def::{
    RevocationRegistryDefinition, RevocationRegistryDefinitionId,
    RevocationRegistryDefinitionPrivate,
};
use anoncreds::data_types::schema::{Schema, SchemaId};
use anoncreds::types::{
    CredentialDefinitionPrivate, CredentialKeyCorrectnessProof, CredentialOffer, CredentialRequest,
    CredentialRequestMetadata, CredentialRevocationState, RevocationStatusList,
};
use std::collections::HashMap;

#[derive(Debug)]
pub struct StoredCredDef {
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
    // CredentialDefinition does not impl Clone
    pub cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition>,
    pub schemas: HashMap<SchemaId, Schema>,
    pub rev_reg_defs: HashMap<RevocationRegistryDefinitionId, RevocationRegistryDefinition>,
    pub revcation_list: HashMap<&'a str, HashMap<u64, RevocationStatusList>>,
}

// A struct for keeping all issuer-related objects together
#[derive(Debug)]
pub struct IssuerWallet<'a> {
    // cred_def_id: StoredRevDef
    pub cred_defs: HashMap<&'a str, StoredCredDef>,
    // revocation_reg_id: StoredRevDef
    pub rev_defs: HashMap<&'a str, StoredRevDef>,
}

impl<'a> Default for IssuerWallet<'a> {
    fn default() -> Self {
        Self {
            cred_defs: HashMap::new(),
            rev_defs: HashMap::new(),
        }
    }
}

// A struct for keeping all issuer-related objects together
#[derive(Debug)]
pub struct ProverWallet<'a> {
    pub credentials: Vec<Credential>,
    pub rev_states: HashMap<RevocationRegistryId, (Option<CredentialRevocationState>, Option<u64>)>,
    pub link_secret: LinkSecret,
    pub cred_offers: HashMap<&'a str, CredentialOffer>,
    pub cred_reqs: Vec<(CredentialRequest, CredentialRequestMetadata)>,
}

impl<'a> Default for ProverWallet<'a> {
    fn default() -> Self {
        let link_secret = LinkSecret::new().expect("Error creating prover link secret");
        Self {
            credentials: vec![],
            rev_states: HashMap::new(),
            link_secret,
            cred_offers: HashMap::new(),
            cred_reqs: vec![],
        }
    }
}
