use std::collections::HashMap;

use super::tails::TailsReader;
pub use indy_data_types::{
    anoncreds::{
        cred_def::{
            CredentialDefinition, CredentialDefinitionPrivate, CredentialKeyCorrectnessProof,
            SignatureType,
        },
        cred_offer::CredentialOffer,
        cred_request::{CredentialRequest, CredentialRequestMetadata},
        credential::{AttributeValues, Credential, CredentialValues},
        master_secret::MasterSecret,
        pres_request::PresentationRequest,
        presentation::Presentation,
        rev_reg::{RevocationRegistry, RevocationRegistryDelta},
        rev_reg_def::{
            IssuanceType, RegistryType, RevocationRegistryDefinition,
            RevocationRegistryDefinitionPrivate,
        },
        schema::{AttributeNames, Schema},
    },
    CredentialDefinitionId, RevocationRegistryId, SchemaId,
};
pub use indy_utils::did::DidValue;
use indy_utils::{invalid, Validatable, ValidationError};

use crate::ursa::cl::{RevocationRegistry as CryptoRevocationRegistry, Witness};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDefinitionConfig {
    pub support_revocation: bool,
}

impl CredentialDefinitionConfig {
    pub fn new(support_revocation: bool) -> Self {
        Self { support_revocation }
    }
}

impl Default for CredentialDefinitionConfig {
    fn default() -> Self {
        Self {
            support_revocation: false,
        }
    }
}

impl Validatable for CredentialDefinitionConfig {}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct RequestedCredentials {
    pub(crate) self_attested_attributes: HashMap<String, String>,
    pub(crate) requested_attributes: HashMap<String, RequestedAttribute>,
    pub(crate) requested_predicates: HashMap<String, ProvingCredentialKey>,
}

impl RequestedCredentials {
    pub fn add_self_attested(&mut self, referent: String, value: String) {
        self.self_attested_attributes.insert(referent, value);
    }

    pub fn add_requested_attribute(
        &mut self,
        referent: String,
        cred_id: String,
        timestamp: Option<u64>,
        revealed: bool,
    ) {
        self.requested_attributes.insert(
            referent,
            RequestedAttribute {
                cred_id,
                timestamp,
                revealed,
            },
        );
    }

    pub fn add_requested_predicate(
        &mut self,
        referent: String,
        cred_id: String,
        timestamp: Option<u64>,
    ) {
        self.requested_predicates
            .insert(referent, ProvingCredentialKey { cred_id, timestamp });
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RequestedAttribute {
    pub cred_id: String,
    pub timestamp: Option<u64>,
    pub revealed: bool,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq, Hash, Clone)]
pub(crate) struct ProvingCredentialKey {
    pub cred_id: String,
    pub timestamp: Option<u64>,
}

impl Validatable for RequestedCredentials {
    fn validate(&self) -> std::result::Result<(), ValidationError> {
        if self.self_attested_attributes.is_empty()
            && self.requested_attributes.is_empty()
            && self.requested_predicates.is_empty()
        {
            return Err(invalid!(
                "Requested Credentials validation failed: `self_attested_attributes` and `requested_attributes` and `requested_predicates` are empty"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialRevocationState {
    pub(crate) witness: Witness,
    pub(crate) rev_reg: CryptoRevocationRegistry,
    pub(crate) timestamp: u64,
}

impl Validatable for CredentialRevocationState {
    fn validate(&self) -> std::result::Result<(), ValidationError> {
        if self.timestamp == 0 {
            return Err(invalid!(
                "Credential Revocation State validation failed: `timestamp` must be greater than 0",
            ));
        }
        Ok(())
    }
}

pub struct CredentialRevocationConfig<'a> {
    pub reg_def: &'a RevocationRegistryDefinition,
    pub reg_def_private: &'a RevocationRegistryDefinitionPrivate,
    pub registry: &'a RevocationRegistry,
    pub registry_idx: u32,
    pub tails_reader: TailsReader,
}

impl<'a> std::fmt::Debug for CredentialRevocationConfig<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CredentialRevocationConfig {{ reg_def: {:?}, private: {:?}, registry: {:?}, idx: {}, reader: {:?} }}",
            self.reg_def,
            secret!(self.reg_def_private),
            self.registry,
            secret!(self.registry_idx),
            self.tails_reader,
        )
    }
}
