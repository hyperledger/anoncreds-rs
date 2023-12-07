use crate::cl::{RevocationRegistry as CryptoRevocationRegistry, Witness};
pub use crate::data_types::{
    cred_def::{CredentialDefinitionPrivate, CredentialKeyCorrectnessProof, SignatureType},
    cred_offer::CredentialOffer,
    cred_request::{CredentialRequest, CredentialRequestMetadata},
    credential::{AttributeValues, Credential, CredentialValues},
    link_secret::LinkSecret,
    pres_request::PresentationRequest,
    presentation::Presentation,
    rev_reg::RevocationRegistry,
    rev_reg_def::{
        RegistryType, RevocationRegistryDefinition, RevocationRegistryDefinitionPrivate,
    },
    rev_status_list::RevocationStatusList,
    schema::AttributeNames,
};
use crate::services::helpers::encode_credential_attribute;
use crate::{
    error::{Error, ValidationError},
    invalid,
    utils::validation::Validatable,
};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredentialDefinitionConfig {
    pub support_revocation: bool,
}

impl CredentialDefinitionConfig {
    #[must_use]
    pub const fn new(support_revocation: bool) -> Self {
        Self { support_revocation }
    }
}

impl Validatable for CredentialDefinitionConfig {}

#[derive(Debug, Default)]
pub struct MakeCredentialValues(pub(crate) CredentialValues);

impl MakeCredentialValues {
    pub fn add_encoded(
        &mut self,
        name: impl Into<String>,
        raw: impl Into<String>,
        encoded: String,
    ) {
        self.0 .0.insert(
            name.into(),
            AttributeValues {
                raw: raw.into(),
                encoded,
            },
        );
    }

    pub fn add_raw(
        &mut self,
        name: impl Into<String>,
        raw: impl Into<String>,
    ) -> Result<(), Error> {
        let raw = raw.into();
        let encoded = encode_credential_attribute(&raw)?;
        self.0
             .0
            .insert(name.into(), AttributeValues { raw, encoded });
        Ok(())
    }
}

impl From<MakeCredentialValues> for CredentialValues {
    fn from(m: MakeCredentialValues) -> Self {
        m.0
    }
}

#[derive(Debug)]
pub struct PresentCredentials<'p, T>(pub(crate) Vec<PresentCredential<'p, T>>);

impl<'p, T> Default for PresentCredentials<'p, T> {
    fn default() -> Self {
        PresentCredentials(Vec::new())
    }
}

impl<'p, T> PresentCredentials<'p, T> {
    pub fn add_credential(
        &mut self,
        cred: &'p T,
        timestamp: Option<u64>,
        rev_state: Option<&'p CredentialRevocationState>,
    ) -> AddCredential<'_, 'p, T> {
        let idx = self.0.len();
        self.0.push(PresentCredential {
            cred,
            timestamp,
            rev_state,
            requested_attributes: HashSet::new(),
            requested_predicates: HashSet::new(),
        });
        AddCredential {
            present: &mut self.0[idx],
        }
    }

    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.iter().filter(|c| !c.is_empty()).count()
    }
}

impl<T> Validatable for PresentCredentials<'_, T> {
    fn validate(&self) -> std::result::Result<(), ValidationError> {
        let mut attr_names = HashSet::new();
        let mut pred_names = HashSet::new();

        for c in &self.0 {
            for (name, _reveal) in &c.requested_attributes {
                if !attr_names.insert(name.as_str()) {
                    return Err(invalid!("Duplicate requested attribute referent: {}", name));
                }
            }

            for name in &c.requested_predicates {
                if !pred_names.insert(name.as_str()) {
                    return Err(invalid!("Duplicate requested predicate referent: {}", name));
                }
            }

            if c.timestamp.is_some() != c.rev_state.is_some() {
                return Err(invalid!(
                    "Either timestamp and revocation state must be presented, or neither"
                ));
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct PresentCredential<'p, T> {
    pub cred: &'p T,
    pub timestamp: Option<u64>,
    pub rev_state: Option<&'p CredentialRevocationState>,
    pub requested_attributes: HashSet<(String, bool)>,
    pub requested_predicates: HashSet<String>,
}

impl<T> PresentCredential<'_, T> {
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.requested_attributes.is_empty() && self.requested_predicates.is_empty()
    }

    pub(crate) fn revealed_attributes(&self) -> HashSet<String> {
        let mut referents = HashSet::new();
        for (referent, revealed) in self.requested_attributes.iter() {
            if *revealed {
                referents.insert(referent.to_string());
            }
        }
        referents
    }
}

#[derive(Debug)]
pub struct AddCredential<'a, 'p, T> {
    present: &'a mut PresentCredential<'p, T>,
}

impl<'a, 'p, T> AddCredential<'a, 'p, T> {
    pub fn add_requested_attribute(&mut self, referent: impl Into<String>, revealed: bool) {
        self.present
            .requested_attributes
            .insert((referent.into(), revealed));
    }

    pub fn add_requested_predicate(&mut self, referent: impl Into<String>) {
        self.present.requested_predicates.insert(referent.into());
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct RequestedAttribute<'a> {
    pub cred_id: String,
    pub timestamp: Option<u64>,
    pub revealed: bool,
    pub rev_state: Option<&'a CredentialRevocationState>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct RequestedPredicate<'a> {
    pub cred_id: String,
    pub timestamp: Option<u64>,
    pub rev_state: Option<&'a CredentialRevocationState>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ProvingCredentialKey {
    pub cred_id: String,
    pub timestamp: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialRevocationState {
    pub witness: Witness,
    pub rev_reg: CryptoRevocationRegistry,
    pub timestamp: u64,
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
    pub status_list: &'a RevocationStatusList,
    pub registry_idx: u32,
}

impl<'a> std::fmt::Debug for CredentialRevocationConfig<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CredentialRevocationConfig {{ reg_def: {:?}, private: {:?}, status_list: {:?}, idx: {} }}",
            self.reg_def,
            secret!(self.reg_def_private),
            self.status_list,
            secret!(self.registry_idx),
        )
    }
}
