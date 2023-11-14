use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::string::ToString;
use zeroize::Zeroize;

use crate::data_types::pres_request::{PredicateInfo, PredicateTypes};
use crate::data_types::w3c::constants::{ANONCREDS_CONTEXTS, ANONCREDS_TYPES};
use crate::data_types::w3c::credential_proof::{CredentialProof, CredentialSignatureProof};
use crate::data_types::w3c::presentation_proof::CredentialPresentationProof;
use crate::data_types::{
    cred_def::CredentialDefinitionId,
    credential::CredentialValuesEncoding,
    issuer_id::IssuerId,
    rev_reg_def::RevocationRegistryDefinitionId,
    schema::SchemaId,
    w3c::{
        constants::{
            W3C_ANONCREDS_CONTEXT, W3C_ANONCREDS_CREDENTIAL_TYPE, W3C_CONTEXT, W3C_CREDENTIAL_TYPE,
        },
        one_or_many::OneOrMany,
        uri::URI,
    },
};
use crate::error::ValidationError;
use crate::types::{CredentialValues, MakeCredentialValues};
use crate::utils::validation::Validatable;
use crate::Result;

/// AnonCreds W3C Credential definition
/// Note, that this definition is tied to AnonCreds W3C form
/// Some fields are defined as required despite to general W3C specification
/// For example `credential_schema` is required for AnonCreds W3C Credentials and has custom format
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct W3CCredential {
    #[serde(rename = "@context")]
    pub context: Contexts,
    #[serde(rename = "type")]
    pub type_: Types,
    pub issuer: IssuerId,
    pub issuance_date: Date,
    pub credential_schema: CredentialSchema,
    pub credential_subject: CredentialSubject,
    pub proof: OneOrMany<CredentialProof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<URI>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<CredentialStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<Date>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Contexts(pub HashSet<URI>);

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Types(pub HashSet<String>);

pub type Date = DateTime<Utc>;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<URI>,
    #[serde(flatten)]
    pub attributes: CredentialAttributes,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct CredentialAttributes(pub HashMap<String, Value>);

#[cfg(feature = "zeroize")]
impl Drop for CredentialAttributes {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for CredentialAttributes {
    fn zeroize(&mut self) {
        for attr in self.0.values_mut() {
            if let Value::String(attr) = attr {
                attr.zeroize()
            }
        }
    }
}

impl Validatable for CredentialAttributes {
    fn validate(&self) -> std::result::Result<(), ValidationError> {
        if self.0.is_empty() {
            return Err(
                "CredentialAttributes validation failed: empty list has been passed".into(),
            );
        }
        for (attribute, value) in self.0.iter() {
            match value {
                Value::String(_) | Value::Object(_) => {}
                _ => {
                    return Err(format!(
                        "CredentialAttributes validation failed: {} value format is not supported",
                        attribute
                    )
                    .into())
                }
            }
        }

        Ok(())
    }
}

impl From<&CredentialValues> for CredentialAttributes {
    fn from(values: &CredentialValues) -> Self {
        CredentialAttributes(
            values
                .0
                .iter()
                .map(|(attribute, values)| {
                    (attribute.to_owned(), Value::String(values.raw.to_owned()))
                })
                .collect(),
        )
    }
}

impl CredentialAttributes {
    pub fn add_attribute(&mut self, attribute: String, value: Value) {
        self.0.insert(attribute, value);
    }

    pub fn add_predicate(&mut self, attribute: String, value: PredicateAttribute) {
        self.0.insert(attribute, json!(value));
    }

    pub fn get_attribute(&self, attribute: &str) -> Result<&Value> {
        self.0
            .get(attribute)
            .ok_or_else(|| err_msg!("Credential attribute {} not found", attribute))
    }

    pub fn encode(&self, encoding: &CredentialValuesEncoding) -> Result<CredentialValues> {
        match encoding {
            CredentialValuesEncoding::Auto => {
                let mut cred_values = MakeCredentialValues::default();
                for (attribute, raw_value) in self.0.iter() {
                    match raw_value {
                        Value::String(raw_value) => {
                            cred_values.add_raw(attribute, &raw_value.to_string())?
                        }
                        value => {
                            return Err(err_msg!(
                                "Encoding is not supported for credential value {:?}",
                                value
                            ));
                        }
                    }
                }
                Ok(cred_values.into())
            }
            encoding => Err(err_msg!(
                "Credential values encoding {:?} is not supported",
                encoding
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct PredicateAttribute {
    #[serde(rename = "type")]
    pub type_: PredicateAttributeType,
    pub p_type: PredicateTypes,
    pub p_value: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PredicateAttributeType {
    #[serde(rename = "AnonCredsPredicate")]
    AnonCredsPredicate,
}

impl Default for PredicateAttributeType {
    fn default() -> Self {
        PredicateAttributeType::AnonCredsPredicate
    }
}

impl From<PredicateInfo> for PredicateAttribute {
    fn from(info: PredicateInfo) -> Self {
        PredicateAttribute {
            type_: PredicateAttributeType::AnonCredsPredicate,
            p_type: info.p_type,
            p_value: info.p_value,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialStatus {
    pub id: URI,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchema {
    #[serde(rename = "type")]
    pub type_: CredentialSchemaType,
    pub definition: CredentialDefinitionId,
    pub schema: SchemaId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_registry: Option<RevocationRegistryDefinitionId>,
    #[serde(default)]
    pub encoding: CredentialValuesEncoding,
}

impl CredentialSchema {
    pub fn new(
        schema: SchemaId,
        definition: CredentialDefinitionId,
        revocation_registry: Option<RevocationRegistryDefinitionId>,
        encoding: CredentialValuesEncoding,
    ) -> CredentialSchema {
        CredentialSchema {
            type_: CredentialSchemaType::AnonCredsDefinition,
            definition,
            schema,
            revocation_registry,
            encoding,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialSchemaType {
    #[serde(rename = "AnonCredsDefinition")]
    AnonCredsDefinition,
}

impl Default for CredentialSchemaType {
    fn default() -> Self {
        CredentialSchemaType::AnonCredsDefinition
    }
}

impl W3CCredential {
    pub fn new() -> W3CCredential {
        W3CCredential {
            context: ANONCREDS_CONTEXTS.clone(),
            type_: ANONCREDS_TYPES.clone(),
            issuance_date: Utc::now(),
            proof: OneOrMany::Many(Vec::new()),
            ..Default::default()
        }
    }

    pub fn set_id(&mut self, id: URI) {
        self.id = Some(id)
    }

    pub fn set_issuer(&mut self, issuer: IssuerId) {
        self.issuer = issuer
    }

    pub fn set_credential_schema(&mut self, credential_schema: CredentialSchema) {
        self.credential_schema = credential_schema
    }

    pub fn set_attributes(&mut self, attributes: CredentialAttributes) {
        self.credential_subject.attributes = attributes
    }

    pub fn set_subject_id(&mut self, id: URI) {
        self.credential_subject.id = Some(id)
    }

    pub fn add_context(&mut self, context: URI) {
        self.context.0.insert(context);
    }

    pub fn add_type(&mut self, types: String) {
        self.type_.0.insert(types);
    }

    pub fn add_proof(&mut self, proof: CredentialProof) {
        match self.proof {
            OneOrMany::One(ref existing_proof) => {
                self.proof = OneOrMany::Many(vec![existing_proof.clone(), proof])
            }
            OneOrMany::Many(ref mut proofs) => proofs.push(proof),
        }
    }

    pub fn get_credential_signature_proof(&self) -> Result<&CredentialSignatureProof> {
        match &self.proof {
            OneOrMany::One(ref proof) => proof.get_credential_signature_proof(),
            OneOrMany::Many(ref proofs) => proofs
                .iter()
                .find_map(|proof| proof.get_credential_signature_proof().ok())
                .ok_or_else(|| err_msg!("credential does not contain AnonCredsSignatureProof")),
        }
    }

    pub(crate) fn get_mut_credential_signature_proof(
        &mut self,
    ) -> Result<&mut CredentialSignatureProof> {
        match self.proof {
            OneOrMany::One(ref mut proof) => proof.get_mut_credential_signature_proof(),
            OneOrMany::Many(ref mut proofs) => proofs
                .iter_mut()
                .find_map(|proof| proof.get_mut_credential_signature_proof().ok())
                .ok_or_else(|| err_msg!("credential does not contain AnonCredsSignatureProof")),
        }
    }

    pub fn get_presentation_proof(&self) -> Result<&CredentialPresentationProof> {
        match &self.proof {
            OneOrMany::One(ref proof) => proof.get_presentation_proof(),
            OneOrMany::Many(ref proofs) => proofs
                .iter()
                .find_map(|proof| proof.get_presentation_proof().ok())
                .ok_or_else(|| err_msg!("credential does not contain PresentationProof")),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !self.context.0.contains(&URI(W3C_CONTEXT.to_string())) {
            return Err(err_msg!("Credential does not contain w3c context"));
        }
        if !self
            .context
            .0
            .contains(&URI(W3C_ANONCREDS_CONTEXT.to_string()))
        {
            return Err(err_msg!(
                "Credential does not contain w3c anoncreds context"
            ));
        }
        if !self.type_.0.contains(W3C_CREDENTIAL_TYPE) {
            return Err(err_msg!("Credential does not contain w3c credential type"));
        }
        if !self.type_.0.contains(W3C_ANONCREDS_CREDENTIAL_TYPE) {
            return Err(err_msg!(
                "Credential does not contain w3c anoncreds credential type"
            ));
        }
        Ok(())
    }
}
