use chrono::{DateTime, Utc};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::string::ToString;
use zeroize::Zeroize;

use crate::data_types::w3c::constants::{ANONCREDS_CONTEXTS, ANONCREDS_CREDENTIAL_TYPES};
use crate::data_types::w3c::credential_proof::{
    CredentialProof, CredentialSignatureProof, NonAnonCredsDataIntegrityProof,
};
use crate::data_types::w3c::presentation_proof::{CredentialPresentationProof, PredicateAttribute};
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
    #[serde(alias = "@type")]
    #[serde(rename = "type")]
    pub type_: Types,
    pub issuer: IssuerId,
    pub issuance_date: Date,
    pub credential_schema: CredentialSchema,
    pub credential_subject: CredentialSubject,
    pub proof: OneOrMany<CredentialProof>,
    #[serde(alias = "@id")]
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
pub struct CredentialAttributes(pub HashMap<String, CredentialAttributeValue>);

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CredentialAttributeValue {
    Attribute(String),
    Predicate(Vec<PredicateAttribute>),
}

impl Default for CredentialAttributeValue {
    fn default() -> Self {
        CredentialAttributeValue::Attribute(String::new())
    }
}

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
            if let CredentialAttributeValue::Attribute(attr) = attr {
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
                    (
                        attribute.to_owned(),
                        CredentialAttributeValue::Attribute(values.raw.to_owned()),
                    )
                })
                .collect(),
        )
    }
}

impl CredentialAttributes {
    pub(crate) fn add_attribute(&mut self, attribute: String, value: CredentialAttributeValue) {
        self.0.insert(attribute, value);
    }

    pub(crate) fn add_predicate(
        &mut self,
        attribute: String,
        predicate: PredicateAttribute,
    ) -> Result<()> {
        match self.0.get_mut(&attribute) {
            Some(value) => match value {
                CredentialAttributeValue::Attribute(_) => {
                    return Err(err_msg!("Predicate cannot be added for revealed attribute"));
                }
                CredentialAttributeValue::Predicate(predicates) => predicates.push(predicate),
            },
            None => {
                self.0.insert(
                    attribute,
                    CredentialAttributeValue::Predicate(vec![predicate]),
                );
            }
        }
        Ok(())
    }

    pub(crate) fn encode(&self, encoding: &CredentialValuesEncoding) -> Result<CredentialValues> {
        match encoding {
            CredentialValuesEncoding::Auto => {
                let mut cred_values = MakeCredentialValues::default();
                for (attribute, raw_value) in self.0.iter() {
                    match raw_value {
                        CredentialAttributeValue::Attribute(raw_value) => {
                            cred_values.add_raw(attribute, raw_value)?
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialStatus {
    #[serde(rename = "type")]
    pub type_: CredentialStatusType,
    pub id: RevocationRegistryDefinitionId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialStatusType {
    AnonCredsCredentialStatusList2023,
    Other(String),
}

impl ToString for CredentialStatusType {
    fn to_string(&self) -> String {
        match self {
            CredentialStatusType::AnonCredsCredentialStatusList2023 => {
                "AnonCredsCredentialStatusList2023".to_string()
            }
            CredentialStatusType::Other(other) => other.to_string(),
        }
    }
}

impl From<&str> for CredentialStatusType {
    fn from(value: &str) -> Self {
        match value {
            "AnonCredsCredentialStatusList2023" => {
                CredentialStatusType::AnonCredsCredentialStatusList2023
            }
            other => CredentialStatusType::Other(other.to_string()),
        }
    }
}

impl Serialize for CredentialStatusType {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Value::String(self.to_string()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CredentialStatusType {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Value::deserialize(deserializer)
            .map_err(de::Error::custom)?
            .as_str()
            .map(CredentialStatusType::from)
            .ok_or_else(|| de::Error::custom("Cannot parse credential status type"))
    }
}

impl Default for CredentialStatusType {
    fn default() -> Self {
        CredentialStatusType::AnonCredsCredentialStatusList2023
    }
}

impl CredentialStatus {
    pub fn new(id: RevocationRegistryDefinitionId) -> CredentialStatus {
        CredentialStatus {
            type_: CredentialStatusType::AnonCredsCredentialStatusList2023,
            id,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchema {
    #[serde(rename = "type")]
    pub type_: CredentialSchemaType,
    pub definition: CredentialDefinitionId,
    pub schema: SchemaId,
    #[serde(default)]
    pub encoding: CredentialValuesEncoding,
}

impl CredentialSchema {
    pub fn new(
        schema: SchemaId,
        definition: CredentialDefinitionId,
        encoding: CredentialValuesEncoding,
    ) -> CredentialSchema {
        CredentialSchema {
            type_: CredentialSchemaType::AnonCredsDefinition,
            definition,
            schema,
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
            type_: ANONCREDS_CREDENTIAL_TYPES.clone(),
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

    pub fn set_credential_status(&mut self, credential_status: CredentialStatus) {
        self.credential_status = Some(credential_status)
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

    pub fn add_anoncreds_signature_proof(&mut self, proof: CredentialSignatureProof) {
        self.add_proof(CredentialProof::AnonCredsSignatureProof(proof));
    }

    pub fn add_non_anoncreds_integrity_proof(&mut self, proof: NonAnonCredsDataIntegrityProof) {
        self.add_proof(CredentialProof::NonAnonCredsDataIntegrityProof(proof));
    }

    pub fn set_anoncreds_presentation_proof(&mut self, proof: CredentialPresentationProof) {
        self.proof = OneOrMany::One(CredentialProof::AnonCredsCredentialPresentationProof(proof));
    }

    pub fn get_credential_signature_proof(&self) -> Result<&CredentialSignatureProof> {
        self.proof
            .get_value(&|proof: &CredentialProof| proof.get_credential_signature_proof())
    }

    pub(crate) fn get_mut_credential_signature_proof(
        &mut self,
    ) -> Result<&mut CredentialSignatureProof> {
        self.proof.get_mut_value(&|proof: &mut CredentialProof| {
            proof.get_mut_credential_signature_proof()
        })
    }

    pub fn get_presentation_proof(&self) -> Result<&CredentialPresentationProof> {
        self.proof
            .get_value(&|proof: &CredentialProof| proof.get_presentation_proof())
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

    pub fn get_schema_id(&self) -> &SchemaId {
        &self.credential_schema.schema
    }

    pub fn get_cred_def_id(&self) -> &CredentialDefinitionId {
        &self.credential_schema.definition
    }

    pub fn get_rev_reg_id(&self) -> Option<&RevocationRegistryDefinitionId> {
        if let Some(credential_status) = self.credential_status.as_ref() {
            match credential_status.type_ {
                CredentialStatusType::AnonCredsCredentialStatusList2023 => {
                    Some(&credential_status.id)
                }
                CredentialStatusType::Other(_) => None,
            }
        } else {
            None
        }
    }
}
