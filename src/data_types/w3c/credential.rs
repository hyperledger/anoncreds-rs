use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::string::ToString;

use crate::Result;
use crate::data_types::{
    cred_def::CredentialDefinitionId,
    credential::{CredentialValuesEncoding, RawCredentialValues},
    issuer_id::IssuerId,
    rev_reg_def::RevocationRegistryDefinitionId,
    schema::SchemaId,
    w3c::{
        constants::{W3C_ANONCREDS_CONTEXT, W3C_ANONCREDS_CREDENTIAL_TYPE, W3C_CONTEXT, W3C_CREDENTIAL_TYPE},
        one_or_many::OneOrMany,
        uri::URI,
    },
};
use crate::data_types::presentation::Identifier;
use crate::data_types::w3c::credential_proof::{CredentialProof, CredentialSignatureProof, NonAnonCredsDataIntegrityProof};
use crate::data_types::w3c::presentation_proof::CredentialPresentationProof;

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

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
pub struct Contexts(pub HashSet<URI>);

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
pub struct Types(pub HashSet<String>);

pub type Date = DateTime<Utc>;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<URI>,
    #[serde(flatten)]
    pub attributes: RawCredentialValues,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CredentialStatus {
    pub id: URI,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CredentialSchema {
    #[serde(rename = "type")]
    pub type_: CredentialSchemaType,
    pub definition: CredentialDefinitionId,
    pub schema: SchemaId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation: Option<RevocationRegistryDefinitionId>,
    #[serde(default)]
    pub encoding: CredentialValuesEncoding,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    pub fn add_non_anoncreds_identity_proof(&mut self, proof: NonAnonCredsDataIntegrityProof) {
        match self.proof {
            OneOrMany::One(ref existing_proof) => {
                self.proof = OneOrMany::Many(
                    vec![
                        existing_proof.clone(),
                        CredentialProof::NonAnonCredsDataIntegrityProof(proof),
                    ]
                )
            }
            OneOrMany::Many(ref mut proofs) => {
                proofs.push(CredentialProof::NonAnonCredsDataIntegrityProof(proof))
            }
        }
    }

    pub fn set_id(&mut self, id: URI) {
        self.id = Some(id)
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

    pub fn get_credential_signature_proof(&self) -> Result<&CredentialSignatureProof> {
        match &self.proof {
            OneOrMany::One(ref proof) => {
                proof.get_credential_signature_proof()
            }
            OneOrMany::Many(ref proofs) => {
                proofs
                    .iter()
                    .find_map(|proof| proof.get_credential_signature_proof().ok())
                    .ok_or(err_msg!("credential does not contain AnonCredsSignatureProof"))
            }
        }
    }

    pub fn get_mut_credential_signature_proof(&mut self) -> Result<&mut CredentialSignatureProof> {
        match self.proof {
            OneOrMany::One(ref mut proof) => {
                proof.get_mut_credential_signature_proof()
            }
            OneOrMany::Many(ref mut proofs) => {
                proofs
                    .iter_mut()
                    .find_map(|proof| proof.get_mut_credential_signature_proof().ok())
                    .ok_or(err_msg!("credential does not contain AnonCredsSignatureProof"))
            }
        }
    }

    pub fn get_presentation_proof(&self) -> Result<&CredentialPresentationProof> {
        match &self.proof {
            OneOrMany::One(ref proof) => {
                proof.get_presentation_proof()
            }
            OneOrMany::Many(ref proofs) => {
                proofs
                    .iter()
                    .find_map(|proof| proof.get_presentation_proof().ok())
                    .ok_or(err_msg!("credential does not contain PresentationProof"))
            }
        }
    }

    pub fn get_mut_presentation_proof(&mut self) -> Result<&mut CredentialPresentationProof> {
        match self.proof {
            OneOrMany::One(ref mut proof) => {
                proof.get_mut_presentation_proof()
            }
            OneOrMany::Many(ref mut proofs) => {
                proofs
                    .iter_mut()
                    .find_map(|proof| proof.get_mut_presentation_proof().ok())
                    .ok_or(err_msg!("credential does not contain PresentationProof"))
            }
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !self.context.0.contains(&URI(W3C_CONTEXT.to_string())) {
            return Err(err_msg!("Credential does not contain w3c context"));
        }
        if !self.context.0.contains(&URI(W3C_ANONCREDS_CONTEXT.to_string())) {
            return Err(err_msg!("Credential does not contain w3c anoncreds context"));
        }
        if !self.type_.0.contains(W3C_CREDENTIAL_TYPE) {
            return Err(err_msg!("Credential does not contain w3c credential type"));
        }
        if !self.type_.0.contains(W3C_ANONCREDS_CREDENTIAL_TYPE) {
            return Err(err_msg!("Credential does not contain w3c anoncreds credential type"));
        }
        Ok(())
    }
}

impl Into<Identifier> for CredentialSchema {
    fn into(self) -> Identifier {
        Identifier {
            schema_id: self.schema.clone(),
            cred_def_id: self.definition.clone(),
            rev_reg_id: self.revocation.clone(),
            timestamp: None,
        }
    }
}