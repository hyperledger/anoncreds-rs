use std::collections::HashMap;
use serde_json::Value;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::cl::{CredentialSignature, RevocationRegistry, SignatureCorrectnessProof, Witness};
use crate::data_types::w3c::credential::{AttributeEncoding, CredentialSchema, CredentialSchemaType, CredentialSignatureHelper, CredentialSubject, Proofs};
use crate::data_types::w3c::OneOrMany;
use crate::Error;
use crate::error::{ConversionError, ValidationError};
use crate::types::MakeCredentialValues;
use crate::utils::validation::Validatable;

use super::rev_reg_def::RevocationRegistryDefinitionId;
use super::{cred_def::CredentialDefinitionId, schema::SchemaId};
use super::w3c::credential::{
    W3CCredential,
    CredentialSignature as W3CCredentialSignature,
};

#[derive(Debug, Deserialize, Serialize)]
pub struct Credential {
    pub schema_id: SchemaId,
    pub cred_def_id: CredentialDefinitionId,
    pub rev_reg_id: Option<RevocationRegistryDefinitionId>,
    pub values: CredentialValues,
    pub signature: CredentialSignature,
    pub signature_correctness_proof: SignatureCorrectnessProof,
    pub rev_reg: Option<RevocationRegistry>,
    pub witness: Option<Witness>,
}

impl Credential {
    pub const QUALIFIABLE_TAGS: [&'static str; 5] = [
        "issuer_did",
        "cred_def_id",
        "schema_id",
        "schema_issuer_did",
        "rev_reg_id",
    ];

    pub fn try_clone(&self) -> Result<Self, ConversionError> {
        Ok(Self {
            schema_id: self.schema_id.clone(),
            cred_def_id: self.cred_def_id.clone(),
            rev_reg_id: self.rev_reg_id.clone(),
            values: self.values.clone(),
            signature: self.signature.try_clone().map_err(|e| e.to_string())?,
            signature_correctness_proof: self
                .signature_correctness_proof
                .try_clone()
                .map_err(|e| e.to_string())?,
            rev_reg: self.rev_reg.clone(),
            witness: self.witness.clone(),
        })
    }

    // FIXME: Do we expect credentials with fully-qualified ids???
    // FIXME: ConversionError or new kind???
    pub fn to_w3c(&self, method: Option<&str>) -> Result<W3CCredential, ConversionError> {
        let issuer = self.cred_def_id.issuer_did(method)?;
        let cred_def_id = self.cred_def_id.id(method)?;
        let schema_id = self.schema_id.id(method)?;
        let signature = W3CCredentialSignature::from(self);
        let attributes = self.values.0
            .iter()
            .map(|(attribute, values)| (attribute.to_string(), Value::String(values.raw.to_string())))
            .collect();
        let credential_subject = CredentialSubject { property_set: attributes };

        Ok(
            W3CCredential {
                issuer,
                issuance_date: chrono::offset::Utc::now(), // FIXME: use random time of the day
                credential_schema: CredentialSchema {
                    type_: CredentialSchemaType::AnonCredsDefinition,
                    definition: cred_def_id,
                    schema: schema_id,
                    revocation: None,
                    encoding: AttributeEncoding::Auto,
                },
                credential_subject,
                proof: OneOrMany::Many(
                    vec![
                        Proofs::CLSignature2023(signature)
                    ]
                ),
                ..W3CCredential::default()
            }
        )
    }

    pub fn from_w3c(w3c_credential: &W3CCredential) -> Result<Credential, Error> {
        let schema_id = w3c_credential.credential_schema.schema.clone();
        let cred_def_id = w3c_credential.credential_schema.definition.clone();
        let rev_reg_id = w3c_credential.credential_schema.revocation.clone();
        let signature = w3c_credential.anoncreds_credential_signature_proof()
            .ok_or(ValidationError::from_msg("anoncreds credential proof no set"))?;

        let signature = CredentialSignatureHelper::try_from(signature)?;

        let mut cred_values = MakeCredentialValues::default();
        for (attribute, value) in w3c_credential.credential_subject.property_set.iter() {
            cred_values.add_raw(attribute, &value.to_string())?;
        }

        Ok(
            Credential {
                schema_id,
                cred_def_id,
                rev_reg_id,
                values: cred_values.into(),
                signature: signature.signature,
                signature_correctness_proof: signature.signature_correctness_proof,
                rev_reg: None,
                witness: None,
            }
        )
    }
}

impl Validatable for Credential {
    fn validate(&self) -> Result<(), ValidationError> {
        self.values.validate()?;
        self.schema_id.validate()?;
        self.cred_def_id.validate()?;
        self.rev_reg_id
            .as_ref()
            .map(Validatable::validate)
            .transpose()?;

        if self.rev_reg_id.is_some() && (self.witness.is_none() || self.rev_reg.is_none()) {
            return Err("Credential validation failed: `witness` and `rev_reg` must be passed for revocable Credential".into());
        }

        if self.values.0.is_empty() {
            return Err("Credential validation failed: `values` is empty".into());
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CredentialInfo {
    pub referent: String,
    pub attrs: ShortCredentialValues,
    pub schema_id: SchemaId,
    pub cred_def_id: CredentialDefinitionId,
    pub rev_reg_id: Option<RevocationRegistryDefinitionId>,
    pub cred_rev_id: Option<String>,
}

pub type ShortCredentialValues = HashMap<String, String>;

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct CredentialValues(pub HashMap<String, AttributeValues>);

#[cfg(feature = "zeroize")]
impl Drop for CredentialValues {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Validatable for CredentialValues {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.0.is_empty() {
            return Err("CredentialValues validation failed: empty list has been passed".into());
        }

        Ok(())
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for CredentialValues {
    fn zeroize(&mut self) {
        for attr in self.0.values_mut() {
            attr.zeroize();
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "zeroize", derive(Zeroize))]
pub struct AttributeValues {
    pub raw: String,
    pub encoded: String,
}
