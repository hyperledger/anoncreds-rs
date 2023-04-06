use std::collections::HashMap;

use zeroize::Zeroize;

use crate::error::{ConversionError, ValidationError};
use crate::utils::validation::Validatable;

use super::{cred_def::CredentialDefinitionId, rev_reg::RevocationRegistryId, schema::SchemaId};

#[derive(Debug, Deserialize, Serialize)]
pub struct Credential {
    pub schema_id: SchemaId,
    pub cred_def_id: CredentialDefinitionId,
    pub rev_reg_id: Option<RevocationRegistryId>,
    pub values: CredentialValues,
    pub signature: ursa::cl::CredentialSignature,
    pub signature_correctness_proof: ursa::cl::SignatureCorrectnessProof,
    pub rev_reg: Option<ursa::cl::RevocationRegistry>,
    pub witness: Option<ursa::cl::Witness>,
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
    pub rev_reg_id: Option<RevocationRegistryId>,
    pub cred_rev_id: Option<String>,
}

pub type ShortCredentialValues = HashMap<String, String>;

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct CredentialValues(pub HashMap<String, AttributeValues>);

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

impl Zeroize for CredentialValues {
    fn zeroize(&mut self) {
        for attr in self.0.values_mut() {
            attr.zeroize();
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Zeroize, Deserialize, Serialize)]
pub struct AttributeValues {
    pub raw: String,
    pub encoded: String,
}
