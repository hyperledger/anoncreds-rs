use std::str::FromStr;

use crate::{error::ConversionError, impl_anoncreds_object_identifier};

use super::{issuer_id::IssuerId, schema::SchemaId};

pub const CL_SIGNATURE_TYPE: &str = "CL";

impl_anoncreds_object_identifier!(CredentialDefinitionId);

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureType {
    CL,
}

impl FromStr for SignatureType {
    type Err = ConversionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            CL_SIGNATURE_TYPE => Ok(Self::CL),
            _ => Err(ConversionError::from_msg("Invalid signature type")),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialDefinitionData {
    pub primary: ursa::cl::CredentialPrimaryPublicKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation: Option<ursa::cl::CredentialRevocationPublicKey>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDefinition {
    pub schema_id: SchemaId,
    #[serde(rename = "type")]
    pub signature_type: SignatureType,
    pub tag: String,
    pub value: CredentialDefinitionData,
    pub issuer_id: IssuerId,
}

impl CredentialDefinition {
    pub fn get_public_key(&self) -> Result<ursa::cl::CredentialPublicKey, ConversionError> {
        let key = ursa::cl::CredentialPublicKey::build_from_parts(
            &self.value.primary,
            self.value.revocation.as_ref(),
        )
        .map_err(|e| e.to_string())?;
        Ok(key)
    }
}

impl Validatable for CredentialDefinition {
    fn validate(&self) -> Result<(), ValidationError> {
        self.schema_id.validate()?;
        self.issuer_id.validate()?;

        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialDefinitionPrivate {
    pub value: ursa::cl::CredentialPrivateKey,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct CredentialKeyCorrectnessProof {
    pub value: ursa::cl::CredentialKeyCorrectnessProof,
}

impl CredentialKeyCorrectnessProof {
    pub fn try_clone(&self) -> Result<Self, ConversionError> {
        Ok(Self {
            value: self.value.try_clone().map_err(|e| e.to_string())?,
        })
    }
}
