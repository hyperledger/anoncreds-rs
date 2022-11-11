use crate::data_types::identifiers::cred_def::CredentialDefinitionId;
use crate::data_types::identifiers::schema::SchemaId;
use crate::data_types::utils::Qualifiable;
use crate::data_types::{ConversionError, Validatable, ValidationError};

pub const CL_SIGNATURE_TYPE: &str = "CL";

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureType {
    CL,
}

impl SignatureType {
    pub fn from_str(value: &str) -> Result<Self, ConversionError> {
        match value {
            CL_SIGNATURE_TYPE => Ok(Self::CL),
            _ => Err(ConversionError::from_msg("Invalid signature type")),
        }
    }

    pub fn to_str(&self) -> &'static str {
        match *self {
            SignatureType::CL => CL_SIGNATURE_TYPE,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialDefinitionData {
    pub primary: crate::ursa::cl::CredentialPrimaryPublicKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation: Option<crate::ursa::cl::CredentialRevocationPublicKey>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "ver")]
pub enum CredentialDefinition {
    #[serde(rename = "1.0")]
    CredentialDefinitionV1(CredentialDefinitionV1),
}

impl CredentialDefinition {
    pub fn id(&self) -> &CredentialDefinitionId {
        match self {
            CredentialDefinition::CredentialDefinitionV1(c) => &c.id,
        }
    }

    pub fn to_unqualified(self) -> CredentialDefinition {
        match self {
            CredentialDefinition::CredentialDefinitionV1(cred_def) => {
                CredentialDefinition::CredentialDefinitionV1(CredentialDefinitionV1 {
                    id: cred_def.id.to_unqualified(),
                    schema_id: cred_def.schema_id.to_unqualified(),
                    signature_type: cred_def.signature_type,
                    tag: cred_def.tag,
                    value: cred_def.value,
                })
            }
        }
    }
}

impl Validatable for CredentialDefinition {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            CredentialDefinition::CredentialDefinitionV1(cred_def) => cred_def.validate(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDefinitionV1 {
    pub id: CredentialDefinitionId,
    pub schema_id: SchemaId,
    #[serde(rename = "type")]
    pub signature_type: SignatureType,
    pub tag: String,
    pub value: CredentialDefinitionData,
}

impl CredentialDefinitionV1 {
    pub fn get_public_key(&self) -> Result<crate::ursa::cl::CredentialPublicKey, ConversionError> {
        let key = crate::ursa::cl::CredentialPublicKey::build_from_parts(
            &self.value.primary,
            self.value.revocation.as_ref(),
        )
        .map_err(|e| e.to_string())?;
        Ok(key)
    }
}

impl Validatable for CredentialDefinitionV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.id.validate()?;
        self.schema_id.validate()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialDefinitionPrivate {
    pub value: crate::ursa::cl::CredentialPrivateKey,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct CredentialKeyCorrectnessProof {
    pub value: crate::ursa::cl::CredentialKeyCorrectnessProof,
}

impl CredentialKeyCorrectnessProof {
    pub fn try_clone(&self) -> Result<Self, ConversionError> {
        Ok(Self {
            value: self.value.try_clone().map_err(|e| e.to_string())?,
        })
    }
}
