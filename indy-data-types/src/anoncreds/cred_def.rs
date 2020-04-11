use crate::identifiers::cred_def::CredentialDefinitionId;
use crate::identifiers::schema::SchemaId;
use crate::ursa::cl::{CredentialPrimaryPublicKey, CredentialRevocationPublicKey};
use crate::utils::qualifier::Qualifiable;
use crate::{ConversionError, TryClone, Validatable, ValidationError};

pub const CL_SIGNATURE_TYPE: &str = "CL";

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum SignatureType {
    CL,
}

impl SignatureType {
    pub fn to_str(&self) -> &'static str {
        match *self {
            SignatureType::CL => CL_SIGNATURE_TYPE,
        }
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CredentialDefinitionData {
    pub primary: CredentialPrimaryPublicKey,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub revocation: Option<CredentialRevocationPublicKey>,
}

impl TryClone for CredentialDefinitionData {
    fn try_clone(&self) -> Result<CredentialDefinitionData, ConversionError> {
        let primary = self.primary.try_clone()?;
        let revocation = self.revocation.clone();
        Ok(CredentialDefinitionData {
            primary,
            revocation,
        })
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "ver"))]
pub enum CredentialDefinition {
    #[cfg_attr(feature = "serde", serde(rename = "1.0"))]
    CredentialDefinitionV1(CredentialDefinitionV1),
}

impl CredentialDefinition {
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

impl TryClone for CredentialDefinition {
    fn try_clone(&self) -> Result<CredentialDefinition, ConversionError> {
        match self {
            CredentialDefinition::CredentialDefinitionV1(v1) => Ok(
                CredentialDefinition::CredentialDefinitionV1(v1.try_clone()?),
            ),
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

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct CredentialDefinitionV1 {
    pub id: CredentialDefinitionId,
    pub schema_id: SchemaId,
    #[cfg_attr(feature = "serde", serde(rename = "type"))]
    pub signature_type: SignatureType,
    pub tag: String,
    pub value: CredentialDefinitionData,
}

impl TryClone for CredentialDefinitionV1 {
    fn try_clone(&self) -> Result<CredentialDefinitionV1, ConversionError> {
        Ok(Self {
            id: self.id.clone(),
            schema_id: self.schema_id.clone(),
            signature_type: self.signature_type.clone(),
            tag: self.tag.clone(),
            value: self.value.try_clone()?,
        })
    }
}

impl Validatable for CredentialDefinitionV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.id.validate()?;
        self.schema_id.validate()
    }
}
