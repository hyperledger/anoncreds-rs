use crate::identifiers::cred_def::CredentialDefinitionId;
use crate::identifiers::schema::SchemaId;
use crate::utils::Qualifiable;
use crate::{ConversionError, Validatable, ValidationError};

pub const CL_SIGNATURE_TYPE: &str = "CL";

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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
    pub primary: ursa_cl!(CredentialPrimaryPublicKey),
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub revocation: Option<ursa_cl!(CredentialRevocationPublicKey)>,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(tag = "ver"))]
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

impl Validatable for CredentialDefinition {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            CredentialDefinition::CredentialDefinitionV1(cred_def) => cred_def.validate(),
        }
    }
}

#[derive(Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct CredentialDefinitionV1 {
    pub id: CredentialDefinitionId,
    pub schema_id: SchemaId,
    #[cfg_attr(feature = "serde", serde(rename = "type"))]
    pub signature_type: SignatureType,
    pub tag: String,
    pub value: CredentialDefinitionData,
}

#[cfg(any(feature = "cl", feature = "cl_native"))]
impl CredentialDefinitionV1 {
    pub fn get_public_key(
        &self,
    ) -> Result<crate::ursa::cl::CredentialPublicKey, crate::ConversionError> {
        let key = crate::ursa::cl::CredentialPublicKey::build_from_parts(
            &self.value.primary,
            self.value.revocation.as_ref(),
        )?;
        Ok(key)
    }
}

impl Validatable for CredentialDefinitionV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.id.validate()?;
        self.schema_id.validate()
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct CredentialDefinitionPrivate {
    pub value: ursa_cl!(CredentialPrivateKey),
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize), serde(transparent))]
pub struct CredentialKeyCorrectnessProof {
    pub value: ursa_cl!(CredentialKeyCorrectnessProof),
}

impl CredentialKeyCorrectnessProof {
    pub fn try_clone(&self) -> Result<Self, ConversionError> {
        #[cfg(any(feature = "cl", feature = "cl_native"))]
        {
            Ok(Self {
                value: self.value.try_clone()?,
            })
        }
        #[cfg(not(any(feature = "cl", feature = "cl_native")))]
        {
            Ok(Self {
                value: self.value.clone(),
            })
        }
    }
}
