use std::str::FromStr;

use crate::{
    data_types::{invalid, ConversionError, Validatable, ValidationError},
    impl_anoncreds_object_identifier,
};

use super::cred_def::CredentialDefinitionId;

pub const CL_ACCUM: &str = "CL_ACCUM";

pub const ISSUANCE_BY_DEFAULT: &str = "ISSUANCE_BY_DEFAULT";
pub const ISSUANCE_ON_DEMAND: &str = "ISSUANCE_ON_DEMAND";

impl_anoncreds_object_identifier!(RevocationRegistryDefinitionId);

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub enum IssuanceType {
    #[default]
    ISSUANCE_BY_DEFAULT,
    ISSUANCE_ON_DEMAND,
}

impl FromStr for IssuanceType {
    type Err = ConversionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            ISSUANCE_BY_DEFAULT => Ok(Self::ISSUANCE_BY_DEFAULT),
            ISSUANCE_ON_DEMAND => Ok(Self::ISSUANCE_ON_DEMAND),
            _ => Err(ConversionError::from_msg("Invalid issuance type")),
        }
    }
}

impl IssuanceType {
    pub fn to_bool(&self) -> bool {
        *self == IssuanceType::ISSUANCE_BY_DEFAULT
    }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum RegistryType {
    CL_ACCUM,
}

impl FromStr for RegistryType {
    type Err = ConversionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            CL_ACCUM => Ok(Self::CL_ACCUM),
            _ => Err(ConversionError::from_msg("Invalid registry type")),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationRegistryDefinitionValue {
    pub issuance_type: IssuanceType,
    pub max_cred_num: u32,
    pub public_keys: RevocationRegistryDefinitionValuePublicKeys,
    pub tails_hash: String,
    pub tails_location: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationRegistryDefinitionValuePublicKeys {
    pub accum_key: ursa::cl::RevocationKeyPublic,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "ver")]
pub enum RevocationRegistryDefinition {
    #[serde(rename = "1.0")]
    RevocationRegistryDefinitionV1(RevocationRegistryDefinitionV1),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationRegistryDefinitionV1 {
    pub revoc_def_type: RegistryType,
    pub tag: String,
    pub cred_def_id: CredentialDefinitionId,
    pub value: RevocationRegistryDefinitionValue,
}

impl Validatable for RevocationRegistryDefinitionV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.cred_def_id.validate()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RevocationRegistryDefinitionPrivate {
    pub value: ursa::cl::RevocationKeyPrivate,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct RevocationRegistryConfig {
    pub issuance_type: Option<IssuanceType>,
    pub max_cred_num: Option<u32>,
}

impl Validatable for RevocationRegistryConfig {
    fn validate(&self) -> Result<(), ValidationError> {
        if let Some(num_) = self.max_cred_num {
            if num_ == 0 {
                return Err(invalid!("RevocationRegistryConfig validation failed: `max_cred_num` must be greater than 0"));
            }
        }
        Ok(())
    }
}
