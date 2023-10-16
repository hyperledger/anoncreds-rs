use crate::types::error::AnoncredsError;
use anoncreds_core::data_types::issuer_id::IssuerId;
use anoncreds_core::data_types::cred_def::CredentialDefinitionId;
use anoncreds_core::data_types::rev_reg_def::{
    RevocationRegistryDefinition as AnoncredsRevocationRegistryDefinition, 
    RevocationRegistryDefinitionPrivate as AnoncredsRevocationRegistryDefinitionPrivate,
    RevocationRegistryDefinitionValue as AnoncredsRevocationRegistryDefinitionValue,
    RevocationRegistryDefinitionValuePublicKeys as AnoncredsRevocationRegistryDefinitionValuePublicKeys,
    RegistryType
};
use std::convert::TryFrom;
use std::sync::Arc;

/// Wrapper for [RevocationRegistryDefinition]
pub struct RevocationRegistryDefinition {
    pub core: AnoncredsRevocationRegistryDefinition
}

impl RevocationRegistryDefinition {
    pub fn new(json_string: String) -> Result<Self, AnoncredsError> {
        let core_def: AnoncredsRevocationRegistryDefinition = serde_json::from_str(&json_string).map_err(|_| AnoncredsError::ConversionError)?;
        return Ok(RevocationRegistryDefinition { core: core_def })
    }

    pub fn get_issuer_id(&self) -> IssuerId {
        self.core.issuer_id.clone()
    }

    pub fn get_revoc_def_type(&self) -> RegistryType {
        self.core.revoc_def_type.clone()
    }

    pub fn get_tag(&self) -> String {
        self.core.tag.clone()
    }

    pub fn get_cred_def_id(&self) -> CredentialDefinitionId {
        self.core.cred_def_id.clone()
    }

    pub fn get_value(&self) -> Arc<RevocationRegistryDefinitionValue> {
        Arc::new(RevocationRegistryDefinitionValue::from(self.core.value.clone()))
    }

    pub fn get_json(&self) -> Result<String, AnoncredsError> {
        serde_json::to_string(&self.core).map_err(|_| AnoncredsError::ConversionError)
    }
}

impl From<AnoncredsRevocationRegistryDefinition> for RevocationRegistryDefinition {
    fn from(acr: AnoncredsRevocationRegistryDefinition) -> Self {
        return RevocationRegistryDefinition { core: acr }
    }
}

impl TryFrom<&RevocationRegistryDefinition> for AnoncredsRevocationRegistryDefinition {
    type Error = AnoncredsError;

    fn try_from(def: &RevocationRegistryDefinition) -> Result<AnoncredsRevocationRegistryDefinition, Self::Error> {
        let json_value = serde_json::to_string(&def.core.value).map_err(|_| AnoncredsError::ConversionError)?;
        return serde_json::from_str(&json_value).map_err(|_| AnoncredsError::ConversionError)
    }
}

pub struct RevocationRegistryDefinitionPrivate {
    pub core: AnoncredsRevocationRegistryDefinitionPrivate
}

impl RevocationRegistryDefinitionPrivate {
    pub fn new(json_string: String) -> Result<Self, AnoncredsError> {
        let core_def: AnoncredsRevocationRegistryDefinitionPrivate = serde_json::from_str(&json_string).map_err(|_| AnoncredsError::ConversionError)?;
        return Ok(RevocationRegistryDefinitionPrivate { core: core_def })
    }
    
    pub fn get_json(&self) -> Result<String, AnoncredsError> {
        serde_json::to_string(&self.core).map_err(|_| AnoncredsError::ConversionError)
    }
}

impl From<AnoncredsRevocationRegistryDefinitionPrivate> for RevocationRegistryDefinitionPrivate {
    fn from(acr: AnoncredsRevocationRegistryDefinitionPrivate) -> Self {
        return RevocationRegistryDefinitionPrivate { core: acr }
    }
}

impl TryFrom<&RevocationRegistryDefinitionPrivate> for AnoncredsRevocationRegistryDefinitionPrivate {
    type Error = AnoncredsError;

    fn try_from(def: &RevocationRegistryDefinitionPrivate) -> Result<AnoncredsRevocationRegistryDefinitionPrivate, Self::Error> {
        let json_value = serde_json::to_string(&def.core.value).map_err(|_| AnoncredsError::ConversionError)?;
        return serde_json::from_str(&json_value).map_err(|_| AnoncredsError::ConversionError)
    }
}

pub struct RevocationRegistryDefinitionValue {
    pub(crate) core: AnoncredsRevocationRegistryDefinitionValue
}

impl RevocationRegistryDefinitionValue {
    pub fn new(json_string: String) -> Result<Self, AnoncredsError> {
        let core_def: AnoncredsRevocationRegistryDefinitionValue = serde_json::from_str(&json_string).map_err(|_| AnoncredsError::ConversionError)?;
        return Ok(RevocationRegistryDefinitionValue { core: core_def })
    }

    pub fn get_max_cred_num(&self) -> u32 {
        self.core.max_cred_num.clone()
    }

    pub fn get_tails_hash(&self) -> String {
        self.core.tails_hash.clone()
    }

    pub fn get_tails_location(&self) -> String {
        self.core.tails_location.clone()
    }

    pub fn get_json(&self) -> Result<String, AnoncredsError> {
        serde_json::to_string(&self.core).map_err(|_| AnoncredsError::ConversionError)
    }
}

impl From<AnoncredsRevocationRegistryDefinitionValue> for RevocationRegistryDefinitionValue {
    fn from(acr: AnoncredsRevocationRegistryDefinitionValue) -> Self {
        return RevocationRegistryDefinitionValue { core: acr }
    }
}

impl TryFrom<&RevocationRegistryDefinitionValue> for AnoncredsRevocationRegistryDefinitionValue {
    type Error = AnoncredsError;

    fn try_from(def: &RevocationRegistryDefinitionValue) -> Result<AnoncredsRevocationRegistryDefinitionValue, Self::Error> {
        let json_value = serde_json::to_string(&def.core).map_err(|_| AnoncredsError::ConversionError)?;
        return serde_json::from_str(&json_value).map_err(|_| AnoncredsError::ConversionError)
    }
}

pub struct RevocationRegistryDefinitionValuePublicKeys {
    pub(crate) core: AnoncredsRevocationRegistryDefinitionValuePublicKeys
}

impl RevocationRegistryDefinitionValuePublicKeys {
    pub fn new(json_string: String) -> Result<Self, AnoncredsError> {
        let core_def: AnoncredsRevocationRegistryDefinitionValuePublicKeys = serde_json::from_str(&json_string).map_err(|_| AnoncredsError::ConversionError)?;
        return Ok(RevocationRegistryDefinitionValuePublicKeys { core: core_def })
    }

    pub fn get_json(&self) -> Result<String, AnoncredsError> {
        serde_json::to_string(&self.core).map_err(|_| AnoncredsError::ConversionError)
    }
}

impl From<AnoncredsRevocationRegistryDefinitionValuePublicKeys> for RevocationRegistryDefinitionValuePublicKeys {
    fn from(acr: AnoncredsRevocationRegistryDefinitionValuePublicKeys) -> Self {
        return RevocationRegistryDefinitionValuePublicKeys { core: acr }
    }
}

impl TryFrom<&RevocationRegistryDefinitionValuePublicKeys> for AnoncredsRevocationRegistryDefinitionValuePublicKeys {
    type Error = AnoncredsError;

    fn try_from(def: &RevocationRegistryDefinitionValuePublicKeys) -> Result<AnoncredsRevocationRegistryDefinitionValuePublicKeys, Self::Error> {
        let json_value = serde_json::to_string(&def.core).map_err(|_| AnoncredsError::ConversionError)?;
        return serde_json::from_str(&json_value).map_err(|_| AnoncredsError::ConversionError)
    }
}