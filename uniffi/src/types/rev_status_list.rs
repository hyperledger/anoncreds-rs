use crate::types::error::AnoncredsError;
use anoncreds_core::types::RevocationStatusList as AnoncredsRevocationStatusList;

pub struct RevocationStatusList {
    pub core: AnoncredsRevocationStatusList
}

impl RevocationStatusList {
    pub fn new(json_string: String) -> Result<Self, AnoncredsError> {
        let core_def: AnoncredsRevocationStatusList = serde_json::from_str(&json_string).map_err(|_| AnoncredsError::ConversionError)?;
        return Ok(RevocationStatusList { core: core_def })
    }

    pub fn get_json(&self) -> Result<String, AnoncredsError> {
        serde_json::to_string(&self.core).map_err(|_| AnoncredsError::ConversionError)
    }
}