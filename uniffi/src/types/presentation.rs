use anoncreds_core::types::Presentation as AnoncredsPresentation;
use anoncreds_core::types::PresentationRequest as AnoncredsPresentationRequest;

use crate::AnoncredsError;

pub struct Presentation {
    pub core: AnoncredsPresentation,
}

impl Presentation {
    pub fn new(json_string: String) -> Result<Self, AnoncredsError> {
        let core_def: AnoncredsPresentation = serde_json::from_str(&json_string)
            .map_err(|err| AnoncredsError::ConversionError(err.to_string()))?;
        return Ok(Presentation { core: core_def });
    }

    pub fn get_json(&self) -> Result<String, AnoncredsError> {
        serde_json::to_string(&self.core).map_err(|err| AnoncredsError::ConversionError(err.to_string()))
    }
}

pub struct PresentationRequest {
    pub core: AnoncredsPresentationRequest,
}

impl PresentationRequest {
    pub fn new(json_string: String) -> Result<Self, AnoncredsError> {
        let core_def: AnoncredsPresentationRequest =
            serde_json::from_str(&json_string).map_err(|err| AnoncredsError::ConversionError(err.to_string()))?;
        return Ok(PresentationRequest { core: core_def });
    }

    pub fn get_json(&self) -> Result<String, AnoncredsError> {
        serde_json::to_string(&self.core).map_err(|err| AnoncredsError::ConversionError(err.to_string()))
    }
}
