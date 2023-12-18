use crate::types::error::AnoncredsError;
use anoncreds_core::data_types::schema::SchemaId;
use anoncreds_core::data_types::issuer_id::IssuerId;
use anoncreds_core::data_types::cred_def::{
    CredentialDefinitionData as AnoncredsCredentialDefinitionData, 
    CredentialDefinition as AnoncredsCredentialDefinition, 
    CredentialDefinitionPrivate as AnoncredsCredentialDefinitionPrivate,
    CredentialKeyCorrectnessProof as AnoncredsCredentialKeyCorrectnessProof,
    SignatureType
};
use std::convert::TryFrom;
use std::convert::TryInto;

#[derive(Clone)]
pub struct CredentialDefinitionData {
    pub primary: String,
    pub revocation: Option<String>,
}

impl TryFrom<AnoncredsCredentialDefinitionData> for CredentialDefinitionData {
    type Error = AnoncredsError;

    fn try_from(acr: AnoncredsCredentialDefinitionData) -> Result<Self, Self::Error> {
        let primary = serde_json::to_string(&acr.primary).map_err(|err| AnoncredsError::ConversionError(err.to_string()))?;

        let revocation = if let Some(rev_key) = &acr.revocation {
            Some(serde_json::to_string(rev_key).map_err(|err| AnoncredsError::ConversionError(err.to_string()))?)
        } else {
            None
        };

        Ok(Self {
            primary,
            revocation,
        })
    }
}

impl TryInto<AnoncredsCredentialDefinitionData> for CredentialDefinitionData {
    type Error = AnoncredsError;

    fn try_into(self) -> Result<AnoncredsCredentialDefinitionData, Self::Error> {
        let primary: ursa::cl::CredentialPrimaryPublicKey = serde_json::from_str(&self.primary)
            .map_err(|err| AnoncredsError::ConversionError(err.to_string()))?;
    
        let revocation = match &self.revocation {
            Some(rev_key_str) => Some(serde_json::from_str(rev_key_str)
                .map_err(|err| AnoncredsError::ConversionError(err.to_string()))?),
            None => None,
        };
    
        Ok(AnoncredsCredentialDefinitionData {
            primary,
            revocation,
        })
    }
}

pub struct CredentialDefinition {
    pub core: AnoncredsCredentialDefinition
}

impl CredentialDefinition {
    pub fn new(json_string: String) -> Result<Self, AnoncredsError> {
        let core_def: AnoncredsCredentialDefinition = serde_json::from_str(&json_string).map_err(|err| AnoncredsError::ConversionError(err.to_string()))?;
        return Ok(CredentialDefinition { core: core_def })
    }

    pub fn get_schema_id(&self) -> SchemaId {
        self.core.schema_id.clone()
    }

    pub fn get_signature_type(&self) -> SignatureType {
        self.core.signature_type.clone()
    }

    pub fn get_tag(&self) -> String {
        self.core.tag.clone()
    }

    pub fn get_issuer_id(&self) -> IssuerId {
        self.core.issuer_id.clone()
    }

    pub fn get_json(&self) -> Result<String, AnoncredsError> {
        serde_json::to_string(&self.core).map_err(|err| AnoncredsError::ConversionError(err.to_string()))
    }
}

impl TryInto<AnoncredsCredentialDefinition> for CredentialDefinition {
    type Error = AnoncredsError;

    fn try_into(self) -> Result<AnoncredsCredentialDefinition, Self::Error> {
        let cloned_schema_id = self.core.schema_id.clone();
        let cloned_signature_type = self.core.signature_type.clone();
        let cloned_get_tag = self.core.tag.clone();
        let cloned_issuer_id = self.core.issuer_id.clone();
        let json_value = serde_json::to_string(&self.core.value).map_err(|err| AnoncredsError::ConversionError(err.to_string()))?;
        let cloned_value = serde_json::from_str(&json_value).map_err(|err| AnoncredsError::ConversionError(err.to_string()))?;

        let cloned_def = AnoncredsCredentialDefinition {
            schema_id: cloned_schema_id,
            signature_type: cloned_signature_type,
            tag: cloned_get_tag,
            value: cloned_value,
            issuer_id: cloned_issuer_id
        };
        return Ok(cloned_def)
    }
}

impl TryFrom<AnoncredsCredentialDefinition> for CredentialDefinition {
    type Error = AnoncredsError;

    fn try_from(acr: AnoncredsCredentialDefinition) -> Result<Self, Self::Error> {
        let cloned_schema_id = acr.schema_id.clone();
        let cloned_signature_type = acr.signature_type.clone();
        let cloned_get_tag = acr.tag.clone();
        let cloned_issuer_id = acr.issuer_id.clone();
        let json_value = serde_json::to_string(&acr.value).map_err(|err| AnoncredsError::ConversionError(err.to_string()))?;
        let cloned_value = serde_json::from_str(&json_value).map_err(|err| AnoncredsError::ConversionError(err.to_string()))?;

        let cloned_def = AnoncredsCredentialDefinition {
            schema_id: cloned_schema_id,
            signature_type: cloned_signature_type,
            tag: cloned_get_tag,
            value: cloned_value,
            issuer_id: cloned_issuer_id
        };
        return Ok(CredentialDefinition { core: cloned_def })
    }
}

impl TryFrom<&CredentialDefinition> for AnoncredsCredentialDefinition {
    type Error = AnoncredsError;

    fn try_from(def: &CredentialDefinition) -> Result<AnoncredsCredentialDefinition, Self::Error> {
        let cloned_schema_id = def.core.schema_id.clone();
        let cloned_signature_type = def.core.signature_type.clone();
        let cloned_get_tag = def.core.tag.clone();
        let cloned_issuer_id = def.core.issuer_id.clone();
        let json_value = serde_json::to_string(&def.core.value).map_err(|err| AnoncredsError::ConversionError(err.to_string()))?;
        let cloned_value = serde_json::from_str(&json_value).map_err(|err| AnoncredsError::ConversionError(err.to_string()))?;

        return Ok(AnoncredsCredentialDefinition {
            schema_id: cloned_schema_id,
            signature_type: cloned_signature_type,
            tag: cloned_get_tag,
            value: cloned_value,
            issuer_id: cloned_issuer_id
        })
    }
}

pub struct CredentialDefinitionPrivate {
    pub core: AnoncredsCredentialDefinitionPrivate,
}

impl CredentialDefinitionPrivate {
    pub fn new(json_string: String) -> Result<Self, AnoncredsError> {
        let core_def: AnoncredsCredentialDefinitionPrivate = serde_json::from_str(&json_string).map_err(|err| AnoncredsError::ConversionError(err.to_string()))?;
        return Ok(CredentialDefinitionPrivate { core: core_def })
    }

    pub fn get_json(&self) -> Result<String, AnoncredsError> {
        serde_json::to_string(&self.core).map_err(|err| AnoncredsError::ConversionError(err.to_string()))
    }
}

impl From<AnoncredsCredentialDefinitionPrivate> for CredentialDefinitionPrivate {
    fn from(acr: AnoncredsCredentialDefinitionPrivate) -> Self {
        return CredentialDefinitionPrivate { core: acr }
    }
}

impl TryFrom<&CredentialDefinitionPrivate> for AnoncredsCredentialDefinitionPrivate {
    type Error = AnoncredsError;
    
    fn try_from(def: &CredentialDefinitionPrivate) -> Result<AnoncredsCredentialDefinitionPrivate, Self::Error> {
        let json_value = serde_json::to_string(&def.core.value).map_err(|err| AnoncredsError::ConversionError(err.to_string()))?;
        return serde_json::from_str(&json_value).map_err(|err| AnoncredsError::ConversionError(err.to_string()))
    }
}

pub struct CredentialKeyCorrectnessProof {
    pub core: AnoncredsCredentialKeyCorrectnessProof,
}

impl CredentialKeyCorrectnessProof {
    pub fn new(json_string: String) -> Result<Self, AnoncredsError> {
        let core_def: AnoncredsCredentialKeyCorrectnessProof = serde_json::from_str(&json_string).map_err(|err| AnoncredsError::ConversionError(err.to_string()))?;
        return Ok(CredentialKeyCorrectnessProof { core: core_def })
    }

    pub fn get_json(&self) -> Result<String, AnoncredsError> {
        serde_json::to_string(&self.core).map_err(|err| AnoncredsError::ConversionError(err.to_string()))
    }
}

impl From<AnoncredsCredentialKeyCorrectnessProof> for CredentialKeyCorrectnessProof {
    fn from(acr: AnoncredsCredentialKeyCorrectnessProof) -> Self {
        return CredentialKeyCorrectnessProof { core: acr }
    }
}

impl TryFrom<&CredentialKeyCorrectnessProof> for AnoncredsCredentialKeyCorrectnessProof {
    type Error = AnoncredsError;

    fn try_from(def: &CredentialKeyCorrectnessProof) -> Result<AnoncredsCredentialKeyCorrectnessProof, Self::Error> {
        return def.core.try_clone().map_err(|err| AnoncredsError::ConversionError(err.to_string()))
    }
}