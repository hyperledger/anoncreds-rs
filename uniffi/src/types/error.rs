use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
pub enum AnoncredsError {
    #[error("Conversion Error")]
    ConversionError,
    #[error("Something went wrong")]
    SomethingWentWrong,
    #[error("Create Credential Error: {0}")]
    CreateCrentialRequestError(String),
    #[error("Create Schema Error: {0}")]
    CreateSchemaError(String),
    #[error("Create Credential Definition: {0}")]
    CreateCredentialDefinition(String),
    #[error("Create Revocation Registry Def: {0}")]
    CreateRevocationRegistryDef(String),
    #[error("Create Revocation Status List: {0}")]
    CreateRevocationStatusList(String),
    #[error("Update Revocation Status List: {0}")]
    UpdateRevocationStatusList(String),
    #[error("Create Credential Offer: {0}")]
    CreateCredentialOffer(String),
    #[error("Create Credential: {0}")]
    CreateCredential(String),
    #[error("Process Credential: {0}")]
    ProcessCredential(String),

    #[error("Create Presentation: {0}")]
    CreatePresentationError(String),
    #[error("Verify Presentation: {0}")]
    ProcessCredentialError(String),
}
