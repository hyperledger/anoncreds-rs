use crate::Error;

pub mod constants;
pub mod context;
/// AnonCreds W3C Credentials definition
pub mod credential;
pub mod credential_attributes;
pub mod one_or_many;
/// AnonCreds W3C Presentation definition
pub mod presentation;
pub mod proof;
pub mod uri;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum VerifiableCredentialSpecVersion {
    V1_1,
    V2_0,
}

impl Default for VerifiableCredentialSpecVersion {
    fn default() -> Self {
        VerifiableCredentialSpecVersion::V1_1
    }
}

impl TryFrom<&str> for VerifiableCredentialSpecVersion {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "1.1" => Ok(VerifiableCredentialSpecVersion::V1_1),
            "2.0" => Ok(VerifiableCredentialSpecVersion::V2_0),
            value => Err(err_msg!(
                "Unsupported w3c version of verifiable credential specification {}",
                value
            )),
        }
    }
}
