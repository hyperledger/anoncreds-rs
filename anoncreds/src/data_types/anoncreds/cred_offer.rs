use super::nonce::Nonce;
use crate::data_types::identifiers::cred_def::CredentialDefinitionId;
use crate::data_types::identifiers::schema::SchemaId;
use crate::data_types::utils::Qualifiable;
use crate::data_types::{Validatable, ValidationError};

#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialOffer {
    pub schema_id: SchemaId,
    pub cred_def_id: CredentialDefinitionId,
    pub key_correctness_proof: ursa::cl::CredentialKeyCorrectnessProof,
    pub nonce: Nonce,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method_name: Option<String>,
}

impl CredentialOffer {
    #[allow(unused)]
    pub fn to_unqualified(self) -> CredentialOffer {
        let method_name = self.cred_def_id.get_method().map(str::to_owned);
        CredentialOffer {
            schema_id: self.schema_id.to_unqualified(),
            cred_def_id: self.cred_def_id.to_unqualified(),
            key_correctness_proof: self.key_correctness_proof,
            nonce: self.nonce,
            method_name,
        }
    }
}

impl Validatable for CredentialOffer {
    fn validate(&self) -> Result<(), ValidationError> {
        self.schema_id.validate()?;
        self.cred_def_id.validate()?;
        Ok(())
    }
}
