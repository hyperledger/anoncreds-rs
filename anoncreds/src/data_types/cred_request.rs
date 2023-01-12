use crate::error::ValidationError;
use crate::utils::validation::Validatable;

use super::{cred_def::CredentialDefinitionId, nonce::Nonce};

#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prover_did: Option<String>,
    pub cred_def_id: CredentialDefinitionId,
    pub blinded_ms: ursa::cl::BlindedCredentialSecrets,
    pub blinded_ms_correctness_proof: ursa::cl::BlindedCredentialSecretsCorrectnessProof,
    pub nonce: Nonce,
}

impl Validatable for CredentialRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        self.cred_def_id.validate()?;
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialRequestMetadata {
    pub master_secret_blinding_data: ursa::cl::CredentialSecretsBlindingFactors,
    pub nonce: Nonce,
    pub master_secret_name: String,
}

impl Validatable for CredentialRequestMetadata {}
