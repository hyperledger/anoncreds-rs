use super::nonce::Nonce;
use crate::data_types::{Validatable, ValidationError};
use indy_utils::did::DidValue;

#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialRequest {
    pub prover_did: DidValue,
    pub cred_def_id: String,
    pub blinded_ms: ursa::cl::BlindedCredentialSecrets,
    pub blinded_ms_correctness_proof: ursa::cl::BlindedCredentialSecretsCorrectnessProof,
    pub nonce: Nonce,
}

impl Validatable for CredentialRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        self.prover_did.validate()?;
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
