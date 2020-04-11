use crate::identifiers::cred_def::CredentialDefinitionId;
use crate::ursa::cl::{
    BlindedCredentialSecrets, BlindedCredentialSecretsCorrectnessProof,
    CredentialSecretsBlindingFactors, Nonce,
};
use crate::utils::qualifier::Qualifiable;
use crate::{ConversionError, TryClone, Validatable, ValidationError};
use indy_utils::did::DidValue;

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialRequest {
    pub prover_did: DidValue,
    pub cred_def_id: CredentialDefinitionId,
    pub blinded_ms: BlindedCredentialSecrets,
    pub blinded_ms_correctness_proof: BlindedCredentialSecretsCorrectnessProof,
    pub nonce: Nonce,
}

impl CredentialRequest {
    #[allow(unused)]
    pub fn to_unqualified(self) -> CredentialRequest {
        CredentialRequest {
            prover_did: self.prover_did.to_unqualified(),
            cred_def_id: self.cred_def_id.to_unqualified(),
            blinded_ms: self.blinded_ms,
            blinded_ms_correctness_proof: self.blinded_ms_correctness_proof,
            nonce: self.nonce,
        }
    }
}

// impl TryClone for CredentialRequest {
//     fn try_clone(&self) -> Result<Self, ConversionError> {
//         Ok(Self {
//             prover_did: self.prover_did.clone(),
//             cred_def_id: self.cred_def_id.clone(),
//             blinded_ms: self.blinded_ms.try_clone()?,
//             blinded_ms_correctness_proof: self.blinded_ms_correctness_proof.try_clone()?,
//             nonce: self.nonce.try_clone()?,
//         })
//     }
// }

impl Validatable for CredentialRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        self.cred_def_id.validate()?;
        self.prover_did.validate()?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialRequestMetadata {
    pub master_secret_blinding_data: CredentialSecretsBlindingFactors,
    pub nonce: Nonce,
    pub master_secret_name: String,
}

// impl TryClone for CredentialRequestMetadata {
//     fn try_clone(&self) -> Result<Self, ConversionError> {
//         Ok(Self {
//             master_secret_blinding_data: self.master_secret_blinding_data.try_clone()?,
//             nonce: self.nonce.try_clone()?,
//             master_secret_name: self.master_secret_name.clone(),
//         })
//     }
// }

impl Validatable for CredentialRequestMetadata {}
