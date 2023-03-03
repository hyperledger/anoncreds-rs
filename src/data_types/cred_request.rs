use crate::error::{Result, ValidationError};
use crate::invalid;
use crate::utils::validation::{Validatable, LEGACY_IDENTIFIER};

use super::{cred_def::CredentialDefinitionId, nonce::Nonce};

#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    entropy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prover_did: Option<String>,
    cred_def_id: CredentialDefinitionId,
    pub blinded_ms: ursa::cl::BlindedCredentialSecrets,
    pub blinded_ms_correctness_proof: ursa::cl::BlindedCredentialSecretsCorrectnessProof,
    pub nonce: Nonce,
}

impl Validatable for CredentialRequest {
    fn validate(&self) -> std::result::Result<(), ValidationError> {
        self.cred_def_id.validate()?;

        match &self.entropy {
            Some(_) => {
                if self.prover_did.is_some() {
                    Err(invalid!("Prover did and entropy must not both be supplied"))
                } else {
                    Ok(())
                }
            }
            None => {
                if self.cred_def_id.is_legacy() {
                    if let Some(prover_did) = self.prover_did.clone() {
                        if LEGACY_IDENTIFIER.captures(&prover_did).is_some() {
                            Ok(())
                        } else {
                            Err(invalid!("Prover did was supplied, not valid"))
                        }
                    } else {
                        Err(invalid!(
                            "Legacy identifiers used but no entropy or prover did was supplied"
                        ))
                    }
                } else {
                    Err(invalid!("entropy is required"))
                }
            }
        }?;
        Ok(())
    }
}

impl CredentialRequest {
    pub fn new(
        entropy: Option<&str>,
        prover_did: Option<&str>,
        cred_def_id: CredentialDefinitionId,
        blinded_ms: ursa::cl::BlindedCredentialSecrets,
        blinded_ms_correctness_proof: ursa::cl::BlindedCredentialSecretsCorrectnessProof,
        nonce: Nonce,
    ) -> Result<Self> {
        let s = Self {
            entropy: entropy.map(|e| e.to_owned()),
            prover_did: prover_did.map(|p| p.to_owned()),
            cred_def_id,
            blinded_ms,
            blinded_ms_correctness_proof,
            nonce,
        };
        s.validate()?;
        Ok(s)
    }

    pub fn entropy(&self) -> Result<String> {
        self.entropy.clone().map(Result::Ok).unwrap_or_else(|| {
            self.prover_did
                .clone()
                .ok_or(err_msg!("Entropy or prover did must be supplied"))
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialRequestMetadata {
    pub master_secret_blinding_data: ursa::cl::CredentialSecretsBlindingFactors,
    pub nonce: Nonce,
    pub master_secret_name: String,
}

impl Validatable for CredentialRequestMetadata {}

#[cfg(test)]
mod cred_req_tests {
    use crate::{
        data_types::{
            cred_def::{CredentialDefinition, CredentialKeyCorrectnessProof, SignatureType},
            cred_offer::CredentialOffer,
            master_secret::MasterSecret,
            schema::AttributeNames,
        },
        issuer::{create_credential_definition, create_credential_offer, create_schema},
        prover::create_credential_request,
        types::CredentialDefinitionConfig,
    };

    use super::*;

    const NEW_IDENTIFIER: &str = "mock:uri";
    const LEGACY_IDENTIFIER: &str = "NcYxiDXkpYi6ov5FcYDi1e";

    const ENTROPY: Option<&str> = Some("entropy");
    const PROVER_DID: Option<&str> = Some(LEGACY_IDENTIFIER);
    const MASTER_SERCET_ID: &str = "master:secret:id";

    fn cred_def() -> Result<(CredentialDefinition, CredentialKeyCorrectnessProof)> {
        let credential_definition_issuer_id = "sample:id";

        let attr_names = AttributeNames::from(vec!["name".to_owned(), "age".to_owned()]);
        let schema = create_schema("schema:name", "1.0", "sample:uri", attr_names)?;
        let cred_def = create_credential_definition(
            "schema:id",
            &schema,
            credential_definition_issuer_id,
            "default",
            SignatureType::CL,
            CredentialDefinitionConfig {
                support_revocation: true,
            },
        )?;

        Ok((cred_def.0, cred_def.2))
    }

    fn master_secret() -> MasterSecret {
        MasterSecret::new().unwrap()
    }

    fn credential_offer(
        correctness_proof: CredentialKeyCorrectnessProof,
        is_legacy: bool,
    ) -> Result<CredentialOffer> {
        if is_legacy {
            create_credential_offer(LEGACY_IDENTIFIER, LEGACY_IDENTIFIER, &correctness_proof)
        } else {
            create_credential_offer(NEW_IDENTIFIER, NEW_IDENTIFIER, &correctness_proof)
        }
    }

    #[test]
    fn create_credential_request_with_valid_input() -> Result<()> {
        let (cred_def, correctness_proof) = cred_def()?;
        let master_secret = master_secret();
        let credential_offer = credential_offer(correctness_proof, false)?;

        let res = create_credential_request(
            ENTROPY,
            None,
            &cred_def,
            &master_secret,
            MASTER_SERCET_ID,
            &credential_offer,
        );

        assert!(res.is_ok());

        Ok(())
    }

    #[test]
    fn create_credential_request_with_valid_input_legacy() -> Result<()> {
        let (cred_def, correctness_proof) = cred_def()?;
        let master_secret = master_secret();
        let credential_offer = credential_offer(correctness_proof, true)?;

        let res = create_credential_request(
            None,
            PROVER_DID,
            &cred_def,
            &master_secret,
            MASTER_SERCET_ID,
            &credential_offer,
        );

        assert!(res.is_ok());

        Ok(())
    }

    #[test]
    fn create_credential_request_with_invalid_new_identifiers_and_prover_did() -> Result<()> {
        let (cred_def, correctness_proof) = cred_def()?;
        let master_secret = master_secret();
        let credential_offer = credential_offer(correctness_proof, false)?;

        let res = create_credential_request(
            None,
            PROVER_DID,
            &cred_def,
            &master_secret,
            MASTER_SERCET_ID,
            &credential_offer,
        );

        assert!(res.is_err());

        Ok(())
    }

    #[test]
    fn create_credential_request_with_invalid_prover_did_and_entropy() -> Result<()> {
        let (cred_def, correctness_proof) = cred_def()?;
        let master_secret = master_secret();
        let credential_offer = credential_offer(correctness_proof, true)?;

        let res = create_credential_request(
            ENTROPY,
            PROVER_DID,
            &cred_def,
            &master_secret,
            MASTER_SERCET_ID,
            &credential_offer,
        );

        assert!(res.is_err());

        Ok(())
    }

    #[test]
    fn create_credential_request_with_invalid_prover_did() -> Result<()> {
        let (cred_def, correctness_proof) = cred_def()?;
        let master_secret = master_secret();
        let credential_offer = credential_offer(correctness_proof, true)?;

        let res = create_credential_request(
            None,
            ENTROPY,
            &cred_def,
            &master_secret,
            MASTER_SERCET_ID,
            &credential_offer,
        );

        assert!(res.is_err());

        Ok(())
    }

    #[test]
    fn create_credential_request_with_no_entropy_or_prover_did() -> Result<()> {
        let (cred_def, correctness_proof) = cred_def()?;
        let master_secret = master_secret();
        let credential_offer = credential_offer(correctness_proof, true)?;

        let res = create_credential_request(
            None,
            None,
            &cred_def,
            &master_secret,
            MASTER_SERCET_ID,
            &credential_offer,
        );

        assert!(res.is_err());

        Ok(())
    }

    #[test]
    fn create_credential_request_json_contains_entropy() -> Result<()> {
        let (cred_def, correctness_proof) = cred_def()?;
        let master_secret = master_secret();
        let credential_offer = credential_offer(correctness_proof, false)?;

        let res = create_credential_request(
            ENTROPY,
            None,
            &cred_def,
            &master_secret,
            MASTER_SERCET_ID,
            &credential_offer,
        )
        .unwrap();

        let s = serde_json::to_string(&res)?;

        assert!(s.contains("entropy"));

        Ok(())
    }

    #[test]
    fn create_credential_request_json_contains_prover_did_with_legacy_identifiers() -> Result<()> {
        let (cred_def, correctness_proof) = cred_def()?;
        let master_secret = master_secret();
        let credential_offer = credential_offer(correctness_proof, true)?;

        let res = create_credential_request(
            None,
            PROVER_DID,
            &cred_def,
            &master_secret,
            MASTER_SERCET_ID,
            &credential_offer,
        )
        .unwrap();

        let s = serde_json::to_string(&res)?;

        assert!(s.contains("prover_did"));

        Ok(())
    }

    #[test]
    fn create_credential_request_json_contains_entropy_with_legacy_identifiers() -> Result<()> {
        let (cred_def, correctness_proof) = cred_def()?;
        let master_secret = master_secret();
        let credential_offer = credential_offer(correctness_proof, false)?;

        let res = create_credential_request(
            ENTROPY,
            None,
            &cred_def,
            &master_secret,
            MASTER_SERCET_ID,
            &credential_offer,
        )
        .unwrap();

        let s = serde_json::to_string(&res)?;

        assert!(s.contains("entropy"));

        Ok(())
    }
}
