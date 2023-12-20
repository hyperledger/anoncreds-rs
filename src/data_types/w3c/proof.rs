use crate::data_types::cred_def::CredentialDefinitionId;
use crate::data_types::rev_reg_def::RevocationRegistryDefinitionId;
use crate::data_types::schema::SchemaId;
use crate::utils::encoded_object::EncodedObject;
use crate::Result;
use anoncreds_clsignatures::{
    AggregatedProof, CredentialSignature as CLCredentialSignature, RevocationRegistry,
    SignatureCorrectnessProof, SubProof, Witness,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataIntegrityProof {
    #[serde(rename = "type")]
    pub(crate) type_: DataIntegrityProofType,
    pub(crate) cryptosuite: CryptoSuite,
    #[serde(rename = "proofValue")]
    pub(crate) proof_value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) challenge: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataIntegrityProofType {
    DataIntegrityProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoSuite {
    #[serde(rename = "anoncredsvc-2023")]
    AnonCredsVc2023,
    #[serde(rename = "anoncredspresvc-2023")]
    AnonCredsPresVc2023,
    #[serde(rename = "anoncredspresvp-2023")]
    AnonCredsPresVp2023,
}

impl DataIntegrityProof {
    pub fn new<V: EncodedObject + Serialize>(
        cryptosuite: CryptoSuite,
        value: V,
        challenge: Option<String>,
    ) -> Self {
        DataIntegrityProof {
            type_: DataIntegrityProofType::DataIntegrityProof,
            cryptosuite,
            proof_value: value.encode(),
            challenge,
        }
    }

    pub(crate) fn new_credential_proof(value: CredentialSignatureProof) -> DataIntegrityProof {
        DataIntegrityProof::new(CryptoSuite::AnonCredsVc2023, value, None)
    }

    pub(crate) fn new_credential_presentation_proof(
        value: CredentialPresentationProofValue,
    ) -> DataIntegrityProof {
        DataIntegrityProof::new(CryptoSuite::AnonCredsPresVc2023, value, None)
    }

    pub(crate) fn new_presentation_proof(
        value: PresentationProofValue,
        challenge: String,
    ) -> DataIntegrityProof {
        DataIntegrityProof::new(CryptoSuite::AnonCredsPresVp2023, value, Some(challenge))
    }

    pub fn get_proof_value<V: EncodedObject + DeserializeOwned>(&self) -> Result<V> {
        V::decode(&self.proof_value)
    }

    pub fn is_anon_creds_vc_proof(&self) -> bool {
        self.cryptosuite == CryptoSuite::AnonCredsVc2023
    }

    pub fn is_anon_creds_pres_vc_proof(&self) -> bool {
        self.cryptosuite == CryptoSuite::AnonCredsPresVc2023
    }

    pub fn is_anon_creds_pres_proof(&self) -> bool {
        self.cryptosuite == CryptoSuite::AnonCredsPresVp2023
    }

    pub fn get_credential_signature_proof(&self) -> Result<CredentialSignatureProof> {
        if !self.is_anon_creds_vc_proof() {
            return Err(err_msg!(
                "DataIntegrityProof does not contain {:?} proof",
                CryptoSuite::AnonCredsVc2023
            ));
        }
        self.get_proof_value()
    }

    pub fn get_credential_presentation_proof(&self) -> Result<CredentialPresentationProofValue> {
        if !self.is_anon_creds_pres_vc_proof() {
            return Err(err_msg!(
                "DataIntegrityProof does not contain {:?} proof",
                CryptoSuite::AnonCredsPresVc2023
            ));
        }
        self.get_proof_value()
    }

    pub fn get_presentation_proof(&self) -> Result<PresentationProofValue> {
        if !self.is_anon_creds_vc_proof() {
            return Err(err_msg!(
                "DataIntegrityProof does not contain {:?} proof",
                CryptoSuite::AnonCredsPresVp2023
            ));
        }
        self.get_proof_value()
    }

    pub fn get_credential_proof_details(&self) -> Result<CredentialProofDetails> {
        match self.cryptosuite {
            CryptoSuite::AnonCredsVc2023 => {
                let proof = self.get_credential_signature_proof()?;
                Ok(CredentialProofDetails {
                    schema_id: proof.schema_id,
                    cred_def_id: proof.cred_def_id,
                    rev_reg_id: proof.rev_reg_id,
                    rev_reg_index: proof.signature.extract_index(),
                    timestamp: None,
                })
            }
            CryptoSuite::AnonCredsPresVc2023 => {
                let proof = self.get_credential_presentation_proof()?;
                Ok(CredentialProofDetails {
                    schema_id: proof.schema_id,
                    cred_def_id: proof.cred_def_id,
                    rev_reg_id: proof.rev_reg_id,
                    rev_reg_index: None,
                    timestamp: proof.timestamp,
                })
            }
            CryptoSuite::AnonCredsPresVp2023 => Err(err_msg!("Unexpected DataIntegrityProof")),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct CredentialSignatureProof {
    pub schema_id: SchemaId,
    pub cred_def_id: CredentialDefinitionId,
    pub rev_reg_id: Option<RevocationRegistryDefinitionId>,
    pub signature: CLCredentialSignature,
    pub signature_correctness_proof: SignatureCorrectnessProof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rev_reg: Option<RevocationRegistry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<Witness>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialPresentationProofValue {
    pub schema_id: SchemaId,
    pub cred_def_id: CredentialDefinitionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rev_reg_id: Option<RevocationRegistryDefinitionId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    pub sub_proof: SubProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PresentationProofValue {
    pub aggregated: AggregatedProof,
}

impl EncodedObject for CredentialSignatureProof {}

impl EncodedObject for CredentialPresentationProofValue {}

impl EncodedObject for PresentationProofValue {}

// Credential information aggregated from `CredentialSignatureProof` and `CredentialPresentationProofValue`
// This information is needed for presentation creation and verification
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CredentialProofDetails {
    pub schema_id: SchemaId,
    pub cred_def_id: CredentialDefinitionId,
    pub rev_reg_id: Option<RevocationRegistryDefinitionId>,
    pub rev_reg_index: Option<u32>,
    pub timestamp: Option<u64>,
}
