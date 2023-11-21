use crate::data_types::w3c::presentation_proof::CredentialPresentationProof;
use crate::utils::encoded_object::EncodedObject;
use anoncreds_clsignatures::{
    CredentialSignature as CLCredentialSignature, RevocationRegistry, SignatureCorrectnessProof,
    Witness,
};
use serde_json::Value;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CredentialProof {
    AnonCredsSignatureProof(CredentialSignatureProof),
    AnonCredsCredentialPresentationProof(CredentialPresentationProof),
    NonAnonCredsDataIntegrityProof(NonAnonCredsDataIntegrityProof),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSignatureProof {
    #[serde(rename = "type")]
    pub type_: CredentialSignatureType,
    pub signature: String,
}

impl CredentialSignatureProof {
    pub fn new(signature: CredentialSignature) -> Self {
        CredentialSignatureProof {
            type_: CredentialSignatureType::AnonCredsProof2023,
            signature: signature.encode(),
        }
    }

    pub fn get_credential_signature(&self) -> crate::Result<CredentialSignature> {
        match self.type_ {
            CredentialSignatureType::AnonCredsProof2023 => {
                CredentialSignature::decode(&self.signature)
            }
        }
    }
}

pub type NonAnonCredsDataIntegrityProof = Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialSignatureType {
    #[serde(rename = "AnonCredsProof2023")]
    AnonCredsProof2023,
}

impl Default for CredentialSignatureType {
    fn default() -> Self {
        CredentialSignatureType::AnonCredsProof2023
    }
}

impl CredentialProof {
    pub fn get_credential_signature_proof(&self) -> crate::Result<&CredentialSignatureProof> {
        match self {
            CredentialProof::AnonCredsSignatureProof(ref signature) => Ok(signature),
            _ => Err(err_msg!(
                "credential does not contain AnonCredsSignatureProof"
            )),
        }
    }

    pub(crate) fn get_mut_credential_signature_proof(
        &mut self,
    ) -> crate::Result<&mut CredentialSignatureProof> {
        match self {
            CredentialProof::AnonCredsSignatureProof(ref mut signature) => Ok(signature),
            _ => Err(err_msg!(
                "credential does not contain AnonCredsSignatureProof"
            )),
        }
    }

    pub fn get_presentation_proof(&self) -> crate::Result<&CredentialPresentationProof> {
        match self {
            CredentialProof::AnonCredsCredentialPresentationProof(ref proof) => Ok(proof),
            _ => Err(err_msg!(
                "credential does not contain AnonCredsPresentationProof"
            )),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct CredentialSignature {
    pub(crate) signature: CLCredentialSignature,
    pub(crate) signature_correctness_proof: SignatureCorrectnessProof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rev_reg: Option<RevocationRegistry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) witness: Option<Witness>,
}

impl CredentialSignature {
    pub fn new(
        signature: CLCredentialSignature,
        signature_correctness_proof: SignatureCorrectnessProof,
        rev_reg: Option<RevocationRegistry>,
        witness: Option<Witness>,
    ) -> Self {
        CredentialSignature {
            signature,
            signature_correctness_proof,
            rev_reg,
            witness,
        }
    }
}

impl EncodedObject for CredentialSignature {}
