use serde_json::Value;
use anoncreds_clsignatures::{
    CredentialSignature as CLCredentialSignature,
    RevocationRegistry,
    SignatureCorrectnessProof,
    Witness,
};
use crate::data_types::w3c::presentation_proof::CredentialPresentationProof;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CredentialProof {
    AnonCredsSignatureProof(CredentialSignatureProof),
    AnonCredsCredentialPresentationProof(CredentialPresentationProof),
    NonAnonCredsDataIntegrityProof(NonAnonCredsDataIntegrityProof),
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CredentialSignatureProof {
    #[serde(rename = "type")]
    pub type_: CredentialSignatureType,
    pub signature: String,
}

impl CredentialSignatureProof {
    pub fn new(signature: CredentialSignature) -> Self {
        CredentialSignatureProof {
            type_: CredentialSignatureType::CLSignature2023,
            signature: signature.encode(),
        }
    }

    pub fn get_credential_signature(&self) -> crate::Result<CredentialSignature> {
        match self.type_ {
            CredentialSignatureType::CLSignature2023 => {
                CredentialSignature::decode(&self.signature)
            }
        }
    }
}

pub type NonAnonCredsDataIntegrityProof = Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CredentialSignatureType {
    #[serde(rename = "CLSignature2023")]
    CLSignature2023,
}

impl Default for CredentialSignatureType {
    fn default() -> Self {
        CredentialSignatureType::CLSignature2023
    }
}

impl CredentialProof {
    pub fn get_credential_signature_proof(&self) -> crate::Result<&CredentialSignatureProof> {
        match self {
            CredentialProof::AnonCredsSignatureProof(ref signature) => Ok(signature),
            _ => Err(err_msg!("credential does not contain AnonCredsSignatureProof"))
        }
    }

    pub fn get_mut_credential_signature_proof(&mut self) -> crate::Result<&mut CredentialSignatureProof> {
        match self {
            CredentialProof::AnonCredsSignatureProof(ref mut signature) => Ok(signature),
            _ => Err(err_msg!("credential does not contain AnonCredsSignatureProof"))
        }
    }

    pub fn get_presentation_proof(&self) -> crate::Result<&CredentialPresentationProof> {
        match self {
            CredentialProof::AnonCredsCredentialPresentationProof(ref proof) => Ok(proof),
            _ => Err(err_msg!("credential does not contain AnonCredsPresentationProof"))
        }
    }

    pub fn get_mut_presentation_proof(&mut self) -> crate::Result<&mut CredentialPresentationProof> {
        match self {
            CredentialProof::AnonCredsCredentialPresentationProof(ref mut proof) => Ok(proof),
            _ => Err(err_msg!("credential does not contain AnonCredsPresentationProof"))
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct CredentialSignature {
    pub signature: CLCredentialSignature,
    pub signature_correctness_proof: SignatureCorrectnessProof,
    pub rev_reg: Option<RevocationRegistry>,
    pub witness: Option<Witness>,
}

impl CredentialSignature {
    pub fn new(signature: CLCredentialSignature,
               signature_correctness_proof: SignatureCorrectnessProof,
               rev_reg: Option<RevocationRegistry>,
               witness: Option<Witness>, ) -> Self {
        CredentialSignature {
            signature,
            signature_correctness_proof,
            rev_reg,
            witness,
        }
    }

    pub fn encode(&self) -> String {
        crate::utils::base64::encode_json(&self)
    }

    pub fn decode(string: &str) -> crate::Result<CredentialSignature> {
        crate::utils::base64::decode_json(string)
    }
}
