use crate::data_types::nonce::Nonce;
use crate::data_types::pres_request::PredicateTypes;
use crate::utils::base64;
use anoncreds_clsignatures::{AggregatedProof, SubProof};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialPresentationProof {
    #[serde(rename = "type")]
    pub type_: PresentationProofType,
    /// Uniform Resource Identifier - https://www.w3.org/TR/vc-data-model/#dfn-uri
    // FIXME: Consider either removing or moving under proof_value
    //  In fact, it's only needed to make attributes validation on the verifier side
    //  Revealed attributes and predicates can be restored from credential subject, but not unrevealed attributes
    pub mapping: CredentialAttributesMapping,
    pub proof_value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    // Timestamp is needed to query revocation registry at the specific moment in time
    pub timestamp: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialPresentationProofValue {
    pub(crate) sub_proof: SubProof,
}

impl CredentialPresentationProofValue {
    pub fn new(sub_proof: SubProof) -> CredentialPresentationProofValue {
        CredentialPresentationProofValue { sub_proof }
    }

    pub fn encode(&self) -> String {
        base64::encode_json(&self)
    }

    pub fn decode(string: &str) -> crate::Result<CredentialPresentationProofValue> {
        base64::decode_json(string)
    }
}

impl CredentialPresentationProof {
    pub fn new(
        proof_value: CredentialPresentationProofValue,
        mapping: CredentialAttributesMapping,
        timestamp: Option<u64>,
    ) -> CredentialPresentationProof {
        CredentialPresentationProof {
            type_: PresentationProofType::AnonCredsPresentationProof2023,
            mapping,
            timestamp,
            proof_value: proof_value.encode(),
        }
    }

    pub fn get_proof_value(&self) -> crate::Result<CredentialPresentationProofValue> {
        match self.type_ {
            PresentationProofType::AnonCredsPresentationProof2023 => {
                CredentialPresentationProofValue::decode(&self.proof_value)
            }
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationProof {
    #[serde(rename = "type")]
    pub type_: PresentationProofType,
    pub challenge: String,
    pub proof_value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PresentationProofValue {
    pub(crate) aggregated: AggregatedProof,
}

impl PresentationProof {
    pub fn new(proof_value: PresentationProofValue, nonce: Nonce) -> PresentationProof {
        PresentationProof {
            type_: PresentationProofType::AnonCredsPresentationProof2023,
            challenge: nonce.to_string(),
            proof_value: proof_value.encode(),
        }
    }

    pub fn get_proof_value(&self) -> crate::Result<PresentationProofValue> {
        match self.type_ {
            PresentationProofType::AnonCredsPresentationProof2023 => {
                PresentationProofValue::decode(&self.proof_value)
            }
        }
    }
}

impl PresentationProofValue {
    pub fn new(aggregated_proof: AggregatedProof) -> PresentationProofValue {
        PresentationProofValue {
            aggregated: aggregated_proof,
        }
    }

    pub fn encode(&self) -> String {
        base64::encode_json(&self)
    }

    pub fn decode(string: &str) -> crate::Result<PresentationProofValue> {
        base64::decode_json(string)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PresentationProofType {
    #[serde(rename = "AnonCredsPresentationProof2023")]
    AnonCredsPresentationProof2023,
}

impl Default for PresentationProofType {
    fn default() -> Self {
        PresentationProofType::AnonCredsPresentationProof2023
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialAttributesMapping {
    #[serde(default)]
    pub revealed_attributes: Vec<Attribute>,
    pub revealed_attribute_groups: Vec<AttributeGroup>,
    #[serde(default)]
    pub unrevealed_attributes: Vec<Attribute>,
    #[serde(default)]
    pub requested_predicates: Vec<Predicate>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Attribute {
    pub referent: String,
    pub name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AttributeGroup {
    pub referent: String,
    pub names: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Predicate {
    pub referent: String,
    pub name: String,
    pub p_type: PredicateTypes,
    pub p_value: i32,
}