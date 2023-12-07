use crate::data_types::pres_request::{PredicateInfo, PredicateTypes};
use crate::utils::encoded_object::EncodedObject;
use crate::Result;
use anoncreds_clsignatures::{AggregatedProof, SubProof};
use std::collections::HashSet;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialPresentationProof {
    #[serde(rename = "type")]
    pub type_: PresentationProofType,
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
}

impl EncodedObject for CredentialPresentationProofValue {}

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

    pub fn get_proof_value(&self) -> Result<CredentialPresentationProofValue> {
        match self.type_ {
            PresentationProofType::AnonCredsPresentationProof2023 => {
                CredentialPresentationProofValue::decode(&self.proof_value)
            }
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    pub fn new(proof_value: PresentationProofValue, nonce: String) -> PresentationProof {
        PresentationProof {
            type_: PresentationProofType::AnonCredsPresentationProof2023,
            challenge: nonce,
            proof_value: proof_value.encode(),
        }
    }

    pub fn get_proof_value(&self) -> Result<PresentationProofValue> {
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
}

impl EncodedObject for PresentationProofValue {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PresentationProofType {
    #[serde(rename = "AnonCredsPresentationProof2023")]
    AnonCredsPresentationProof2023,
}

impl Default for PresentationProofType {
    fn default() -> Self {
        PresentationProofType::AnonCredsPresentationProof2023
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialAttributesMapping {
    #[serde(default)]
    pub revealed_attributes: HashSet<String>,
    pub revealed_attribute_groups: HashSet<String>,
    #[serde(default)]
    pub unrevealed_attributes: HashSet<String>,
    #[serde(default)]
    pub predicates: HashSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct PredicateAttribute {
    #[serde(rename = "type")]
    pub type_: PredicateAttributeType,
    pub predicate: PredicateTypes,
    pub value: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PredicateAttributeType {
    #[serde(rename = "AnonCredsPredicate")]
    AnonCredsPredicate,
}

impl Default for PredicateAttributeType {
    fn default() -> Self {
        PredicateAttributeType::AnonCredsPredicate
    }
}

impl From<PredicateInfo> for PredicateAttribute {
    fn from(info: PredicateInfo) -> Self {
        PredicateAttribute {
            type_: PredicateAttributeType::AnonCredsPredicate,
            predicate: info.p_type,
            value: info.p_value,
        }
    }
}
