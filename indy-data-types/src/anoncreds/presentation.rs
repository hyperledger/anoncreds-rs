use std::collections::HashMap;

use super::cl_compat::proof::Proof;
use crate::identifiers::cred_def::CredentialDefinitionId;
use crate::identifiers::rev_reg::RevocationRegistryId;
use crate::identifiers::schema::SchemaId;
use crate::Validatable;

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct Presentation {
    pub proof: Proof,
    pub requested_proof: RequestedProof,
    pub identifiers: Vec<Identifier>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct RequestedProof {
    pub revealed_attrs: HashMap<String, RevealedAttributeInfo>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "HashMap::is_empty"))]
    #[cfg_attr(feature = "serde", serde(default))]
    pub revealed_attr_groups: HashMap<String, RevealedAttributeGroupInfo>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub self_attested_attrs: HashMap<String, String>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub unrevealed_attrs: HashMap<String, SubProofReferent>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub predicates: HashMap<String, SubProofReferent>,
}

impl Default for RequestedProof {
    fn default() -> Self {
        RequestedProof {
            revealed_attrs: HashMap::new(),
            revealed_attr_groups: HashMap::new(),
            self_attested_attrs: HashMap::new(),
            unrevealed_attrs: HashMap::new(),
            predicates: HashMap::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct SubProofReferent {
    pub sub_proof_index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct RevealedAttributeInfo {
    pub sub_proof_index: u32,
    pub raw: String,
    pub encoded: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct RevealedAttributeGroupInfo {
    pub sub_proof_index: u32,
    pub values: HashMap<String /* attribute name */, AttributeValue>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct AttributeValue {
    pub raw: String,
    pub encoded: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct Identifier {
    pub schema_id: SchemaId,
    pub cred_def_id: CredentialDefinitionId,
    pub rev_reg_id: Option<RevocationRegistryId>,
    pub timestamp: Option<u64>,
}

impl Validatable for Presentation {}

#[cfg(test)]
mod tests {
    #[cfg(feature = "serde")]
    use super::*;

    #[cfg(feature = "serde")]
    #[test]
    fn deserialize_requested_proof_with_empty_revealed_attr_groups() {
        let mut req_proof_old: RequestedProof = Default::default();
        req_proof_old.revealed_attrs.insert(
            "attr1".to_string(),
            RevealedAttributeInfo {
                sub_proof_index: 0,
                raw: "123".to_string(),
                encoded: "123".to_string(),
            },
        );
        let json = json!(req_proof_old).to_string();
        println!("{}", json);

        let req_proof: RequestedProof = serde_json::from_str(&json).unwrap();
        assert!(req_proof.revealed_attr_groups.is_empty())
    }
}
