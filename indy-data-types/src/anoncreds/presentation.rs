use std::collections::HashMap;

use crate::identifiers::cred_def::CredentialDefinitionId;
use crate::identifiers::rev_reg::RevocationRegistryId;
use crate::identifiers::schema::SchemaId;
use crate::ursa::cl::Proof;
use crate::Validatable;

#[derive(Debug, Serialize, Deserialize)]
pub struct Presentation {
    pub proof: Proof,
    pub requested_proof: RequestedProof,
    pub identifiers: Vec<Identifier>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequestedProof {
    pub revealed_attrs: HashMap<String, RevealedAttributeInfo>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    #[serde(default)]
    pub revealed_attr_groups: HashMap<String, RevealedAttributeGroupInfo>,
    #[serde(default)]
    pub self_attested_attrs: HashMap<String, String>,
    #[serde(default)]
    pub unrevealed_attrs: HashMap<String, SubProofReferent>,
    #[serde(default)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubProofReferent {
    pub sub_proof_index: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RevealedAttributeInfo {
    pub sub_proof_index: u32,
    pub raw: String,
    pub encoded: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RevealedAttributeGroupInfo {
    pub sub_proof_index: u32,
    pub values: HashMap<String /* attribute name */, AttributeValue>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AttributeValue {
    pub raw: String,
    pub encoded: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct Identifier {
    pub schema_id: SchemaId,
    pub cred_def_id: CredentialDefinitionId,
    pub rev_reg_id: Option<RevocationRegistryId>,
    pub timestamp: Option<u64>,
}

impl Validatable for Presentation {}

#[cfg(test)]
mod tests {
    use super::*;

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
