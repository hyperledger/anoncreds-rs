use crate::data_types::credential_w3c::{CredentialWC3, ProofEncoding, UriString};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationWC3 {
    #[serde(rename = "@context")]
    pub context: HashSet<UriString>,
    #[serde(rename = "type")]
    pub type_: HashSet<String>,
    pub verifiable_credential: Vec<CredentialWC3>,
    pub proof: Proof,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    #[serde(rename = "type")]
    pub type_: String,
    pub challenge: String,
    pub proof_value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProofVerifiableCredential {
    #[serde(rename = "type")]
    pub type_: String,
    pub credential: ProofCredential,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProofCredential {
    pub encoding: ProofEncoding,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapping: Option<ProofCredentialMapping>,
    pub proof_value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProofCredentialMapping {
    pub revealed_attributes: Vec<HashMap<String, String>>,
    pub unrevealed_attributes: Vec<HashMap<String, String>>,
    pub requested_predicates: Vec<HashMap<String, Value>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRESENTATION_JSON: &str = r#"{"@context":["https://www.w3.org/2018/credentials/v1","https://github.io/anoncreds-w3c/context.json"],"type":["VerifiablePresentation","AnonCredsPresentation"],"verifiableCredential":[{"@context":["https://www.w3.org/2018/credentials/v1","https://github.io/anoncreds-w3c/context.json"],"type":["VerifiableCredential","AnonCredsPresentation"],"issuer":"did:sov:3avoBCqDMFHFaKUHug9s8W","issuanceDate":"2023-10-26T01:17:32Z","credentialSchema":{"type":"AnonCredsDefinition","id":"did:sov:3avoBCqDMFHFaKUHug9s8W:3:CL:13:default","schema":"did:sov:3avoBCqDMFHFaKUHug9s8W:2:basic_name:0.1.0"},"credentialSubject":{"name":"Alice Jones"},"proof":{"type":"AnonCredsPresentationProof2022","credential":{"encoding":"auto","mapping":{"revealedAttributes":[{"name":"first_name","referent":"attribute_0"}],"unrevealedAttributes":[{"name":"last_name","referent":"attribute_1"}],"requestedPredicates":[{"name":"birthdate","p_type":"<","value":20041012,"referent":"predicate_1"}]},"proofValue":"AAEBAnr2Ql...0UhJ-bIIdWFKVWxjU3ePxv_7HoY5pUw"}}}],"proof":{"type":"AnonCredsPresentationProof2022","challenge":"182453895158932070575246","proofValue":"AAAgtMR4DrkY--ZVgKHmUANE04ET7TzUxZ0vZmVcNt4nCkwBABUACQJ69kJVIxHVAQAIAaJ19l-agSA"}}"#;

    #[test]
    fn test_parse_wc3_presentation() {
        let cred: PresentationWC3 = serde_json::from_str(PRESENTATION_JSON).unwrap();
        let expected = HashSet::from([
            UriString("https://www.w3.org/2018/credentials/v1".to_string()),
            UriString("https://github.io/anoncreds-w3c/context.json".to_string()),
        ]);

        assert_eq!(cred.context, expected)
    }
}
