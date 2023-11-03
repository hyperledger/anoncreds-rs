use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::data_types::{
    pres_request::PredicateTypes,
    w3c::{
        credential::W3CCredential,
        uri::URI
    }
};

/// AnonCreds W3C Presentation definition
/// Note, that this definition is tied to AnonCreds W3C form
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct W3CPresentation {
    #[serde(rename = "@context")]
    pub context: HashSet<URI>,
    #[serde(rename = "type")]
    pub type_: HashSet<String>,
    pub verifiable_credential: Vec<W3CCredential>,
    pub proof: PresentationProof,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialProof {
    #[serde(rename = "type")]
    pub type_: PresentationProofType,
    pub mapping: AttributesMapping,
    pub proof_value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PresentationProof {
    #[serde(rename = "type")]
    pub type_: PresentationProofType,
    pub challenge: String,
    pub proof_value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum PresentationProofType {
    #[serde(rename = "AnonCredsPresentationProof2022")]
    AnonCredsPresentationProof2022,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AttributesMapping {
    #[serde(default)]
    pub revealed_attributes: Vec<Attribute>,
    #[serde(default)]
    pub unrevealed_attributes: Vec<Attribute>,
    #[serde(default)]
    pub requested_predicates: Vec<Predicate>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Attribute {
    pub referent: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Predicate {
    pub referent: String,
    pub name: String,
    pub p_type: PredicateTypes,
    pub p_value: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test presentation taken from the AnonCreds specification
    const PRESENTATION_JSON: &str = r#"{
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://github.io/anoncreds-w3c/context.json"
      ],
      "type": [
        "VerifiablePresentation",
        "AnonCredsPresentation"
      ],
      "verifiableCredential": [
        {
          "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://github.io/anoncreds-w3c/context.json"
          ],
          "type": [
            "VerifiableCredential",
            "AnonCredsPresentation"
          ],
          "issuer": "did:sov:3avoBCqDMFHFaKUHug9s8W",
          "issuanceDate": "2023-10-26T01:17:32Z",
          "credentialSchema": {
            "type": "AnonCredsDefinition",
            "definition": "did:sov:3avoBCqDMFHFaKUHug9s8W:3:CL:13:default",
            "schema": "did:sov:3avoBCqDMFHFaKUHug9s8W:2:basic_person:0.1.0",
            "encoding": "auto"
          },
          "credentialSubject": {
            "firstName": "Alice"
          },
          "proof": {
            "type": "AnonCredsPresentationProof2022",
            "credential": {
              "mapping": {
                "revealedAttributes": [
                  {
                    "name": "firstName",
                    "referent": "attribute_0"
                  }
                ],
                "unrevealedAttributes": [
                  {
                    "name": "lastName",
                    "referent": "attribute_1"
                  }
                ],
                "requestedPredicates": [
                  {
                    "name": "age",
                    "p_type": "<",
                    "value": 18,
                    "referent": "predicate_1"
                  }
                ]
              },
              "proofValue": "AAEBAnr2Ql...0UhJ-bIIdWFKVWxjU3ePxv_7HoY5pUw"
            }
          }
        }
      ],
      "proof": {
        "type": "AnonCredsPresentationProof2022",
        "challenge": "182453895158932070575246",
        "proofValue": "AAAgtMR4....J19l-agSA"
      }
    }"#;

    #[test]
    fn test_parse_presentation() {
        let cred: W3CPresentation = serde_json::from_str(PRESENTATION_JSON).unwrap();
        let expected = HashSet::from([
            URI("https://www.w3.org/2018/credentials/v1".to_string()),
            URI("https://github.io/anoncreds-w3c/context.json".to_string()),
        ]);

        assert_eq!(cred.context, expected)
    }
}
