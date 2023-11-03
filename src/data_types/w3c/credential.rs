use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::string::ToString;
use crate::cl::{
    CredentialSignature as CLCredentialSignature,
    SignatureCorrectnessProof,
};

use crate::data_types::{
    cred_def::CredentialDefinitionId,
    issuer_id::IssuerId,
    rev_reg_def::RevocationRegistryDefinitionId,
    schema::SchemaId,
    w3c::uri::URI,
};
use crate::data_types::w3c::OneOrMany;
use crate::data_types::w3c::presentation::CredentialProof;
use crate::Error;
use crate::types::Credential;
use crate::utils::base64;

/// AnonCreds W3C Credential definition
/// Note, that this definition is tied to AnonCreds W3C form
/// Some fields are defined as required despite to general W3C specification
/// For example `credential_schema` is required for AnonCreds W3C Credentials and has custom format
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct W3CCredential {
    #[serde(rename = "@context")]
    pub context: HashSet<URI>,
    #[serde(rename = "type")]
    pub type_: HashSet<String>,
    pub issuer: IssuerId,
    pub issuance_date: DateTime<Utc>,
    pub credential_schema: CredentialSchema,
    pub credential_subject: CredentialSubject,
    pub proof: OneOrMany<Proofs>,
    /// fields which are not recommended to set but their are defined in the specification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<URI>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<CredentialStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    #[serde(flatten)]
    pub property_set: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredentialStatus {
    pub id: URI,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredentialSchema {
    #[serde(rename = "type")]
    pub type_: CredentialSchemaType,
    pub definition: CredentialDefinitionId,
    pub schema: SchemaId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation: Option<RevocationRegistryDefinitionId>,
    pub encoding: AttributeEncoding,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum CredentialSchemaType {
    #[serde(rename = "AnonCredsDefinition")]
    AnonCredsDefinition,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum AttributeEncoding {
    #[serde(rename = "auto")]
    Auto,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Proofs {
    CLSignature2023(CredentialSignature),
    AnonCredsPresentationProof2022(CredentialProof),
    DataIntegrityProof(DataIntegrityProof),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredentialSignature {
    #[serde(rename = "type")]
    pub type_: CredentialSignatureType,
    pub signature: String,
}

impl From<&Credential> for CredentialSignature {
    fn from(credential: &Credential) -> Self {
        let signature_data = json!({
            "signature": credential.signature,
            "signature_correctness_proof": credential.signature_correctness_proof,
        }).to_string();
        let signature = base64::encode(signature_data.as_bytes());
        CredentialSignature {
            type_: CredentialSignatureType::CLSignature2023,
            signature,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum CredentialSignatureType {
    #[serde(rename = "CLSignature2023")]
    CLSignature2023,
}

pub type DataIntegrityProof = Value;

pub const W3C_CONTEXT: &'static str = "https://www.w3.org/2018/credentials/v1";
pub const W3C_ANONCREDS_CREDENTIAL_CONTEXT: &'static str = "https://github.io/anoncreds-w3c/context.json";
pub const W3C_CREDENTIAL_TYPE: &'static str = "VerifiableCredential";
pub const W3C_ANONCREDS_CREDENTIAL_TYPE: &'static str = "AnonCredsCredential";

impl Default for W3CCredential {
    fn default() -> Self {
        W3CCredential {
            context: HashSet::from([
                URI(W3C_CONTEXT.to_string()),
                URI(W3C_ANONCREDS_CREDENTIAL_CONTEXT.to_string())
            ]),
            type_: HashSet::from([
                W3C_CREDENTIAL_TYPE.to_string(),
                W3C_ANONCREDS_CREDENTIAL_TYPE.to_string()
            ]),
            issuer: Default::default(),
            issuance_date: Utc::now(), // FIXME: use random time of the day
            credential_schema: CredentialSchema {
                type_: CredentialSchemaType::AnonCredsDefinition,
                encoding: AttributeEncoding::Auto,
                definition: CredentialDefinitionId::default(),
                schema: SchemaId::default(),
                revocation: None,
            },
            credential_subject: Default::default(),
            proof: Default::default(),
            id: None,
            credential_status: None,
            expiration_date: None,
        }
    }
}

impl Proofs {
    pub fn credential_signature(&self) -> Option<&CredentialSignature> {
        match self {
            Proofs::CLSignature2023(ref signature) => Some(signature),
            _ => None
        }
    }
}

impl W3CCredential {
    pub fn anoncreds_credential_signature_proof(&self) -> Option<&CredentialSignature> {
        match &self.proof {
            OneOrMany::One(ref proof) => {
                proof.credential_signature()
            }
            OneOrMany::Many(proofs) => {
                proofs
                    .iter()
                    .find_map(|proof| proof.credential_signature())
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct CredentialSignatureHelper {
    pub signature: CLCredentialSignature,
    pub signature_correctness_proof: SignatureCorrectnessProof,
}

impl TryFrom<&CredentialSignature> for CredentialSignatureHelper {
    type Error = Error;

    fn try_from(value: &CredentialSignature) -> Result<Self, Self::Error> {
        match value.type_ {
            CredentialSignatureType::CLSignature2023 => {
                serde_json::from_str(&value.signature)
                    .map_err(err_map!("unable to parse credential cl signature"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test credential taken from the AnonCreds specification
    const CREDENTIAL_JSON: &str = r#"{
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://github.io/anoncreds-w3c/context.json"
      ],
      "type": [
        "VerifiableCredential",
        "AnonCredsCredential"
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
        "firstName": "Alice",
        "lastName": "Jones",
        "age": "18"
      },
      "proof": [
        {
          "type": "CLSignature2023",
          "signature": "AAAgf9w5.....8Z_x3FqdwRHoWruiF0FlM"
        },
        {
          "type": "Ed25519Signature2020",
          "created": "2021-11-13T18:19:39Z",
          "verificationMethod": "did:sov:3avoBCqDMFHFaKUHug9s8W#key-1",
          "proofPurpose": "assertionMethod",
          "proofValue": "z58DAdFfa9SkqZMVPxAQpic7ndSayn1PzZs6ZjWp1CktyGesjuTSwRdoWhAfGFCF5bppETSTojQCrfFPP2oumHKtz"
        }
      ]
    }"#;

    #[test]
    fn test_parse_credential() {
        let cred: W3CCredential = serde_json::from_str(CREDENTIAL_JSON).unwrap();
        let expected = HashSet::from([
            URI("https://www.w3.org/2018/credentials/v1".to_string()),
            URI("https://github.io/anoncreds-w3c/context.json".to_string()),
        ]);

        assert_eq!(cred.context, expected)
    }
}
