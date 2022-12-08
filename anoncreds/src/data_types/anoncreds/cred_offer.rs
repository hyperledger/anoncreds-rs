use super::{nonce::Nonce, schema::SchemaId};

#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialOffer {
    pub schema_id: SchemaId,
    pub cred_def_id: String,
    pub key_correctness_proof: ursa::cl::CredentialKeyCorrectnessProof,
    pub nonce: Nonce,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method_name: Option<String>,
}
