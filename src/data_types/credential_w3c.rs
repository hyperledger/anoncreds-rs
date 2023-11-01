use crate::data_types::presentation_w3c::ProofVerifiableCredential;
use crate::utils::validation::{
    CRED_DEF_IDENTIFIER, DID_IDENTIFIER, SCHEMA_IDENTIFIER, URI_IDENTIFIER,
};

use chrono::{DateTime, Utc};
use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialWC3 {
    #[serde(rename = "@context")]
    pub context: HashSet<UriString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<UriString>,
    #[serde(rename = "type")]
    pub type_: HashSet<String>,
    #[serde(deserialize_with = "deserialize_issuer_id")]
    pub issuer: String,
    pub issuance_date: DateTime<Utc>,
    pub credential_subject: CredentialSubject,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<CredentialStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<CredentialSchema>,
    pub proof: Proofs,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq, Hash)]
pub struct UriString(pub String);

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<UriString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<HashMap<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredentialStatus {
    pub id: UriString,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredentialSchema {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(deserialize_with = "deserialize_cred_def_id")]
    pub id: String,
    #[serde(deserialize_with = "deserialize_schema_id")]
    pub schema: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Proofs {
    CredentialProof(Vec<Proof>),
    VerifiableCredentialProof(ProofVerifiableCredential),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Proof {
    #[serde(rename = "type")]
    pub type_: String,
    pub encoding: ProofEncoding,
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ProofEncoding {
    #[serde(rename = "auto")]
    Auto,
}

impl<'de> Deserialize<'de> for UriString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = Value::deserialize(deserializer)?;

        let id: String = Deserialize::deserialize(v).map_err(de::Error::custom)?;

        URI_IDENTIFIER.captures(&id).ok_or(de::Error::custom(
            "CredentialWC3 `id` validation failed: not URI id is passed",
        ))?;

        Ok(UriString(id))
    }
}

fn deserialize_issuer_id<'de, D>(deserialize: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let did: String = Deserialize::deserialize(deserialize).map_err(de::Error::custom)?;

    DID_IDENTIFIER.captures(&did).ok_or(de::Error::custom(
        "CredentialWC3 `issuer_id` validation failed: passed value is not DID",
    ))?;

    Ok(did)
}

fn deserialize_cred_def_id<'de, D>(deserialize: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let cred_def_id: String = Deserialize::deserialize(deserialize).map_err(de::Error::custom)?;

    CRED_DEF_IDENTIFIER.captures(&cred_def_id).ok_or(
        de::Error::custom("CredentialWC3 `credentialSchema` validation failed: passed value in `id` field is not cred_def id")
    )?;

    Ok(cred_def_id)
}

fn deserialize_schema_id<'de, D>(deserialize: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let cred_def_id: String = Deserialize::deserialize(deserialize).map_err(de::Error::custom)?;

    SCHEMA_IDENTIFIER.captures(&cred_def_id).ok_or(
        de::Error::custom("CredentialWC3 `credentialSchema` validation failed: passed value in `schema` field is not schema id")
    )?;

    Ok(cred_def_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CREDENTIAL_JSON: &str = r#"{"@context":["https://www.w3.org/2018/credentials/v1","https://andrewwhitehead.github.io/anoncreds-w3c-mapping/schema.json"],"type":["VerifiableCredential","AnonCredsCredential"],"issuer":"did:sov:3avoBCqDMFHFaKUHug9s8W","issuanceDate":"2023-11-02T09:16:11Z","credentialSchema":{"type":"AnonCredsDefinition","id":"did:sov:3avoBCqDMFHFaKUHug9s8W:3:CL:13:default","schema":"did:sov:3avoBCqDMFHFaKUHug9s8W:2:fabername:0.1.0"},"credentialSubject":{"name":"Alice Jones"},"proof":[{"type":"CLSignature2022","encoding":"auto","signature":"AAAgf9w5lZgz95dY38QeT0XWJfaGrY-CSr8uDo82jptOTmUBAQChFsSOFc2fDgVDKCSs2KydOLvZbNLFXyB2qlJGTadW1ZBcZ2WvocXcKufEWrbDbTr58ySW_Om1HUmVy-ojBvh4fwAf6XETclSPE8MfctSE09pwpy4ZYpOabSdY2G6mt4U4j5YdCiuCEBnmiG7JaxgdHqW4cG3kSxX1JXmy2rE8S0uHFxqT3H4d2otX0Om9r9e6btmeA0mv4fqfy9gd9y7cxAE4Xw7nQp5y29yhA93gpHmfV0FNcEzvgmFBGhF5DzMEYGM7Bmoxip3zmlXDpn4Z3Q-SQWKuO1SEa-YPEjc7OkQN8GjEweQAP6zUNoDD7FQtGdhXsJ0gq9tLz_Xw_x3BAgBLEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVC4ox7flXlg7AEkAhB-3AwFVCeRcF6Ii4FMqDfJ04FB_vm7NdqoWcfHARRmFzgUgMYoiB04kz5CDzzIVuowqkIbRgrlC7CKryuzuqNiCF3mfQkvJWfK3qXFNBKp2ZBVxYUo92l0LbE0cBAG3p_ZB26PO5XSS8Nw8U7uWJPkG0rQxreZcgEtw1WFNEzfpiTLN-W4xGneTYqot3VDFMXjmn0i37nPhdSSvfnSkk6PDJWi8H5Op-Zm03f5o6cWTW-vyL0p8x0dcvYGLPxDSLnbeP0Fc95KewHAtfWSn4gdQ7C2fzc8pZ9UV9iUIIDtdhDV306h-ZUhO641o2BTIa3fDQi7X590gIdhYhAUfIarHGzvXdff6OatwALnJqhAY2jbGopyrpgsTb9i7SOYwkztTJbHQ139Syv75uJ1rrGDzm_feXNGvM-ta8sr4sdD51vcOhVlFeDPD3R8iEqNbOGuj6-wJlmyF8CsEAQCBwfG7CL3X9rS6GkDsCmkw18__K8cSaePD4YWFDQHBqnzu6nOIy6RGa8U6tXgJbqZPGcBg9Db6W0iwkub9N36nadgqjPQkhuxt0U8H-p6NkPfbqqjZ3dDqNmDAuvr96_MItOSdPI_kRhyhJK9779Lg6iWyakimJ1QViqsefO-1uE-MQ0FXqs4ZcC-V187LXc2IHpJwk2d8Oo66oQij__Gcn4h0qQf0rC8TNy54_IQTSns080AK7Yfy12nMWBnWJN_7d4CToSpDAehyn2YEBPmweGuVnXu-DEjAbeEGFbsTYsCHygo_yzBpndRguYruDzn2yyt3RkyWISFYRZzEL1xPBQAgeOfJKl30pg6m-np2OmrRYp8Z_x3FqdwRHoWruiF0FlM"}]}"#;

    #[test]
    fn test_parse_credential_wc3() {
        let cred: CredentialWC3 = serde_json::from_str(CREDENTIAL_JSON).unwrap();
        let expected = HashSet::from([
            UriString("https://www.w3.org/2018/credentials/v1".to_string()),
            UriString(
                "https://andrewwhitehead.github.io/anoncreds-w3c-mapping/schema.json".to_string(),
            ),
        ]);

        assert_eq!(cred.context, expected)
    }
}
