use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::string::ToString;

use crate::data_types::w3c::constants::ANONCREDS_CREDENTIAL_TYPES;
use crate::data_types::w3c::context::Contexts;
use crate::data_types::w3c::credential_attributes::CredentialSubject;
use crate::data_types::w3c::proof::{
    CredentialPresentationProofValue, CredentialSignatureProofValue, DataIntegrityProof,
};
use crate::data_types::w3c::VerifiableCredentialSpecVersion;
use crate::data_types::{
    issuer_id::IssuerId,
    w3c::{constants::W3C_CREDENTIAL_TYPE, one_or_many::OneOrMany, uri::URI},
};
use crate::Result;

/// AnonCreds W3C Credential definition
/// Note, that this definition is tied to AnonCreds W3C form
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct W3CCredential {
    #[serde(rename = "@context")]
    pub context: Contexts,
    #[serde(alias = "@type")]
    #[serde(rename = "type")]
    pub type_: Types,
    pub issuer: IssuerId,
    pub credential_subject: CredentialSubject,
    pub proof: OneOrMany<CredentialProof>,
    #[serde(alias = "@id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<URI>,

    // for VC 1.1 `issuance_date` property must be used
    // for VC 2.0 there is optional `valid_from` which we leave empty in case of anoncreds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuance_date: Option<IssuanceDate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<IssuanceDate>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Types(pub HashSet<String>);

pub type IssuanceDate = DateTime<Utc>;

pub type NonAnonCredsDataIntegrityProof = serde_json::Value;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CredentialProof {
    AnonCredsDataIntegrityProof(DataIntegrityProof),
    NonAnonCredsDataIntegrityProof(NonAnonCredsDataIntegrityProof),
}

impl W3CCredential {
    pub fn new(
        issuer: IssuerId,
        credential_subject: CredentialSubject,
        proof: DataIntegrityProof,
        version: Option<&VerifiableCredentialSpecVersion>,
    ) -> Self {
        let version = version.cloned().unwrap_or_default();
        let issuance_date = match version {
            VerifiableCredentialSpecVersion::V1_1 => Some(Utc::now()),
            VerifiableCredentialSpecVersion::V2_0 => None,
        };
        Self {
            context: Contexts::get(&version),
            type_: ANONCREDS_CREDENTIAL_TYPES.clone(),
            issuance_date,
            issuer,
            credential_subject,
            proof: OneOrMany::Many(vec![CredentialProof::AnonCredsDataIntegrityProof(proof)]),
            valid_from: None,
            id: None,
        }
    }

    pub(crate) fn derive(
        credential_subject: CredentialSubject,
        proof: DataIntegrityProof,
        credential: &W3CCredential,
    ) -> W3CCredential {
        W3CCredential {
            context: credential.context.clone(),
            type_: credential.type_.clone(),
            issuer: credential.issuer.clone(),
            id: credential.id.clone(),
            issuance_date: credential.issuance_date,
            valid_from: credential.valid_from,
            credential_subject,
            proof: OneOrMany::One(CredentialProof::AnonCredsDataIntegrityProof(proof)),
        }
    }

    pub fn version(&self) -> Result<VerifiableCredentialSpecVersion> {
        self.context.version()
    }

    pub fn get_credential_signature_proof(&self) -> Result<&CredentialSignatureProofValue> {
        self.get_data_integrity_proof()?
            .get_credential_signature_proof()
    }

    pub fn get_credential_presentation_proof(&self) -> Result<&CredentialPresentationProofValue> {
        self.get_data_integrity_proof()?
            .get_credential_presentation_proof()
    }

    pub(crate) fn get_data_integrity_proof(&self) -> Result<&DataIntegrityProof> {
        self.proof
            .find_value(&|proof: &CredentialProof| match proof {
                CredentialProof::AnonCredsDataIntegrityProof(proof) => Some(proof),
                _ => None,
            })
            .ok_or_else(|| err_msg!("Credential does not contain data integrity proof"))
    }

    pub(crate) fn get_mut_data_integrity_proof(&mut self) -> Result<&mut DataIntegrityProof> {
        self.proof
            .find_mut_value(&|proof: &mut CredentialProof| match proof {
                CredentialProof::AnonCredsDataIntegrityProof(proof) => Some(proof),
                _ => None,
            })
            .ok_or_else(|| err_msg!("Credential does not contain data integrity proof"))
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let version = self.context.version()?;

        self.context.validate()?;

        if !self.type_.0.contains(&W3C_CREDENTIAL_TYPE.to_string()) {
            return Err(err_msg!("Credential does not contain w3c credential type"));
        }

        if version == VerifiableCredentialSpecVersion::V1_1 && self.issuance_date.is_none() {
            return Err(err_msg!(
                "V1.1 Credential must include `issuanceDate` property"
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::W3CCredential;

    #[test]
    fn serde_w3c_credential() {
        let cred_json = include_str!("sample_credential.json");
        let cred1: W3CCredential =
            serde_json::from_str(&cred_json).expect("Error deserializing w3c credential");
        let out_json = serde_json::to_string(&cred1).expect("Error serializing w3c credential");
        let cred2: W3CCredential =
            serde_json::from_str(&out_json).expect("Error deserializing w3c credential");
        assert_eq!(cred1, cred2);
    }

    #[test]
    fn serde_w3c_credential_deny_unknown() {
        let cred_json = include_str!("sample_credential.json");
        let mut cred: serde_json::Value =
            serde_json::from_str(cred_json).expect("Error deserializing w3c credential");
        cred.as_object_mut()
            .unwrap()
            .insert("prop".into(), "val".into());
        let res = serde_json::from_value::<W3CCredential>(cred);
        assert!(res.is_err());
    }
}
