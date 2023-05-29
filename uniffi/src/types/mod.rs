use anoncreds_core::data_types::schema::{SchemaId};
use anoncreds_core::data_types::issuer_id::{IssuerId};
use anoncreds_core::data_types::cred_def::{CredentialDefinitionId, SignatureType};
use anoncreds_core::data_types::link_secret::{LinkSecret};
use std::convert::TryFrom;
use serde::{Deserialize, Serialize};
use serde_json::Result;
use std::sync::Arc;

#[derive(Debug)]
pub enum AnoncredsError {
    ConversionError, 
    SomethingWentWrong,
}

pub enum ErrorCode {
    Success = 0,
    Error = 1,
}

pub struct SchemaID {
    pub id: String
}

impl SchemaID {
    fn to_core(&self) -> SchemaId {
        SchemaId::new_unchecked(self.id.clone())
    }
}

pub struct IssuerID {
    pub id: String
}

impl IssuerID {
    fn to_core(&self) -> IssuerId {
        IssuerId::new_unchecked(self.id.clone())
    }
}

pub struct CredentialDefinitionID {
    pub id: String
}

impl CredentialDefinitionID {
    fn to_core(&self) -> CredentialDefinitionId {
        CredentialDefinitionId::new_unchecked(self.id.clone())
    }
}

pub struct SecretLink {
    secret: LinkSecret,
}

impl SecretLink {
    pub fn new() -> Self {
        let secret = LinkSecret::new().unwrap();
        SecretLink { secret: secret }
    }

    pub fn to_core(&self) -> LinkSecret {
        self.secret.try_clone().unwrap()
    }

    pub fn get_big_number(&self) -> String {
        self.secret.0.to_hex().unwrap()
    }
}

pub struct Nonce {
    nonce: anoncreds_core::data_types::nonce::Nonce,
}

impl Nonce {
    pub fn new() -> Self {
        let nonce = anoncreds_core::data_types::nonce::Nonce::new().unwrap();
        return Nonce { nonce: nonce }
    }
}

pub struct CredentialDefinitionData {
    pub primary: String,
    pub revocation: Option<String>,
}

impl CredentialDefinitionData {
    fn from_core(ursa_data: &anoncreds_core::data_types::cred_def::CredentialDefinitionData) -> Result<Self> {
        let primary = serde_json::to_string(&ursa_data.primary)?;

        let revocation = if let Some(rev_key) = &ursa_data.revocation {
            Some(serde_json::to_string(rev_key)?)
        } else {
            None
        };

        Ok(Self {
            primary,
            revocation,
        })
    }

    fn to_core(&self) -> Result<anoncreds_core::data_types::cred_def::CredentialDefinitionData> {
        let primary: ursa::cl::CredentialPrimaryPublicKey = serde_json::from_str(&self.primary)?;

        let revocation = if let Some(rev_key_str) = &self.revocation {
            Some(serde_json::from_str(rev_key_str)?)
        } else {
            None
        };

        Ok(anoncreds_core::data_types::cred_def::CredentialDefinitionData {
            primary,
            revocation,
        })
    }
}

pub struct CredentialDefinition {
    pub schema_id: SchemaID,
    pub signature_type: SignatureType,
    pub tag: String,
    pub value: CredentialDefinitionData,
    pub issuer_id: IssuerID,
}

impl CredentialDefinition {
    pub fn to_core(&self) -> Result<anoncreds_core::data_types::cred_def::CredentialDefinition> {
        let schema_id_core = self.schema_id.to_core();
        let value_core = self.value.to_core()?;
        let issuer_id_core = self.issuer_id.to_core();
        Ok(anoncreds_core::data_types::cred_def::CredentialDefinition {
            schema_id: schema_id_core,
            signature_type: self.signature_type,
            tag: self.tag.clone(),
            value: value_core,
            issuer_id: issuer_id_core,
        })
    }
}

pub struct CredentialOffer {
    pub schema_id: SchemaID,
    pub cred_def_id: CredentialDefinitionID,
    pub key_correctness_proof: String,
    pub nonce: Arc<Nonce>,
    pub method_name: Option<String>,
}

impl CredentialOffer {
    pub fn to_core(&self) -> std::result::Result<anoncreds_core::data_types::cred_offer::CredentialOffer, AnoncredsError> {
        let schema_id_core = self.schema_id.to_core();
        let cred_def_id_core = self.cred_def_id.to_core();
        let key_correctness_proof_core: ursa::cl::CredentialKeyCorrectnessProof = serde_json::from_str(&self.key_correctness_proof)
            .map_err(|_| AnoncredsError::ConversionError)?; // Handle serde_json::Error here
        let nonce_core = anoncreds_core::data_types::nonce::Nonce::new().unwrap();
        let method_name_core = self.method_name.clone();

        Ok(anoncreds_core::data_types::cred_offer::CredentialOffer {
            schema_id: schema_id_core,
            cred_def_id: cred_def_id_core,
            key_correctness_proof: key_correctness_proof_core,
            nonce: nonce_core,
            method_name: method_name_core,
        })
    }

    // fn from_core(ursa_data: &anoncreds_core::data_types::cred_offer::CredentialOffer) -> Result<Self> {
    //     let schema_id = SchemaID { id: ursa_data.schema_id.to_string() };
    //     let cred_def_id = CredentialDefinitionID { id: ursa_data.cred_def_id.to_string() };
    //     let key_correctness_proof = serde_json::to_string(&ursa_data.key_correctness_proof)?;
    //     let nonce = Nonce {
    //         ursa_data.nonce.strval.clone(),
    //         ursa_data.nonce.native.to_string(),
    //     };
    //     let method_name = ursa_data.method_name.clone();

    //     Ok(Self {
    //         schema_id,
    //         cred_def_id,
    //         key_correctness_proof,
    //         nonce,
    //         method_name,
    //     })
    // }
}