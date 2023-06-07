use anoncreds_core::data_types::schema::{SchemaId};
use anoncreds_core::data_types::issuer_id::{IssuerId};
use anoncreds_core::data_types::cred_def::{CredentialDefinitionId, SignatureType};
use anoncreds_core::data_types::link_secret::{LinkSecret as AnoncredsLinkSecret};
use anoncreds_core::data_types::cred_request::{CredentialRequest as AnoncredsCredentialRequest, CredentialRequestMetadata as AnoncredsCredentialRequestMetadata};
use anoncreds_core::data_types::nonce::{Nonce as AnoncredsNounce};
use anoncreds_core::data_types::cred_def::{CredentialDefinitionData as AnoncredsCredentialDefinitionData, CredentialDefinition as AnoncredsCredentialDefinition};
use anoncreds_core::data_types::cred_offer::{CredentialOffer as AnoncredsCredentialOffer};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt::Display;
use serde::{Deserialize, Serialize};
use serde_json::Result as SerdeResult;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum AnoncredsError {
    #[error("Conversion Error")]
    ConversionError,
    #[error("Something went wrong")] 
    SomethingWentWrong,
    #[error("Create Credential Error")]
    CreateCrentialRequestError,
}

pub enum ErrorCode {
    Success = 0,
    Error = 1,
}

#[derive(Clone)]
pub struct SchemaID {
    pub id: String
}

impl Into<SchemaId> for SchemaID {
    fn into(self) -> SchemaId {
        SchemaId::new_unchecked(self.id.clone())
    }
}

impl From<SchemaId> for SchemaID {
    fn from(acr: SchemaId) -> Self {
        SchemaID { id: acr.0 }
    }
}

#[derive(Clone)]
pub struct IssuerID {
    pub id: String
}

impl Into<IssuerId> for IssuerID {
    fn into(self) -> IssuerId {
        IssuerId::new_unchecked(self.id.clone())
    }
}

impl From<IssuerId> for IssuerID {
    fn from(acr: IssuerId) -> Self {
        IssuerID { id: acr.0 }
    }
}

#[derive(Clone)]
pub struct CredentialDefinitionID {
    pub id: String
}

impl Into<CredentialDefinitionId> for CredentialDefinitionID {
    fn into(self) -> CredentialDefinitionId {
        CredentialDefinitionId::new_unchecked(self.id.clone())
    }
}

impl From<CredentialDefinitionId> for CredentialDefinitionID {
    fn from(acr: CredentialDefinitionId) -> Self {
        CredentialDefinitionID { id: acr.0 }
    }
}

pub struct LinkSecret {
    secret: AnoncredsLinkSecret,
}

impl LinkSecret {
    pub fn new() -> Self {
        let secret = AnoncredsLinkSecret::new().unwrap();
        LinkSecret { secret: secret }
    }

    pub fn get_big_number(&self) -> String {
        let clone = self.clone();
        clone.into()
    }
}

impl From<AnoncredsLinkSecret> for LinkSecret {

    fn from(acr: AnoncredsLinkSecret) -> Self {
        return LinkSecret { secret: acr }
    }
}

impl TryFrom<&str> for LinkSecret {
    type Error = AnoncredsError;

    fn try_from(string: &str) -> Result<Self, Self::Error> {
        let acr = AnoncredsLinkSecret::try_from(string).map_err(|_| AnoncredsError::ConversionError)?;
        return Ok(LinkSecret { secret: acr })
    }
}

impl TryFrom<&LinkSecret> for AnoncredsLinkSecret {
    type Error = AnoncredsError;

    fn try_from(acr: &LinkSecret) -> Result<Self, Self::Error> {
        acr.secret.try_clone().map_err(|_| AnoncredsError::ConversionError)
    } 
}

impl Into<String> for LinkSecret {
    fn into(self) -> String {
        self.secret.0.to_hex().unwrap()
    } 
}

impl Clone for LinkSecret {
    fn clone(&self) -> Self {
        LinkSecret { secret: self.secret.try_clone().unwrap() }
    }
}

pub struct Nonce {
    anoncreds_nonce: AnoncredsNounce,
}

impl Nonce {
    pub fn new() -> Self {
        let nonce = AnoncredsNounce::new().unwrap();
        return Nonce { anoncreds_nonce: nonce }
    }
}

impl Into<String> for Nonce {
    fn into(self) -> String {
        self.anoncreds_nonce.as_ref().to_string()
    }
}

impl TryFrom<&str> for Nonce {
    type Error = AnoncredsError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let nonce = AnoncredsNounce::try_from(value).map_err(|_| AnoncredsError::ConversionError)?;
        return Ok(Nonce { anoncreds_nonce: nonce })
    }
}

impl Clone for Nonce {
    fn clone(&self) -> Self {
        let original = self.anoncreds_nonce.try_clone().unwrap();
        return Nonce { anoncreds_nonce: original }
    }
}

#[derive(Clone)]
pub struct CredentialDefinitionData {
    pub primary: String,
    pub revocation: Option<String>,
}

impl TryFrom<AnoncredsCredentialDefinitionData> for CredentialDefinitionData {
    type Error = AnoncredsError;

    fn try_from(acr: AnoncredsCredentialDefinitionData) -> Result<Self, Self::Error> {
        let primary = serde_json::to_string(&acr.primary).map_err(|_| AnoncredsError::ConversionError)?;

        let revocation = if let Some(rev_key) = &acr.revocation {
            Some(serde_json::to_string(rev_key).map_err(|_| AnoncredsError::ConversionError)?)
        } else {
            None
        };

        Ok(Self {
            primary,
            revocation,
        })
    }
}

impl TryInto<AnoncredsCredentialDefinitionData> for CredentialDefinitionData {
    type Error = AnoncredsError;

    fn try_into(self) -> Result<AnoncredsCredentialDefinitionData, Self::Error> {
        let primary: ursa::cl::CredentialPrimaryPublicKey = serde_json::from_str(&self.primary)
            .map_err(|_| AnoncredsError::ConversionError)?;
    
        let revocation = match &self.revocation {
            Some(rev_key_str) => Some(serde_json::from_str(rev_key_str)
                .map_err(|_| AnoncredsError::ConversionError)?),
            None => None,
        };
    
        Ok(AnoncredsCredentialDefinitionData {
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
    pub fn new(json_string: String) -> Result<Self, AnoncredsError> {
        let core_def: AnoncredsCredentialDefinition = serde_json::from_str(&json_string).map_err(|_| AnoncredsError::ConversionError)?;
        return CredentialDefinition::try_from(core_def)
    }

    pub fn get_schema_id(&self) -> SchemaID {
        self.schema_id.clone()
    }

    pub fn get_signature_type(&self) -> SignatureType {
        self.signature_type.clone()
    }

    pub fn get_tag(&self) -> String {
        self.tag.clone()
    }

    pub fn get_value(&self) -> CredentialDefinitionData {
        self.value.clone()
    }

    pub fn get_issuer_id(&self) -> IssuerID {
        self.issuer_id.clone()
    }
}

impl TryInto<AnoncredsCredentialDefinition> for CredentialDefinition {
    type Error = AnoncredsError;

    fn try_into(self) -> Result<AnoncredsCredentialDefinition, Self::Error> {
        let schema_id_core = self.schema_id.clone().into();
        let value_core = self.value.try_into()?;
        let issuer_id_core = self.issuer_id.clone().into();
        Ok(AnoncredsCredentialDefinition {
            schema_id: schema_id_core,
            signature_type: self.signature_type,
            tag: self.tag.clone(),
            value: value_core,
            issuer_id: issuer_id_core,
        })
    }
}

impl TryFrom<AnoncredsCredentialDefinition> for CredentialDefinition {
    type Error = AnoncredsError;

    fn try_from(acr: AnoncredsCredentialDefinition) -> Result<Self, Self::Error> {
        let schema_wrapper = SchemaID::from(acr.schema_id);
        let value_wrapper = CredentialDefinitionData::try_from(acr.value).map_err(|_| AnoncredsError::ConversionError)?;
        let issuer_wrapper = IssuerID::from(acr.issuer_id);

        Ok(
            CredentialDefinition {
                schema_id: schema_wrapper,
                signature_type: acr.signature_type,
                tag: acr.tag.clone(),
                value: value_wrapper,
                issuer_id: issuer_wrapper
            }
        )
    }
}

impl TryFrom<&CredentialDefinition> for AnoncredsCredentialDefinition {
    type Error = AnoncredsError;

    fn try_from(def: &CredentialDefinition) -> Result<AnoncredsCredentialDefinition, Self::Error> {
        let schema_id_core = def.schema_id.clone().into();
        let value_core = def.value.clone().try_into()?;
        let issuer_id_core = def.issuer_id.clone().into();
        Ok(AnoncredsCredentialDefinition {
            schema_id: schema_id_core,
            signature_type: def.signature_type,
            tag: def.tag.clone(),
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
    pub fn new(jsonString: String) -> Result<Self, AnoncredsError> {
        let core_def: AnoncredsCredentialOffer = serde_json::from_str(&jsonString).map_err(|_| AnoncredsError::ConversionError)?;
        return CredentialOffer::try_from(core_def)
    }

    pub fn get_schema_id(&self) -> SchemaID {
        self.schema_id.clone()
    }

    pub fn get_cred_def_id(&self) -> CredentialDefinitionID {
        self.cred_def_id.clone()
    }

    pub fn get_key_correctness_proof(&self) -> String {
        self.key_correctness_proof.clone()
    }

    pub fn get_nonce(&self) -> Arc<Nonce> {
        self.nonce.clone()
    }

    pub fn get_method_name(&self) -> Option<String> {
        self.method_name.clone()
    }
}

impl TryFrom<AnoncredsCredentialOffer> for CredentialOffer {
    type Error = AnoncredsError;

    fn try_from(acr: AnoncredsCredentialOffer) -> Result<Self, Self::Error> {
        let schema_id_wrapper = SchemaID::from(acr.schema_id);
        let cred_def_id_wrapper = CredentialDefinitionID::from(acr.cred_def_id);
        let correctness_proof_wrapper = serde_json::to_string(&acr.key_correctness_proof).map_err(|_| AnoncredsError::ConversionError)?;
        let nonce_wrapper = Arc::new(Nonce { anoncreds_nonce: acr.nonce });

        Ok(CredentialOffer {
            schema_id: schema_id_wrapper,
            cred_def_id: cred_def_id_wrapper,
            key_correctness_proof: correctness_proof_wrapper,
            nonce: nonce_wrapper,
            method_name: acr.method_name,
        })
    }
}

impl TryFrom<&CredentialOffer> for AnoncredsCredentialOffer {
    type Error = AnoncredsError;

    fn try_from(acr: &CredentialOffer) -> Result<Self, Self::Error> {
        let schema_id_core = acr.schema_id.clone().into();
        let cred_def_id_core = acr.cred_def_id.clone().into();
        let key_correctness_proof_core: ursa::cl::CredentialKeyCorrectnessProof = serde_json::from_str(&acr.key_correctness_proof)
            .map_err(|_| AnoncredsError::ConversionError)?; // Handle serde_json::Error here
        let nonce_unwrap = (*acr.nonce).clone();
        let nonce_core = nonce_unwrap.anoncreds_nonce;
        let method_name_core = acr.method_name.clone();

        Ok(AnoncredsCredentialOffer {
            schema_id: schema_id_core,
            cred_def_id: cred_def_id_core,
            key_correctness_proof: key_correctness_proof_core,
            nonce: nonce_core,
            method_name: method_name_core,
        })
    }
}

pub struct CredentialRequest {
    pub anoncreds_request: AnoncredsCredentialRequest
}

impl CredentialRequest {
    pub fn get_blinded_credential_secrets_json(&self) -> String {
        serde_json::to_string(&self.anoncreds_request.blinded_ms).unwrap()
    }

    pub fn get_blinded_credential_secrets_correctness_proof_json(&self) -> String {
        serde_json::to_string(&self.anoncreds_request.blinded_ms_correctness_proof).unwrap()
    }

    pub fn get_nonce(&self) -> Arc<Nonce> {
        return Arc::new(Nonce { anoncreds_nonce: self.anoncreds_request.nonce.try_clone().unwrap() })
    }

    pub fn get_json(&self) -> String {
        serde_json::to_string(&self.anoncreds_request).unwrap()
    }
}

pub struct CredentialRequestMetadata {
    pub link_secret_blinding_data: String,
    pub nonce: Arc<Nonce>,
    pub link_secret_name: String,
}

impl Into<AnoncredsCredentialRequestMetadata> for CredentialRequestMetadata {
    fn into(self) -> AnoncredsCredentialRequestMetadata {
        let link_secret_core: ursa::cl::CredentialSecretsBlindingFactors = serde_json::from_str(&self.link_secret_blinding_data).unwrap();
        let nonce_unwrap = (*self.nonce).clone();
        let nonce_core = nonce_unwrap.anoncreds_nonce;
        AnoncredsCredentialRequestMetadata {
            link_secret_blinding_data: link_secret_core,
            nonce: nonce_core,
            link_secret_name: self.link_secret_name
        }
    }
}

impl From<AnoncredsCredentialRequestMetadata> for CredentialRequestMetadata {
    fn from(acr: AnoncredsCredentialRequestMetadata) -> Self {
        let link_secret_blinding_data_str = serde_json::to_string(&acr.link_secret_blinding_data).expect("Failed to serialize link_secret_blinding_data");
        let nonce_core = Arc::new(Nonce { anoncreds_nonce: acr.nonce});
        return CredentialRequestMetadata {
            link_secret_blinding_data: link_secret_blinding_data_str,
            nonce: nonce_core,
            link_secret_name: acr.link_secret_name
        }
    }
}