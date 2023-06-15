use crate::types::error::AnoncredsError;
use crate::types::cred_def::{CredentialDefinition, CredentialDefinitionPrivate, CredentialKeyCorrectnessProof};
use crate::types::cred_offer::{CredentialOffer};
use crate::types::credential::{Credential};
use crate::CredentialRequest;
use crate::types::rev_status_list::RevocationStatusList;
use crate::types::rev_reg_def::{RevocationRegistryDefinition, RevocationRegistryDefinitionPrivate};

use anoncreds_core::types::CredentialRevocationConfig as AnoncredsCredentialRevocationConfig;
use anoncreds_core::data_types::rev_reg::RevocationRegistryId;
use anoncreds_core::data_types::rev_reg_def::RegistryType;
use anoncreds_core::data_types::schema::Schema;
use anoncreds_core::issuer::{create_credential, create_credential_definition, create_credential_offer, create_revocation_registry_def, create_revocation_status_list, create_schema, update_revocation_status_list, update_revocation_status_list_timestamp_only};
use anoncreds_core::tails::{TailsFileWriter, TailsFileReader};
use anoncreds_core::types::{AttributeNames, CredentialDefinitionConfig, CredentialValues, SignatureType};
use std::collections::BTreeSet;
use std::iter::FromIterator;
use std::sync::Arc;

pub struct IssuerCreateCredentialDefinitionReturn {
    pub credential_definition: Arc<CredentialDefinition>,
    pub credential_definition_private: Arc<CredentialDefinitionPrivate>,
    pub credential_key_correctness_proof: Arc<CredentialKeyCorrectnessProof>
}

pub struct IssuerCreateRevocationRegistryDefReturn {
    pub reg_def: Arc<RevocationRegistryDefinition>,
    pub reg_def_private: Arc<RevocationRegistryDefinitionPrivate>
}

pub struct CredentialRevocationConfig {
    pub reg_def: Arc<RevocationRegistryDefinition>,
    pub reg_def_private: Arc<RevocationRegistryDefinitionPrivate>,
    pub registry_idx: u32
}

impl CredentialRevocationConfig {
    pub fn to_cred_rev_config<'a>(&'a self) -> AnoncredsCredentialRevocationConfig<'a> {
        AnoncredsCredentialRevocationConfig {
            reg_def: &(*self.reg_def).core,
            reg_def_private: &(*self.reg_def_private).core,
            registry_idx: self.registry_idx,
            tails_reader: TailsFileReader::new_tails_reader("")
        }
    }
}

// ///
// /// [Issuer] functionalities wrapper
// ///
pub struct Issuer;

// ///
// /// [Issuer] functionalities wrapper
// ///
impl Issuer {

    /// Create a new instance of [Issuer]
    pub fn new() -> Self {
        Self {}
    }

    pub fn create_schema(
        &self,
        schema_name: String,
        schema_version: String,
        issuer_id: String,
        attr_names: Vec<String>
    ) -> Result<Schema, AnoncredsError> {
        return create_schema(&*schema_name, &*schema_version, issuer_id, AttributeNames::from(attr_names)).map_err(|err| {
            AnoncredsError::CreateSchemaError(format!("Error: {}", err))
        })
    }

    pub fn create_credential_definition(
        &self,
        schema_id: String,
        schema: Schema,
        issuer_id: String,
        tag: String,
        signature_type: SignatureType,
        config: CredentialDefinitionConfig,
    ) -> Result<IssuerCreateCredentialDefinitionReturn, AnoncredsError> {
        let (cred_def, cred_def_priv, key_correctness_proof) = create_credential_definition(schema_id, &schema, issuer_id, &*tag, signature_type, config).map_err(|err| {
            AnoncredsError::CreateCredentialDefinition(format!("Error: {}", err))
        })?;
        return Ok(IssuerCreateCredentialDefinitionReturn {
            credential_definition: Arc::new(CredentialDefinition { core: cred_def }),
            credential_definition_private: Arc::new(CredentialDefinitionPrivate { core: cred_def_priv }),
            credential_key_correctness_proof: Arc::new(CredentialKeyCorrectnessProof { core: key_correctness_proof })
        });
    }

    pub fn create_revocation_registry_def(
        &self,
        cred_def: Arc<CredentialDefinition>,
        cred_def_id: String,
        issuer_id: String,
        tag: String,
        rev_reg_type: RegistryType,
        max_cred_num: u32
    ) -> Result<IssuerCreateRevocationRegistryDefReturn, AnoncredsError> {
        let mut tw = TailsFileWriter::new(None);
        let (rev_reg_def, rev_reg_def_priv) = create_revocation_registry_def(&(*cred_def).core, cred_def_id, issuer_id, &*tag, rev_reg_type, max_cred_num, &mut tw).map_err(|err| {
            AnoncredsError::CreateRevocationRegistryDef(format!("Error: {}", err))
        })?;
        return Ok(IssuerCreateRevocationRegistryDefReturn {
            reg_def: Arc::new(RevocationRegistryDefinition { core: rev_reg_def }),
            reg_def_private: Arc::new(RevocationRegistryDefinitionPrivate { core: rev_reg_def_priv })
        });
    }

    pub fn create_revocation_status_list(
        &self,
        rev_reg_def_id: String,
        rev_reg_def: Arc<RevocationRegistryDefinition>,
        issuer_id: String,
        timestamp: Option<u64>,
        issuance_by_default: bool
    ) -> Result<Arc<RevocationStatusList>, AnoncredsError> {
        let rev_status_list = create_revocation_status_list(rev_reg_def_id, &(*rev_reg_def).core, issuer_id, timestamp, issuance_by_default).map_err(|err| {
            AnoncredsError::CreateRevocationStatusList(format!("Error: {}", err))
        })?;

        return Ok(Arc::new(RevocationStatusList { core: rev_status_list }));
    }

    pub fn update_revocation_status_list_timestamp_only(
        &self,
        timestamp: u64,
        current_list: Arc<RevocationStatusList>
    ) -> Arc<RevocationStatusList> {
        let updated_rev_status_list = update_revocation_status_list_timestamp_only(timestamp, &(*current_list).core);
        return Arc::new(RevocationStatusList { core: updated_rev_status_list });
    }

    pub fn update_revocation_status_list(
        &self,
        timestamp: Option<u64>,
        issued: Option<Vec<u32>>,
        revoked: Option<Vec<u32>>,
        rev_reg_def: Arc<RevocationRegistryDefinition>,
        current_list: Arc<RevocationStatusList>
    ) -> Result<Arc<RevocationStatusList>, AnoncredsError> {
        let _issued: Option<BTreeSet<u32>>;
        if issued.is_some() {
            _issued = Some(BTreeSet::from_iter(issued.unwrap()));
        } else {
            _issued = None
        }
        let _revoked: Option<BTreeSet<u32>>;
        if revoked.is_some() {
            _revoked = Some(BTreeSet::from_iter(revoked.unwrap()));
        } else {
            _revoked = None
        }
        let updated_rev_status_list = update_revocation_status_list(
            timestamp, 
            _issued, 
            _revoked, 
            &(*rev_reg_def).core, 
            &(*current_list).core
        ).map_err(|err| {
            AnoncredsError::UpdateRevocationStatusList(format!("Error: {}", err))
        })?;
        return Ok(Arc::new(RevocationStatusList { core: updated_rev_status_list }));
    }

    pub fn create_credential_offer(
        &self,
        schema_id: String,
        cred_def_id: String,
        correctness_proof: Arc<CredentialKeyCorrectnessProof>
    ) -> Result<Arc<CredentialOffer>, AnoncredsError> {
        let credential_offer = create_credential_offer(schema_id, cred_def_id, &(*correctness_proof).core).map_err(|err| {
            AnoncredsError::CreateCredentialOffer(format!("Error: {}", err))
        })?;
        return Ok(Arc::new(CredentialOffer { core: credential_offer }));
    }

    pub fn create_credential(
        &self,
        cred_def: Arc<CredentialDefinition>,
        cred_def_private: Arc<CredentialDefinitionPrivate>,
        cred_offer: Arc<CredentialOffer>,
        cred_request: Arc<CredentialRequest>,
        cred_values: CredentialValues,
        rev_reg_id: Option<RevocationRegistryId>,
        rev_status_list: Option<Arc<RevocationStatusList>>,
        revocation_config: Option<CredentialRevocationConfig>
    ) -> Result<Arc<Credential>, AnoncredsError> {
        let credential = create_credential(
            &(*cred_def).core,
            &(*cred_def_private).core,
            &(*cred_offer).core,
            &(*cred_request).core,
            cred_values,
            rev_reg_id,
            rev_status_list.as_ref().map(|list| &(*list).core),
            revocation_config.as_ref().map(|config| config.to_cred_rev_config()),
        ).map_err(|err| {
            AnoncredsError::CreateCredential(format!("Error: {}", err))
        })?;
        return Ok(Arc::new(Credential { core: credential }));
    }
}
