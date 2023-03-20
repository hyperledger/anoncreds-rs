use std::collections::HashMap;

use anoncreds::{
    data_types::{
        cred_def::{CredentialDefinition, CredentialDefinitionId},
        schema::{Schema, SchemaId},
    },
    issuer, prover,
    tails::TailsFileWriter,
    types::{
        CredentialDefinitionPrivate, CredentialKeyCorrectnessProof, CredentialRevocationState,
        MakeCredentialValues, PresentCredentials, Presentation, PresentationRequest,
        RevocationRegistryDefinition, RevocationRegistryDefinitionPrivate, RevocationStatusList,
    },
};

use super::storage::ProverWallet;

// Goverment credential related fixtures
pub const GVT_SCHEMA_NAME: &str = "Government Schema";
pub const GVT_SCHEMA_ID: &str = "schema:government";
pub const GVT_SCHEMA_VERSION: &str = "1.0";
pub const GVT_SCHEMA_ATTRIBUTES: &[&str; 4] = &["name", "age", "sex", "height"];

pub const GVT_CRED_DEF_ID: &str = "creddef:government";
pub const GVT_CRED_DEF_TAG: &str = "govermenttag";

pub const GVT_ISSUER_ID: &str = "issuer:id/path=bar";

pub const GVT_REV_REG_DEF_ID: &str = "revreg:government/id";
pub const GVT_REV_REG_TAG: &str = "revreggovermenttag";
pub const GVT_REV_IDX: u32 = 9;
pub const GVT_REV_MAX_CRED_NUM: u32 = 10;

// Employee credential related fixtures
pub const EMP_SCHEMA_NAME: &str = "Employee Schema";
pub const EMP_SCHEMA_ID: &str = "schema:employeebadge";
pub const EMP_SCHEMA_VERSION: &str = "1.0";
pub const EMP_SCHEMA_ATTRIBUTES: &[&str; 3] = &["name", "role", "department"];

pub const EMP_CRED_DEF_ID: &str = "creddef:employee";
pub const EMP_CRED_DEF_TAG: &str = "employeetag";

pub const EMP_ISSUER_ID: &str = "employer:id/path=bar";

pub const EMP_REV_REG_DEF_ID: &str = "revreg:employee/id";
pub const EMP_REV_REG_TAG: &str = "revregemployeetag";
pub const EMP_REV_IDX: u32 = 9;
pub const EMP_REV_MAX_CRED_NUM: u32 = 10;

// Create a `GVT` or `EMP` schema
pub fn create_schema(name: &str) -> (Schema, &str) {
    match name {
        "GVT" => (
            issuer::create_schema(
                GVT_SCHEMA_NAME,
                GVT_SCHEMA_VERSION,
                GVT_ISSUER_ID,
                GVT_SCHEMA_ATTRIBUTES[..].into(),
            )
            .expect("error while creating GVT schema"),
            GVT_SCHEMA_ID,
        ),
        "EMP" => (
            issuer::create_schema(
                EMP_SCHEMA_NAME,
                EMP_SCHEMA_VERSION,
                EMP_ISSUER_ID,
                EMP_SCHEMA_ATTRIBUTES[..].into(),
            )
            .expect("error while creating EMP schema"),
            EMP_SCHEMA_ID,
        ),
        unsupported => panic!("Unsupported schema. {unsupported}"),
    }
}

pub fn create_cred_def(
    schema: &Schema,
    support_revocation: bool,
) -> (
    (
        CredentialDefinition,
        CredentialDefinitionPrivate,
        CredentialKeyCorrectnessProof,
    ),
    &str,
) {
    match schema.name.as_str() {
        GVT_SCHEMA_NAME => (
            issuer::create_credential_definition(
                GVT_SCHEMA_ID,
                schema,
                GVT_ISSUER_ID,
                GVT_CRED_DEF_TAG,
                anoncreds::types::SignatureType::CL,
                anoncreds::types::CredentialDefinitionConfig { support_revocation },
            )
            .expect("error while creating GVT cred def"),
            GVT_CRED_DEF_ID,
        ),
        EMP_SCHEMA_NAME => (
            issuer::create_credential_definition(
                EMP_SCHEMA_ID,
                schema,
                EMP_ISSUER_ID,
                EMP_CRED_DEF_TAG,
                anoncreds::types::SignatureType::CL,
                anoncreds::types::CredentialDefinitionConfig { support_revocation },
            )
            .expect("error while creating EMP cred def"),
            EMP_CRED_DEF_ID,
        ),
        unsupported => panic!("Unsupported schema name. {unsupported}"),
    }
}

pub fn create_rev_reg_def<'a>(
    cred_def: &CredentialDefinition,
    tf: &mut TailsFileWriter,
) -> (
    (
        RevocationRegistryDefinition,
        RevocationRegistryDefinitionPrivate,
    ),
    &'a str,
) {
    match cred_def.tag.as_str() {
        GVT_CRED_DEF_TAG => (
            issuer::create_revocation_registry_def(
                cred_def,
                GVT_CRED_DEF_ID,
                GVT_ISSUER_ID,
                GVT_REV_REG_TAG,
                anoncreds::types::RegistryType::CL_ACCUM,
                GVT_REV_MAX_CRED_NUM,
                tf,
            )
            .expect("Error while creating GVT rev reg"),
            GVT_REV_REG_DEF_ID,
        ),
        EMP_CRED_DEF_TAG => (
            issuer::create_revocation_registry_def(
                cred_def,
                EMP_CRED_DEF_ID,
                EMP_ISSUER_ID,
                EMP_REV_REG_TAG,
                anoncreds::types::RegistryType::CL_ACCUM,
                EMP_REV_MAX_CRED_NUM,
                tf,
            )
            .expect("Error while creating EMP rev reg"),
            EMP_REV_REG_DEF_ID,
        ),
        unsupported => panic!("Unsupported cred def. {unsupported}"),
    }
}

pub fn create_revocation_status_list(
    rev_reg_def: &RevocationRegistryDefinition,
    time: Option<u64>,
    issuance_by_default: bool,
) -> RevocationStatusList {
    match rev_reg_def.tag.as_str() {
        GVT_REV_REG_TAG => issuer::create_revocation_status_list(
            GVT_REV_REG_DEF_ID,
            rev_reg_def,
            GVT_ISSUER_ID,
            time,
            issuance_by_default,
        )
        .expect("Error while creating GVT rev status list"),
        EMP_REV_REG_TAG => issuer::create_revocation_status_list(
            EMP_REV_REG_DEF_ID,
            rev_reg_def,
            EMP_ISSUER_ID,
            time,
            issuance_by_default,
        )
        .expect("Error while creating EMP rev status list"),
        unsupported => panic!("Unsupported rev reg def. {unsupported}"),
    }
}

pub fn create_presentation(
    schemas: &HashMap<&SchemaId, &Schema>,
    cred_defs: &HashMap<&CredentialDefinitionId, &CredentialDefinition>,
    pres_request: &PresentationRequest,
    prover_wallet: &ProverWallet,
    rev_state_timestamp: Option<u64>,
    rev_state: Option<&CredentialRevocationState>,
) -> Presentation {
    let mut present = PresentCredentials::default();
    {
        // Here we add credential with the timestamp of which the rev_state is updated to,
        // also the rev_reg has to be provided for such a time.
        // TODO: this timestamp is not verified by the `NonRevokedInterval`?
        let mut cred1 = present.add_credential(
            &prover_wallet.credentials[0],
            rev_state_timestamp,
            rev_state,
        );
        cred1.add_requested_attribute("attr1_referent", true);
        cred1.add_requested_attribute("attr2_referent", false);
        cred1.add_requested_attribute("attr4_referent", true);
        cred1.add_requested_predicate("predicate1_referent");
    }

    let mut self_attested = HashMap::new();
    let self_attested_phone = "8-800-300";
    self_attested.insert(
        "attr3_referent".to_string(),
        self_attested_phone.to_string(),
    );

    prover::create_presentation(
        pres_request,
        present,
        Some(self_attested),
        &prover_wallet.link_secret,
        schemas,
        cred_defs,
    )
    .expect("Error creating presentation")
}

pub fn credential_values(name: &str) -> MakeCredentialValues {
    match name {
        "GVT" => {
            let mut gvt_cred_values = MakeCredentialValues::default();
            gvt_cred_values
                .add_raw("sex", "male")
                .expect("Error encoding attribute");
            gvt_cred_values
                .add_raw("name", "Alex")
                .expect("Error encoding attribute");
            gvt_cred_values
                .add_raw("height", "175")
                .expect("Error encoding attribute");
            gvt_cred_values
                .add_raw("age", "28")
                .expect("Error encoding attribute");
            gvt_cred_values
        }
        "EMP" => {
            let mut emp_cred_values = MakeCredentialValues::default();
            emp_cred_values
                .add_raw("name", "John")
                .expect("Error encoding attribute");
            emp_cred_values
                .add_raw("role", "Developer")
                .expect("Error encoding attribute");
            emp_cred_values
                .add_raw("department", "IT")
                .expect("Error encoding attribute");
            emp_cred_values
        }
        unsupported => panic!("Unsupported credential values. {unsupported}"),
    }
}
