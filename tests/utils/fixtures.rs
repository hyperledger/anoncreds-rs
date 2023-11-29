use serde_json::json;
use std::collections::HashMap;

use anoncreds::data_types::pres_request::{NonRevokedInterval, PresentationRequestPayload};
use anoncreds::w3c::types::MakeCredentialAttributes;
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
    verifier,
};

use super::storage::ProverWallet;

// Government credential related fixtures
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

pub const GVT_CRED: &str = "GVT";
pub const EMP_CRED: &str = "EMP";

// Create a `GVT` or `EMP` schema
pub fn create_schema(name: &str) -> (Schema, &str) {
    match name {
        GVT_CRED => (
            issuer::create_schema(
                GVT_SCHEMA_NAME,
                GVT_SCHEMA_VERSION,
                GVT_ISSUER_ID.try_into().unwrap(),
                GVT_SCHEMA_ATTRIBUTES[..].into(),
            )
            .expect("error while creating GVT schema"),
            GVT_SCHEMA_ID,
        ),
        EMP_CRED => (
            issuer::create_schema(
                EMP_SCHEMA_NAME,
                EMP_SCHEMA_VERSION,
                EMP_ISSUER_ID.try_into().unwrap(),
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
                GVT_SCHEMA_ID.try_into().unwrap(),
                schema,
                GVT_ISSUER_ID.try_into().unwrap(),
                GVT_CRED_DEF_TAG,
                anoncreds::types::SignatureType::CL,
                anoncreds::types::CredentialDefinitionConfig { support_revocation },
            )
            .expect("error while creating GVT cred def"),
            GVT_CRED_DEF_ID,
        ),
        EMP_SCHEMA_NAME => (
            issuer::create_credential_definition(
                EMP_SCHEMA_ID.try_into().unwrap(),
                schema,
                EMP_ISSUER_ID.try_into().unwrap(),
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
                GVT_CRED_DEF_ID.try_into().unwrap(),
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
                EMP_CRED_DEF_ID.try_into().unwrap(),
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
    cred_def: &CredentialDefinition,
    rev_reg_def: &RevocationRegistryDefinition,
    rev_reg_priv: &RevocationRegistryDefinitionPrivate,
    time: Option<u64>,
    issuance_by_default: bool,
) -> RevocationStatusList {
    match rev_reg_def.tag.as_str() {
        GVT_REV_REG_TAG => issuer::create_revocation_status_list(
            cred_def,
            GVT_REV_REG_DEF_ID.try_into().unwrap(),
            rev_reg_def,
            rev_reg_priv,
            issuance_by_default,
            time,
        )
        .expect("Error while creating GVT rev status list"),
        EMP_REV_REG_TAG => issuer::create_revocation_status_list(
            cred_def,
            EMP_REV_REG_DEF_ID.try_into().unwrap(),
            rev_reg_def,
            rev_reg_priv,
            issuance_by_default,
            time,
        )
        .expect("Error while creating EMP rev status list"),
        unsupported => panic!("Unsupported rev reg def. {unsupported}"),
    }
}

pub fn credential_values(name: &str) -> MakeCredentialValues {
    match name {
        GVT_CRED => {
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
        EMP_CRED => {
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

pub fn raw_credential_values(name: &str) -> MakeCredentialAttributes {
    match name {
        GVT_CRED => {
            let mut gvt_cred_values = MakeCredentialAttributes::default();
            gvt_cred_values.add("sex", "male");
            gvt_cred_values.add("name", "Alex");
            gvt_cred_values.add("height", "175");
            gvt_cred_values.add("age", "28");
            gvt_cred_values
        }
        EMP_CRED => {
            let mut emp_cred_values = MakeCredentialAttributes::default();
            emp_cred_values.add("name", "John");
            emp_cred_values.add("role", "Developer");
            emp_cred_values.add("department", "IT");
            emp_cred_values
        }
        unsupported => panic!("Unsupported credential values. {unsupported}"),
    }
}
