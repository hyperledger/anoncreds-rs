use std::str::FromStr;

use ffi_support::FfiStr;

use super::error::{catch_error, ErrorCode};
use super::object::ObjectHandle;
use crate::data_types::anoncreds::cred_def::CredentialDefinition;
use crate::services::{
    issuer::create_credential_definition,
    types::{
        CredentialDefinitionConfig, CredentialDefinitionPrivate,
        CredentialKeyCorrectnessProof as KeyCorrectnessProof, SignatureType,
    },
};

#[no_mangle]
pub extern "C" fn anoncreds_create_credential_definition(
    schema_id: FfiStr,
    schema: ObjectHandle,
    tag: FfiStr,
    issuer_id: FfiStr,
    signature_type: FfiStr,
    support_revocation: i8,
    cred_def_p: *mut ObjectHandle,
    cred_def_pvt_p: *mut ObjectHandle,
    key_proof_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(cred_def_p);
        check_useful_c_ptr!(cred_def_pvt_p);
        check_useful_c_ptr!(key_proof_p);
        let tag = tag.as_opt_str().ok_or_else(|| err_msg!("Missing tag"))?;
        let schema_id = schema_id
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing schema id"))?;
        let signature_type = {
            let stype = signature_type
                .as_opt_str()
                .ok_or_else(|| err_msg!("Missing signature type"))?;
            SignatureType::from_str(stype).map_err(err_map!(Input))?
        };
        let issuer_id = issuer_id
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing issuer id"))?;
        let (cred_def, cred_def_pvt, key_proof) = create_credential_definition(
            schema_id,
            schema.load()?.cast_ref()?,
            issuer_id,
            tag,
            signature_type,
            CredentialDefinitionConfig {
                support_revocation: support_revocation != 0,
            },
        )?;
        let cred_def = ObjectHandle::create(cred_def)?;
        let cred_def_pvt = ObjectHandle::create(cred_def_pvt)?;
        let key_proof = ObjectHandle::create(key_proof)?;
        unsafe {
            *cred_def_p = cred_def;
            *cred_def_pvt_p = cred_def_pvt;
            *key_proof_p = key_proof;
        }
        Ok(())
    })
}

impl_anoncreds_object!(CredentialDefinition, "CredentialDefinition");
impl_anoncreds_object_from_json!(
    CredentialDefinition,
    anoncreds_credential_definition_from_json
);

impl_anoncreds_object!(CredentialDefinitionPrivate, "CredentialDefinitionPrivate");
impl_anoncreds_object_from_json!(
    CredentialDefinitionPrivate,
    anoncreds_credential_definition_private_from_json
);

impl_anoncreds_object!(KeyCorrectnessProof, "KeyCorrectnessProof");
impl_anoncreds_object_from_json!(
    KeyCorrectnessProof,
    anoncreds_key_correctness_proof_from_json
);
