use std::ffi::c_char;

use ffi_support::{rust_string_to_c, FfiStr};

use super::error::{catch_error, ErrorCode};
use super::object::ObjectHandle;
use crate::data_types::anoncreds::schema::SchemaId;
use crate::services::{
    issuer::create_credential_definition,
    types::{
        CredentialDefinition, CredentialDefinitionConfig, CredentialDefinitionPrivate,
        CredentialKeyCorrectnessProof as KeyCorrectnessProof, SignatureType,
    },
};

#[no_mangle]
pub extern "C" fn anoncreds_create_credential_definition(
    schema_id: FfiStr,
    schema: ObjectHandle,
    tag: FfiStr,
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
        let schema_id = {
            let schema_id = schema_id
                .as_opt_str()
                .ok_or_else(|| err_msg!("Missing schema id"))?;
            SchemaId::new(schema_id)?
        };
        let signature_type = {
            let stype = signature_type
                .as_opt_str()
                .ok_or_else(|| err_msg!("Missing signature type"))?;
            SignatureType::from_str(stype).map_err(err_map!(Input))?
        };
        let (cred_def, cred_def_pvt, key_proof) = create_credential_definition(
            schema_id.to_owned(),
            schema.load()?.cast_ref()?,
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

#[no_mangle]
pub extern "C" fn anoncreds_credential_definition_get_attribute(
    handle: ObjectHandle,
    name: FfiStr,
    result_p: *mut *const c_char,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(result_p);
        let cred_def = handle.load()?;
        let cred_def = cred_def.cast_ref::<CredentialDefinition>()?;
        let val = match name.as_opt_str().unwrap_or_default() {
            "schema_id" => match cred_def {
                CredentialDefinition::CredentialDefinitionV1(cred_def) => {
                    cred_def.schema_id.to_owned()
                }
            },
            s => return Err(err_msg!("Unsupported attribute: {}", s)),
        };
        unsafe { *result_p = rust_string_to_c(val) };
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
