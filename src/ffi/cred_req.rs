use ffi_support::FfiStr;

use super::error::{catch_error, ErrorCode};
use super::object::ObjectHandle;
use crate::data_types::cred_def::CredentialDefinition;
use crate::services::{
    prover::create_credential_request,
    types::{CredentialRequest, CredentialRequestMetadata},
};

#[no_mangle]
pub extern "C" fn anoncreds_create_credential_request(
    entropy: FfiStr,
    cred_def: ObjectHandle,
    master_secret: ObjectHandle,
    master_secret_id: FfiStr,
    cred_offer: ObjectHandle,
    cred_req_p: *mut ObjectHandle,
    cred_req_meta_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(cred_req_p);
        check_useful_c_ptr!(cred_req_meta_p);
        let master_secret_id = master_secret_id
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing master secret ID"))?;
        let entropy = entropy
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing entropy"))?;

        let cred_def = cred_def.load()?;
        let cred_def: &CredentialDefinition = cred_def.cast_ref()?;

        let (cred_req, cred_req_metadata) = create_credential_request(
            entropy,
            cred_def,
            master_secret.load()?.cast_ref()?,
            master_secret_id,
            cred_offer.load()?.cast_ref()?,
        )?;
        let cred_req = ObjectHandle::create(cred_req)?;
        let cred_req_metadata = ObjectHandle::create(cred_req_metadata)?;
        unsafe {
            *cred_req_p = cred_req;
            *cred_req_meta_p = cred_req_metadata;
        };
        Ok(())
    })
}

impl_anoncreds_object!(CredentialRequest, "CredentialRequest");
impl_anoncreds_object_from_json!(CredentialRequest, anoncreds_credential_request_from_json);

impl_anoncreds_object!(CredentialRequestMetadata, "CredentialRequestMetadata");
impl_anoncreds_object_from_json!(
    CredentialRequestMetadata,
    anoncreds_credential_request_metadata_from_json
);
