use ffi_support::FfiStr;
use indy_utils::Qualifiable;

use super::error::{catch_error, ErrorCode};
use super::object::ObjectHandle;
use crate::services::{
    prover::new_credential_request,
    types::{CredentialRequest, CredentialRequestMetadata, DidValue},
};

#[no_mangle]
pub extern "C" fn credx_create_credential_request(
    prover_did: FfiStr,
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
        let prover_did = {
            let did = prover_did
                .as_opt_str()
                .ok_or_else(|| err_msg!("Missing prover DID"))?;
            DidValue::from_str(did)?
        };
        let master_secret_id = master_secret_id
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing master secret ID"))?;
        let (cred_req, cred_req_metadata) = new_credential_request(
            &prover_did,
            cred_def.load()?.cast_ref()?,
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

impl_indy_object!(CredentialRequest, "CredentialRequest");
impl_indy_object_from_json!(CredentialRequest, credx_credential_request_from_json);

impl_indy_object!(CredentialRequestMetadata, "CredentialRequestMetadata");
impl_indy_object_from_json!(
    CredentialRequestMetadata,
    credx_credential_request_metadata_from_json
);
