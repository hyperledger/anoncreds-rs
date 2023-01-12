use ffi_support::FfiStr;

use super::error::{catch_error, ErrorCode};
use super::object::ObjectHandle;
use crate::data_types::anoncreds::cred_def::CredentialDefinition;
use crate::services::{
    prover::create_credential_request,
    types::{CredentialRequest, CredentialRequestMetadata},
};

#[no_mangle]
pub extern "C" fn anoncreds_create_credential_request(
    prover_did: FfiStr, // optional
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

        // Here we check whether the identifiers inside the cred_def (schema_id, and issuer_id)
        // are legacy or new. If they are new, it is not allowed to supply a `prover_did` and a
        // random string will be chosen for you.
        let cred_def = cred_def.load()?;
        let cred_def: &CredentialDefinition = cred_def.cast_ref()?;
        if cred_def.schema_id.is_uri() || cred_def.issuer_id.is_uri() {
            return Err(err_msg!(
                "Prover did must not be supplied when using new identifiers"
            ));
        }

        let prover_did = prover_did.as_opt_str();
        let (cred_req, cred_req_metadata) = create_credential_request(
            prover_did,
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
