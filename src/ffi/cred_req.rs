use ffi_support::FfiStr;

use super::error::{catch_error, ErrorCode};
use super::object::ObjectHandle;
use crate::data_types::cred_def::CredentialDefinition;
use crate::data_types::link_secret::LinkSecret;
use crate::services::{
    prover::create_credential_request,
    types::{CredentialRequest, CredentialRequestMetadata},
};

#[no_mangle]
pub extern "C" fn anoncreds_create_credential_request(
    entropy: FfiStr,
    prover_did: FfiStr,
    cred_def: ObjectHandle,
    link_secret: FfiStr,
    link_secret_id: FfiStr,
    cred_offer: ObjectHandle,
    cred_req_p: *mut ObjectHandle,
    cred_req_meta_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(cred_req_p);
        check_useful_c_ptr!(cred_req_meta_p);

        let link_secret = link_secret
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing link secret"))?;
        let link_secret = LinkSecret::try_from(link_secret)?;

        let link_secret_id = link_secret_id
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing link secret ID"))?;
        let entropy = entropy.as_opt_str();
        let prover_did = prover_did.as_opt_str();

        let cred_def = cred_def.load()?;
        let cred_def: &CredentialDefinition = cred_def.cast_ref()?;

        let (cred_req, cred_req_metadata) = create_credential_request(
            entropy,
            prover_did,
            cred_def,
            &link_secret,
            link_secret_id,
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

/// Create Credential Request according to the AnonCreds specification
/// Note that Credential Request still will be legacy styled (the same as result of anoncreds_create_credential_request)
///
/// # Params
/// entropy:                entropy string to use for request creation
/// prover_did:             DID of the credential holder
/// cred_def:               object handle pointing to credential definition
/// link_secret:            holder link secret
/// link_secret_id:         id of holder's link secret
/// credential_offer:       object handle pointing to credential offer
/// cred_req_p:             Reference that will contain created credential request (in legacy form) instance pointer.
/// cred_req_meta_p:        Reference that will contain created credential request metadata (in legacy form) instance pointer.
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_w3c_create_credential_request(
    entropy: FfiStr,
    prover_did: FfiStr,
    cred_def: ObjectHandle,
    link_secret: FfiStr,
    link_secret_id: FfiStr,
    cred_offer: ObjectHandle,
    cred_req_p: *mut ObjectHandle,
    cred_req_meta_p: *mut ObjectHandle,
) -> ErrorCode {
    anoncreds_create_credential_request(
        entropy,
        prover_did,
        cred_def,
        link_secret,
        link_secret_id,
        cred_offer,
        cred_req_p,
        cred_req_meta_p,
    )
}

impl_anoncreds_object!(CredentialRequest, "CredentialRequest");
impl_anoncreds_object_from_json!(CredentialRequest, anoncreds_credential_request_from_json);

impl_anoncreds_object!(CredentialRequestMetadata, "CredentialRequestMetadata");
impl_anoncreds_object_from_json!(
    CredentialRequestMetadata,
    anoncreds_credential_request_metadata_from_json
);
