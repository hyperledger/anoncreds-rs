use ffi_support::FfiStr;

use crate::ffi::cred_req::anoncreds_create_credential_request;
use crate::ffi::error::ErrorCode;
use crate::ffi::object::ObjectHandle;

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
pub extern "C" fn anoncreds_create_w3c_credential_request(
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
