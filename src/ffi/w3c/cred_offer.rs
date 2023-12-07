use crate::ffi::cred_offer::anoncreds_create_credential_offer;
use crate::ffi::error::ErrorCode;
use crate::ffi::object::ObjectHandle;
use ffi_support::FfiStr;

/// Create Credential Offer according to the AnonCreds specification
/// Note that Credential Offer still will be legacy styled (the same as result of anoncreds_create_credential_offer)
///
/// # Params
/// schema_id:              id of schema future credential refers to
/// cred_def_id:            id of credential definition future credential refers to
/// key_proof:              object handle pointing to credential definition key correctness proof
/// cred_offer_p:           reference that will contain created credential offer (in legacy form) instance pointer
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_create_w3c_credential_offer(
    schema_id: FfiStr,
    cred_def_id: FfiStr,
    key_proof: ObjectHandle,
    cred_offer_p: *mut ObjectHandle,
) -> ErrorCode {
    anoncreds_create_credential_offer(schema_id, cred_def_id, key_proof, cred_offer_p)
}
