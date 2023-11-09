use ffi_support::FfiStr;

use super::error::{catch_error, ErrorCode};
use super::object::ObjectHandle;
use crate::services::{issuer::create_credential_offer, types::CredentialOffer};

#[no_mangle]
pub extern "C" fn anoncreds_create_credential_offer(
    schema_id: FfiStr,
    cred_def_id: FfiStr,
    key_proof: ObjectHandle,
    cred_offer_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(cred_offer_p);
        let schema_id = schema_id
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing schema ID"))?
            .try_into()?;
        let cred_def_id = cred_def_id
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing cred def ID"))?
            .try_into()?;
        let cred_offer =
            create_credential_offer(schema_id, cred_def_id, key_proof.load()?.cast_ref()?)?;
        let cred_offer = ObjectHandle::create(cred_offer)?;
        unsafe { *cred_offer_p = cred_offer };
        Ok(())
    })
}

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
pub extern "C" fn anoncreds_w3c_create_credential_offer(
    schema_id: FfiStr,
    cred_def_id: FfiStr,
    key_proof: ObjectHandle,
    cred_offer_p: *mut ObjectHandle,
) -> ErrorCode {
    anoncreds_create_credential_offer(schema_id, cred_def_id, key_proof, cred_offer_p)
}

impl_anoncreds_object!(CredentialOffer, "CredentialOffer");
impl_anoncreds_object_from_json!(CredentialOffer, anoncreds_credential_offer_from_json);
