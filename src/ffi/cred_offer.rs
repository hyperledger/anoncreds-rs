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
            .ok_or_else(|| err_msg!("Missing schema ID"))?;
        let cred_def_id = cred_def_id
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing cred def ID"))?;
        let cred_offer =
            create_credential_offer(schema_id, cred_def_id, key_proof.load()?.cast_ref()?)?;
        let cred_offer = ObjectHandle::create(cred_offer)?;
        unsafe { *cred_offer_p = cred_offer };
        Ok(())
    })
}

impl_anoncreds_object!(CredentialOffer, "CredentialOffer");
impl_anoncreds_object_from_json!(CredentialOffer, anoncreds_credential_offer_from_json);
