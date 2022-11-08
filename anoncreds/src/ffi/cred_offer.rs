use ffi_support::FfiStr;
use indy_utils::Qualifiable;

use super::error::{catch_error, ErrorCode};
use super::object::ObjectHandle;
use crate::services::{
    issuer::create_credential_offer,
    types::{CredentialOffer, SchemaId},
};

#[no_mangle]
pub extern "C" fn anoncreds_create_credential_offer(
    schema_id: FfiStr,
    cred_def: ObjectHandle,
    key_proof: ObjectHandle,
    cred_offer_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(cred_offer_p);
        let schema_id = {
            let sid = schema_id
                .as_opt_str()
                .ok_or_else(|| err_msg!("Missing schema ID"))?;
            SchemaId::from_str(sid)?
        };
        let cred_offer = create_credential_offer(
            &schema_id,
            cred_def.load()?.cast_ref()?,
            key_proof.load()?.cast_ref()?,
        )?;
        let cred_offer = ObjectHandle::create(cred_offer)?;
        unsafe { *cred_offer_p = cred_offer };
        Ok(())
    })
}

impl_anoncreds_object!(CredentialOffer, "CredentialOffer");
impl_anoncreds_object_from_json!(CredentialOffer, anoncreds_credential_offer_from_json);
