use ffi_support::FfiStr;
use indy_utils::Qualifiable;

use super::error::ErrorCode;
use super::object::ObjectHandle;
use crate::services::{
    issuer::new_credential_offer,
    types::{CredentialOffer, SchemaId},
};

#[no_mangle]
pub extern "C" fn credx_create_credential_offer(
    schema_id: FfiStr,
    cred_def: ObjectHandle,
    key_proof: ObjectHandle,
    cred_offer_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_err! {
        check_useful_c_ptr!(cred_offer_p);
        let schema_id = SchemaId::from_str(schema_id.as_str())?;
        let cred_offer = new_credential_offer(
            &schema_id,
            cred_def.load()?.cast_ref()?,
            key_proof.load()?.cast_ref()?,
        )?;
        let cred_offer = ObjectHandle::create(cred_offer)?;
        unsafe { *cred_offer_p = cred_offer };
        Ok(ErrorCode::Success)
    }
}

impl_indy_object!(CredentialOffer, "CredentialOffer");
impl_indy_object_from_json!(CredentialOffer, credx_credential_offer_from_json);
