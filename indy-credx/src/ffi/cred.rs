use super::error::{catch_error, ErrorCode};
use super::object::ObjectHandle;
use super::util::FfiStrList;
use crate::services::{
    issuer::{encode_credential_attribute, new_credential},
    prover::process_credential,
    types::{AttributeValues, Credential, CredentialValues},
};

#[no_mangle]
pub extern "C" fn credx_create_credential(
    cred_def: ObjectHandle,
    cred_def_private: ObjectHandle,
    cred_offer: ObjectHandle,
    cred_request: ObjectHandle,
    attr_names: FfiStrList,
    attr_raw_values: FfiStrList,
    attr_enc_values: FfiStrList,
    // revocation info
    cred_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(cred_p);
        if attr_names.is_empty() {
            return Err(err_msg!("Cannot create credential with no attribute"));
        }
        if attr_names.len() != attr_raw_values.len() {
            return Err(err_msg!(
                "Mismatch between length of attribute names and raw values"
            ));
        }
        let enc_values = attr_enc_values.as_slice();
        let mut cred_values = CredentialValues(Default::default());
        let mut attr_idx = 0;
        for (name, raw) in attr_names
            .as_slice()
            .into_iter()
            .zip(attr_raw_values.as_slice())
        {
            let name = name
                .as_opt_str()
                .ok_or_else(|| err_msg!("Missing attribute name"))?
                .to_string();
            let raw = raw
                .as_opt_str()
                .ok_or_else(|| err_msg!("Missing attribute raw value"))?
                .to_string();
            let mut encoded = if attr_idx < enc_values.len() {
                enc_values[attr_idx].as_opt_str().map(str::to_string)
            } else {
                None
            };
            if encoded.is_none() {
                encoded.replace(encode_credential_attribute(&raw)?);
            }
            cred_values.0.insert(
                name,
                AttributeValues {
                    raw,
                    encoded: encoded.unwrap(),
                },
            );
            attr_idx += 1;
        }
        let (cred, rev_reg, rev_delta) = new_credential(
            cred_def.load()?.cast_ref()?,
            cred_def_private.load()?.cast_ref()?,
            cred_offer.load()?.cast_ref()?,
            cred_request.load()?.cast_ref()?,
            cred_values,
            None,
        )?;
        let cred = ObjectHandle::create(cred)?;
        unsafe { *cred_p = cred };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn credx_process_credential(
    cred: ObjectHandle,
    cred_req_metadata: ObjectHandle,
    master_secret: ObjectHandle,
    cred_def: ObjectHandle,
    // rev_reg_def: ObjectHandle
    cred_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(cred_p);
        let mut cred = cred
            .load()?
            .cast_ref::<Credential>()?
            .try_clone()
            .map_err(err_map!(Unexpected, "Error copying credential"))?;
        process_credential(
            &mut cred,
            cred_req_metadata.load()?.cast_ref()?,
            master_secret.load()?.cast_ref()?,
            cred_def.load()?.cast_ref()?,
            None,
        )?;
        let cred = ObjectHandle::create(cred)?;
        unsafe { *cred_p = cred };
        Ok(())
    })
}

impl_indy_object!(Credential, "Credential");
impl_indy_object_from_json!(Credential, credx_credential_from_json);
