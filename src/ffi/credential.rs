use std::os::raw::c_char;
use std::ptr;

use ffi_support::{rust_string_to_c, FfiStr};

use super::error::{catch_error, ErrorCode};
use super::object::{AnoncredsObject, ObjectHandle};
use super::util::FfiStrList;
use crate::data_types::link_secret::LinkSecret;
use crate::data_types::rev_reg::RevocationRegistryId;
use crate::error::Result;
use crate::services::{
    issuer::create_credential,
    prover::process_credential,
    tails::TailsFileReader,
    types::{Credential, CredentialRevocationConfig, MakeCredentialValues},
    utils::encode_credential_attribute,
};

#[derive(Debug)]
#[repr(C)]
pub struct FfiCredRevInfo<'a> {
    reg_def: ObjectHandle,
    reg_def_private: ObjectHandle,
    reg_idx: i64,
    tails_path: FfiStr<'a>,
}

struct RevocationConfig {
    reg_def: AnoncredsObject,
    reg_def_private: AnoncredsObject,
    reg_idx: u32,
    tails_path: String,
}

impl RevocationConfig {
    pub fn as_ref_config(&self) -> Result<CredentialRevocationConfig> {
        Ok(CredentialRevocationConfig {
            reg_def: self.reg_def.cast_ref()?,
            reg_def_private: self.reg_def_private.cast_ref()?,
            registry_idx: self.reg_idx,
            tails_reader: TailsFileReader::new_tails_reader(self.tails_path.as_str()),
        })
    }
}

#[no_mangle]
pub extern "C" fn anoncreds_create_credential(
    cred_def: ObjectHandle,
    cred_def_private: ObjectHandle,
    cred_offer: ObjectHandle,
    cred_request: ObjectHandle,
    attr_names: FfiStrList,
    attr_raw_values: FfiStrList,
    attr_enc_values: FfiStrList,
    rev_reg_id: FfiStr,
    rev_status_list: ObjectHandle,
    revocation: *const FfiCredRevInfo,
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
        let rev_reg_id = rev_reg_id
            .as_opt_str()
            .map(RevocationRegistryId::new)
            .transpose()?;
        let enc_values = attr_enc_values.as_slice();
        let mut cred_values = MakeCredentialValues::default();
        for (attr_idx, (name, raw)) in attr_names
            .as_slice()
            .iter()
            .zip(attr_raw_values.as_slice())
            .enumerate()
        {
            let name = name
                .as_opt_str()
                .ok_or_else(|| err_msg!("Missing attribute name"))?
                .to_string();
            let raw = raw
                .as_opt_str()
                .ok_or_else(|| err_msg!("Missing attribute raw value"))?
                .to_string();
            let encoded = if attr_idx < enc_values.len() {
                enc_values[attr_idx].as_opt_str().map(str::to_string)
            } else {
                None
            };
            if let Some(encoded) = encoded {
                cred_values.add_encoded(name, raw, encoded);
            } else {
                cred_values.add_raw(name, raw)?;
            }
        }
        let revocation_config = if revocation.is_null() {
            None
        } else {
            let revocation = unsafe { &*revocation };
            let tails_path = revocation
                .tails_path
                .as_opt_str()
                .ok_or_else(|| err_msg!("Missing tails file path"))?
                .to_string();
            Some(RevocationConfig {
                reg_def: revocation.reg_def.load()?,
                reg_def_private: revocation.reg_def_private.load()?,
                reg_idx: revocation
                    .reg_idx
                    .try_into()
                    .map_err(|_| err_msg!("Invalid revocation index"))?,
                tails_path,
            })
        };

        let cred = create_credential(
            cred_def.load()?.cast_ref()?,
            cred_def_private.load()?.cast_ref()?,
            cred_offer.load()?.cast_ref()?,
            cred_request.load()?.cast_ref()?,
            cred_values.into(),
            rev_reg_id,
            rev_status_list
                .opt_load()?
                .as_ref()
                .map(AnoncredsObject::cast_ref)
                .transpose()?,
            revocation_config
                .as_ref()
                .map(RevocationConfig::as_ref_config)
                .transpose()?,
        )?;
        let cred = ObjectHandle::create(cred)?;
        unsafe {
            *cred_p = cred;
        };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn anoncreds_encode_credential_attributes(
    attr_raw_values: FfiStrList,
    result_p: *mut *const c_char,
) -> ErrorCode {
    catch_error(|| {
        let mut result = String::new();
        for raw_val in attr_raw_values.as_slice() {
            let enc_val = encode_credential_attribute(
                raw_val
                    .as_opt_str()
                    .ok_or_else(|| err_msg!("Missing attribute raw value"))?,
            )?;
            if !result.is_empty() {
                result.push(',');
            }
            result.push_str(enc_val.as_str());
        }
        unsafe { *result_p = rust_string_to_c(result) };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn anoncreds_process_credential(
    cred: ObjectHandle,
    cred_req_metadata: ObjectHandle,
    link_secret: FfiStr,
    cred_def: ObjectHandle,
    rev_reg_def: ObjectHandle,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(cred_p);

        let link_secret = link_secret
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing link secret"))?;
        let link_secret = LinkSecret::try_from(link_secret)?;

        let mut cred = cred
            .load()?
            .cast_ref::<Credential>()?
            .try_clone()
            .map_err(err_map!(Unexpected, "Error copying credential"))?;
        process_credential(
            &mut cred,
            cred_req_metadata.load()?.cast_ref()?,
            &link_secret,
            cred_def.load()?.cast_ref()?,
            rev_reg_def
                .opt_load()?
                .as_ref()
                .map(AnoncredsObject::cast_ref)
                .transpose()?,
        )?;
        let cred = ObjectHandle::create(cred)?;
        unsafe { *cred_p = cred };
        Ok(())
    })
}

impl_anoncreds_object!(Credential, "Credential");
impl_anoncreds_object_from_json!(Credential, anoncreds_credential_from_json);

#[no_mangle]
pub extern "C" fn anoncreds_credential_get_attribute(
    handle: ObjectHandle,
    name: FfiStr,
    result_p: *mut *const c_char,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(result_p);
        let cred = handle.load()?;
        let cred = cred.cast_ref::<Credential>()?;
        let val = match name.as_opt_str().unwrap_or_default() {
            "schema_id" => rust_string_to_c(cred.schema_id.clone()),
            "cred_def_id" => rust_string_to_c(cred.cred_def_id.to_string()),
            "rev_reg_id" => cred
                .rev_reg_id
                .as_ref()
                .map_or(ptr::null_mut(), |s| rust_string_to_c(s.to_string())),
            "rev_reg_index" => cred
                .signature
                .extract_index()
                .map_or(ptr::null_mut(), |s| rust_string_to_c(s.to_string())),
            s => return Err(err_msg!("Unsupported attribute: {}", s)),
        };
        unsafe { *result_p = val };
        Ok(())
    })
}
