use std::convert::TryInto;
use std::os::raw::c_char;
use std::ptr;

use ffi_support::{rust_string_to_c, FfiStr};

use super::error::{catch_error, ErrorCode};
use super::object::{IndyObject, ObjectHandle};
use super::util::FfiStrList;
use crate::error::Result;
use crate::services::{
    issuer::{create_credential, encode_credential_attribute},
    prover::process_credential,
    tails::TailsFileReader,
    types::{AttributeValues, Credential, CredentialRevocationConfig, CredentialValues},
};

#[derive(Debug)]
#[repr(C)]
pub struct FfiCredRevInfo<'a> {
    reg_def: ObjectHandle,
    reg_def_private: ObjectHandle,
    registry: ObjectHandle,
    reg_idx: i64,
    tails_path: FfiStr<'a>,
}

struct RevocationConfig {
    reg_def: IndyObject,
    reg_def_private: IndyObject,
    registry: IndyObject,
    reg_idx: u32,
    tails_path: String,
}

impl RevocationConfig {
    pub fn ref_config(&self) -> Result<CredentialRevocationConfig> {
        Ok(CredentialRevocationConfig {
            reg_def: self.reg_def.cast_ref()?,
            reg_def_private: self.reg_def_private.cast_ref()?,
            registry: self.registry.cast_ref()?,
            registry_idx: self.reg_idx,
            tails_reader: TailsFileReader::new(self.tails_path.as_str()),
        })
    }
}

#[no_mangle]
pub extern "C" fn credx_create_credential(
    cred_def: ObjectHandle,
    cred_def_private: ObjectHandle,
    cred_offer: ObjectHandle,
    cred_request: ObjectHandle,
    attr_names: FfiStrList,
    attr_raw_values: FfiStrList,
    attr_enc_values: FfiStrList,
    revocation: *const FfiCredRevInfo,
    cred_p: *mut ObjectHandle,
    rev_reg_p: *mut ObjectHandle,
    rev_delta_p: *mut ObjectHandle,
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
        let revocation_config = if !revocation.is_null() {
            let revocation = unsafe { &*revocation };
            let tails_path = revocation
                .tails_path
                .as_opt_str()
                .ok_or_else(|| err_msg!("Missing tails file path"))?
                .to_string();
            Some(RevocationConfig {
                reg_def: revocation.reg_def.load()?,
                reg_def_private: revocation.reg_def_private.load()?,
                registry: revocation.registry.load()?,
                reg_idx: revocation
                    .reg_idx
                    .try_into()
                    .map_err(|_| err_msg!("Invalid revocation index"))?,
                tails_path,
            })
        } else {
            None
        };
        let (cred, rev_reg, rev_delta) = create_credential(
            cred_def.load()?.cast_ref()?,
            cred_def_private.load()?.cast_ref()?,
            cred_offer.load()?.cast_ref()?,
            cred_request.load()?.cast_ref()?,
            cred_values,
            revocation_config
                .as_ref()
                .map(RevocationConfig::ref_config)
                .transpose()?,
        )?;
        let cred = ObjectHandle::create(cred)?;
        let rev_reg = rev_reg
            .map(ObjectHandle::create)
            .transpose()?
            .unwrap_or_default();
        let rev_delta = rev_delta
            .map(ObjectHandle::create)
            .transpose()?
            .unwrap_or_default();
        unsafe {
            *cred_p = cred;
            *rev_reg_p = rev_reg;
            *rev_delta_p = rev_delta;
        };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn credx_process_credential(
    cred: ObjectHandle,
    cred_req_metadata: ObjectHandle,
    master_secret: ObjectHandle,
    cred_def: ObjectHandle,
    rev_reg_def: ObjectHandle,
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
            rev_reg_def
                .opt_load()?
                .as_ref()
                .map(IndyObject::cast_ref)
                .transpose()?,
        )?;
        let cred = ObjectHandle::create(cred)?;
        unsafe { *cred_p = cred };
        Ok(())
    })
}

impl_indy_object!(Credential, "Credential");
impl_indy_object_from_json!(Credential, credx_credential_from_json);

#[no_mangle]
pub extern "C" fn credx_credential_get_attribute(
    handle: ObjectHandle,
    name: FfiStr,
    result_p: *mut *const c_char,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(result_p);
        let cred = handle.load()?;
        let cred = cred.cast_ref::<Credential>()?;
        let val = match name.as_opt_str().unwrap_or_default() {
            "schema_id" => rust_string_to_c(cred.schema_id.to_string()),
            "cred_def_id" => rust_string_to_c(cred.cred_def_id.to_string()),
            "rev_reg_id" => cred
                .rev_reg_id
                .as_ref()
                .map(|s| rust_string_to_c(s.to_string()))
                .unwrap_or(ptr::null_mut()),
            "rev_reg_index" => cred
                .signature
                .extract_index()
                .map(|s| rust_string_to_c(s.to_string()))
                .unwrap_or(ptr::null_mut()),
            s => return Err(err_msg!("Unsupported attribute: {}", s)),
        };
        unsafe { *result_p = val };
        Ok(())
    })
}
