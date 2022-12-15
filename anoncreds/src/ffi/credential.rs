use std::collections::HashSet;
use std::convert::TryInto;
use std::os::raw::c_char;
use std::ptr;

use ffi_support::{rust_string_to_c, FfiStr};

use super::error::{catch_error, ErrorCode};
use super::object::{AnonCredsObject, ObjectHandle};
use super::util::{FfiList, FfiStrList};
use crate::data_types::anoncreds::rev_reg::RevocationRegistryId;
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
    registry: ObjectHandle,
    reg_idx: i64,
    reg_used: FfiList<'a, i64>,
    tails_path: FfiStr<'a>,
}

struct RevocationConfig {
    reg_def: AnonCredsObject,
    reg_def_private: AnonCredsObject,
    registry: AnonCredsObject,
    reg_idx: u32,
    reg_used: HashSet<u32>,
    tails_path: String,
}

impl RevocationConfig {
    pub fn as_ref_config(&self) -> Result<CredentialRevocationConfig> {
        Ok(CredentialRevocationConfig {
            reg_def: self.reg_def.cast_ref()?,
            reg_def_private: self.reg_def_private.cast_ref()?,
            registry: self.registry.cast_ref()?,
            registry_idx: self.reg_idx,
            registry_used: &self.reg_used,
            tails_reader: TailsFileReader::new(self.tails_path.as_str()),
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
        let rev_reg_id = rev_reg_id
            .as_opt_str()
            .map(RevocationRegistryId::new)
            .transpose()?;
        let enc_values = attr_enc_values.as_slice();
        let mut cred_values = MakeCredentialValues::default();
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
            attr_idx += 1;
        }
        let revocation_config = if !revocation.is_null() {
            let revocation = unsafe { &*revocation };
            let tails_path = revocation
                .tails_path
                .as_opt_str()
                .ok_or_else(|| err_msg!("Missing tails file path"))?
                .to_string();
            let mut reg_used = HashSet::new();
            for reg_idx in revocation.reg_used.as_slice() {
                reg_used.insert(
                    (*reg_idx)
                        .try_into()
                        .map_err(|_| err_msg!("Invalid revocation index"))?,
                );
            }
            Some(RevocationConfig {
                reg_def: revocation.reg_def.load()?,
                reg_def_private: revocation.reg_def_private.load()?,
                registry: revocation.registry.load()?,
                reg_idx: revocation
                    .reg_idx
                    .try_into()
                    .map_err(|_| err_msg!("Invalid revocation index"))?,
                reg_used,
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
            cred_values.into(),
            rev_reg_id,
            revocation_config
                .as_ref()
                .map(RevocationConfig::as_ref_config)
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
                .map(AnonCredsObject::cast_ref)
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
            "schema_id" => rust_string_to_c(cred.schema_id.to_owned()),
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
