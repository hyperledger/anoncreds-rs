use super::error::{catch_error, ErrorCode};
use super::object::{AnoncredsObject, ObjectHandle};
use super::util::FfiList;
use crate::data_types::rev_status_list::RevocationStatusList;
use crate::data_types::{
    rev_reg::RevocationRegistry,
    rev_reg_def::{
        RegistryType, RevocationRegistryDefinition, RevocationRegistryDefinitionPrivate,
    },
};
use crate::issuer;
use crate::services::issuer::create_revocation_registry_def;
use crate::services::prover::create_or_update_revocation_state;
use crate::services::tails::TailsFileWriter;
use crate::services::types::CredentialRevocationState;
use ffi_support::{rust_string_to_c, FfiStr};
use std::collections::BTreeSet;
use std::os::raw::c_char;
use std::str::FromStr;

#[no_mangle]
pub extern "C" fn anoncreds_create_revocation_status_list(
    cred_def: ObjectHandle,
    rev_reg_def_id: FfiStr,
    rev_reg_def: ObjectHandle,
    reg_rev_priv: ObjectHandle,
    issuer_id: FfiStr,
    issuance_by_default: i8,
    timestamp: i64,
    rev_status_list_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(rev_status_list_p);
        let rev_reg_def_id = rev_reg_def_id
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing rev_reg_def_id"))?;
        let issuer_id = issuer_id
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing issuer_id"))?;
        let timestamp = if timestamp <= 0 {
            None
        } else {
            Some(timestamp as u64)
        };

        let rev_status_list = issuer::create_revocation_status_list(
            cred_def.load()?.cast_ref()?,
            rev_reg_def_id,
            rev_reg_def.load()?.cast_ref()?,
            reg_rev_priv.load()?.cast_ref()?,
            issuer_id,
            issuance_by_default != 0,
            timestamp,
        )?;

        let rev_status_list_handle = ObjectHandle::create(rev_status_list)?;

        unsafe { *rev_status_list_p = rev_status_list_handle };

        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn anoncreds_update_revocation_status_list(
    cred_def: ObjectHandle,
    rev_reg_def: ObjectHandle,
    rev_reg_priv: ObjectHandle,
    rev_current_list: ObjectHandle,
    issued: FfiList<i32>,
    revoked: FfiList<i32>,
    timestamp: i64,
    new_rev_status_list_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(new_rev_status_list_p);
        let timestamp = if timestamp <= 0 {
            None
        } else {
            Some(timestamp as u64)
        };
        let revoked: Option<BTreeSet<u32>> = if revoked.is_empty() {
            None
        } else {
            Some(revoked.as_slice().iter().map(|r| *r as u32).collect())
        };
        let issued: Option<BTreeSet<u32>> = if issued.is_empty() {
            None
        } else {
            Some(issued.as_slice().iter().map(|r| *r as u32).collect())
        };
        let new_rev_status_list = issuer::update_revocation_status_list(
            cred_def.load()?.cast_ref()?,
            rev_reg_def.load()?.cast_ref()?,
            rev_reg_priv.load()?.cast_ref()?,
            rev_current_list.load()?.cast_ref()?,
            issued,
            revoked,
            timestamp,
        )?;

        let new_rev_status_list = ObjectHandle::create(new_rev_status_list)?;

        unsafe { *new_rev_status_list_p = new_rev_status_list };

        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn anoncreds_update_revocation_status_list_timestamp_only(
    timestamp: i64,
    rev_current_list: ObjectHandle,
    rev_status_list_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(rev_status_list_p);
        let timestamp = timestamp as u64;

        let new_rev_status_list = issuer::update_revocation_status_list_timestamp_only(
            timestamp,
            rev_current_list.load()?.cast_ref()?,
        );

        let new_rev_status_list_handle = ObjectHandle::create(new_rev_status_list)?;

        unsafe { *rev_status_list_p = new_rev_status_list_handle };

        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn anoncreds_create_revocation_registry_def(
    cred_def: ObjectHandle,
    cred_def_id: FfiStr,
    tag: FfiStr,
    rev_reg_type: FfiStr,
    max_cred_num: i64,
    tails_dir_path: FfiStr,
    reg_def_p: *mut ObjectHandle,
    reg_def_private_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(reg_def_p);
        check_useful_c_ptr!(reg_def_private_p);
        let tag = tag.as_opt_str().ok_or_else(|| err_msg!("Missing tag"))?;
        let cred_def_id = cred_def_id
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing cred def id"))?
            .try_into()?;
        let rev_reg_type = {
            let rtype = rev_reg_type
                .as_opt_str()
                .ok_or_else(|| err_msg!("Missing registry type"))?;
            RegistryType::from_str(rtype).map_err(err_map!(Input))?
        };
        let mut tails_writer = TailsFileWriter::new(tails_dir_path.into_opt_string());
        let (reg_def, reg_def_private) = create_revocation_registry_def(
            cred_def.load()?.cast_ref()?,
            cred_def_id,
            tag,
            rev_reg_type,
            max_cred_num
                .try_into()
                .map_err(|_| err_msg!("Invalid maximum credential count"))?,
            &mut tails_writer,
        )?;
        let reg_def = ObjectHandle::create(reg_def)?;
        let reg_def_private = ObjectHandle::create(reg_def_private)?;
        unsafe {
            *reg_def_p = reg_def;
            *reg_def_private_p = reg_def_private;
        };
        Ok(())
    })
}

impl_anoncreds_object!(RevocationRegistryDefinition, "RevocationRegistryDefinition");
impl_anoncreds_object_from_json!(
    RevocationRegistryDefinition,
    anoncreds_revocation_registry_definition_from_json
);

#[no_mangle]
pub extern "C" fn anoncreds_revocation_registry_definition_get_attribute(
    handle: ObjectHandle,
    name: FfiStr,
    result_p: *mut *const c_char,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(result_p);
        let reg_def = handle.load()?;
        let reg_def = reg_def.cast_ref::<RevocationRegistryDefinition>()?;
        let val = match name.as_opt_str().unwrap_or_default() {
            "max_cred_num" => reg_def.value.max_cred_num.to_string(),
            "tails_hash" => reg_def.value.tails_hash.to_string(),
            "tails_location" => reg_def.value.tails_location.to_string(),
            s => return Err(err_msg!("Unsupported attribute: {}", s)),
        };
        unsafe { *result_p = rust_string_to_c(val) };
        Ok(())
    })
}

impl_anoncreds_object!(
    RevocationRegistryDefinitionPrivate,
    "RevocationRegistryDefinitionPrivate"
);
impl_anoncreds_object_from_json!(
    RevocationRegistryDefinitionPrivate,
    anoncreds_revocation_registry_definition_private_from_json
);

impl_anoncreds_object!(RevocationRegistry, "RevocationRegistry");
impl_anoncreds_object_from_json!(RevocationRegistry, anoncreds_revocation_registry_from_json);

impl_anoncreds_object!(RevocationStatusList, "RevocationStatusList");
impl_anoncreds_object_from_json!(
    RevocationStatusList,
    anoncreds_revocation_status_list_from_json
);

#[no_mangle]
pub extern "C" fn anoncreds_create_or_update_revocation_state(
    rev_reg_def: ObjectHandle,
    rev_status_list: ObjectHandle,
    rev_reg_index: i64,
    tails_path: FfiStr,
    rev_state: ObjectHandle,
    old_rev_status_list: ObjectHandle,
    rev_state_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(rev_state_p);
        let prev_rev_state = rev_state.opt_load()?;
        let prev_rev_status_list = old_rev_status_list.opt_load()?;
        let tails_path = tails_path
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing tails file path"))?;
        let rev_state = create_or_update_revocation_state(
            tails_path,
            rev_reg_def.load()?.cast_ref()?,
            rev_status_list.load()?.cast_ref()?,
            rev_reg_index
                .try_into()
                .map_err(|_| err_msg!("Invalid credential revocation index"))?,
            prev_rev_state
                .as_ref()
                .map(AnoncredsObject::cast_ref)
                .transpose()?,
            prev_rev_status_list
                .as_ref()
                .map(AnoncredsObject::cast_ref)
                .transpose()?,
        )?;
        let rev_state = ObjectHandle::create(rev_state)?;
        unsafe { *rev_state_p = rev_state };
        Ok(())
    })
}

impl_anoncreds_object!(CredentialRevocationState, "CredentialRevocationState");
impl_anoncreds_object_from_json!(
    CredentialRevocationState,
    anoncreds_revocation_state_from_json
);
