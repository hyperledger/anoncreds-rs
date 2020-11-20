use std::collections::BTreeSet;
use std::convert::TryInto;
use std::os::raw::c_char;

use ffi_support::{rust_string_to_c, FfiStr};
use indy_utils::Qualifiable;

use super::error::{catch_error, ErrorCode};
use super::object::{IndyObject, IndyObjectId, ObjectHandle};
use super::util::FfiList;
use crate::error::Result;
use crate::services::{
    issuer::{create_revocation_registry, revoke_credential, update_revocation_registry},
    prover::create_or_update_revocation_state,
    tails::{TailsFileReader, TailsFileWriter},
    types::{
        CredentialRevocationState, DidValue, IssuanceType, RegistryType, RevocationRegistry,
        RevocationRegistryDefinition, RevocationRegistryDefinitionPrivate, RevocationRegistryDelta,
        RevocationRegistryId,
    },
};

#[no_mangle]
pub extern "C" fn credx_create_revocation_registry(
    origin_did: FfiStr,
    cred_def: ObjectHandle,
    tag: FfiStr,
    rev_reg_type: FfiStr,
    issuance_type: FfiStr,
    max_cred_num: i64,
    tails_dir_path: FfiStr,
    reg_def_p: *mut ObjectHandle,
    reg_def_private_p: *mut ObjectHandle,
    reg_entry_p: *mut ObjectHandle,
    reg_init_delta_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(reg_def_p);
        check_useful_c_ptr!(reg_def_private_p);
        check_useful_c_ptr!(reg_entry_p);
        check_useful_c_ptr!(reg_init_delta_p);
        let origin_did = {
            let did = origin_did
                .as_opt_str()
                .ok_or_else(|| err_msg!("Missing origin DID"))?;
            DidValue::from_str(did)?
        };
        let tag = tag.as_opt_str().ok_or_else(|| err_msg!("Missing tag"))?;
        let rev_reg_type = {
            let rtype = rev_reg_type
                .as_opt_str()
                .ok_or_else(|| err_msg!("Missing registry type"))?;
            RegistryType::from_str(rtype).map_err(err_map!(Input))?
        };
        let issuance_type = match issuance_type.as_opt_str() {
            Some(s) => IssuanceType::from_str(s).map_err(err_map!(Input))?,
            None => IssuanceType::default(),
        };
        let mut tails_writer = TailsFileWriter::new(tails_dir_path.into_opt_string());
        let (reg_def, reg_def_private, reg_entry, reg_init_delta) = create_revocation_registry(
            &origin_did,
            cred_def.load()?.cast_ref()?,
            tag,
            rev_reg_type,
            issuance_type,
            max_cred_num
                .try_into()
                .map_err(|_| err_msg!("Invalid maximum credential count"))?,
            &mut tails_writer,
        )?;
        let reg_def = ObjectHandle::create(reg_def)?;
        let reg_def_private = ObjectHandle::create(reg_def_private)?;
        let reg_entry = ObjectHandle::create(reg_entry)?;
        let reg_init_delta = ObjectHandle::create(reg_init_delta)?;
        unsafe {
            *reg_def_p = reg_def;
            *reg_def_private_p = reg_def_private;
            *reg_entry_p = reg_entry;
            *reg_init_delta_p = reg_init_delta;
        };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn credx_update_revocation_registry(
    rev_reg_def: ObjectHandle,
    rev_reg: ObjectHandle,
    issued: FfiList<i64>,
    revoked: FfiList<i64>,
    tails_path: FfiStr,
    rev_reg_p: *mut ObjectHandle,
    rev_reg_delta_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(rev_reg_p);
        check_useful_c_ptr!(rev_reg_delta_p);
        let issued = registry_indices_to_set(issued.as_slice().into_iter().cloned())?;
        let revoked = registry_indices_to_set(revoked.as_slice().into_iter().cloned())?;
        let tails_reader = TailsFileReader::new(
            tails_path
                .as_opt_str()
                .ok_or_else(|| err_msg!("Missing tails file path"))?,
        );
        let (rev_reg, rev_reg_delta) = update_revocation_registry(
            rev_reg_def.load()?.cast_ref()?,
            rev_reg.load()?.cast_ref()?,
            issued,
            revoked,
            &tails_reader,
        )?;
        let rev_reg = ObjectHandle::create(rev_reg)?;
        let rev_reg_delta = ObjectHandle::create(rev_reg_delta)?;
        unsafe {
            *rev_reg_p = rev_reg;
            *rev_reg_delta_p = rev_reg_delta;
        };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn credx_revoke_credential(
    rev_reg_def: ObjectHandle,
    rev_reg: ObjectHandle,
    cred_rev_idx: i64,
    tails_path: FfiStr,
    rev_reg_p: *mut ObjectHandle,
    rev_reg_delta_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(rev_reg_p);
        check_useful_c_ptr!(rev_reg_delta_p);
        let tails_reader = TailsFileReader::new(
            tails_path
                .as_opt_str()
                .ok_or_else(|| err_msg!("Missing tails file path"))?,
        );
        let (rev_reg, rev_reg_delta) = revoke_credential(
            rev_reg_def.load()?.cast_ref()?,
            rev_reg.load()?.cast_ref()?,
            cred_rev_idx
                .try_into()
                .map_err(|_| err_msg!("Invalid registry index"))?,
            &tails_reader,
        )?;
        let rev_reg = ObjectHandle::create(rev_reg)?;
        let rev_reg_delta = ObjectHandle::create(rev_reg_delta)?;
        unsafe {
            *rev_reg_p = rev_reg;
            *rev_reg_delta_p = rev_reg_delta;
        };
        Ok(())
    })
}

fn registry_indices_to_set(indices: impl Iterator<Item = i64>) -> Result<BTreeSet<u32>> {
    indices.into_iter().try_fold(BTreeSet::new(), |mut r, idx| {
        r.insert(
            idx.try_into()
                .map_err(|_| err_msg!("Invalid registry index"))?,
        );
        Result::Ok(r)
    })
}

impl_indy_object!(RevocationRegistryDefinition, "RevocationRegistryDefinition");
impl_indy_object_from_json!(
    RevocationRegistryDefinition,
    credx_revocation_registry_definition_from_json
);

impl IndyObjectId for RevocationRegistryDefinition {
    type Id = RevocationRegistryId;

    fn get_id(&self) -> Self::Id {
        match self {
            RevocationRegistryDefinition::RevocationRegistryDefinitionV1(r) => r.id.clone(),
        }
    }
}

#[no_mangle]
pub extern "C" fn credx_revocation_registry_definition_get_attribute(
    handle: ObjectHandle,
    name: FfiStr,
    result_p: *mut *const c_char,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(result_p);
        let reg_def = handle.load()?;
        let reg_def = reg_def.cast_ref::<RevocationRegistryDefinition>()?;
        let val = match name.as_opt_str().unwrap_or_default() {
            "id" => reg_def.get_id().to_string(),
            "tails_hash" => match reg_def {
                RevocationRegistryDefinition::RevocationRegistryDefinitionV1(r) => {
                    r.value.tails_hash.to_string()
                }
            },
            "tails_location" => match reg_def {
                RevocationRegistryDefinition::RevocationRegistryDefinitionV1(r) => {
                    r.value.tails_location.to_string()
                }
            },
            s => return Err(err_msg!("Unsupported attribute: {}", s)),
        };
        unsafe { *result_p = rust_string_to_c(val) };
        Ok(())
    })
}

impl_indy_object!(
    RevocationRegistryDefinitionPrivate,
    "RevocationRegistryDefinitionPrivate"
);
impl_indy_object_from_json!(
    RevocationRegistryDefinitionPrivate,
    credx_revocation_registry_definition_private_from_json
);

impl_indy_object!(RevocationRegistry, "RevocationRegistry");
impl_indy_object_from_json!(RevocationRegistry, credx_revocation_registry_from_json);

impl_indy_object!(RevocationRegistryDelta, "RevocationRegistryDelta");
impl_indy_object_from_json!(
    RevocationRegistryDelta,
    credx_revocation_registry_delta_from_json
);

#[no_mangle]
pub extern "C" fn credx_create_or_update_revocation_state(
    rev_reg_def: ObjectHandle,
    rev_reg_delta: ObjectHandle,
    rev_reg_index: i64,
    timestamp: i64,
    tails_path: FfiStr,
    rev_state: ObjectHandle,
    rev_state_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(rev_state_p);
        let prev_rev_state = rev_state.opt_load()?;
        let tails_reader = TailsFileReader::new(
            tails_path
                .as_opt_str()
                .ok_or_else(|| err_msg!("Missing tails file path"))?,
        );
        let rev_state = create_or_update_revocation_state(
            tails_reader,
            rev_reg_def.load()?.cast_ref()?,
            rev_reg_delta.load()?.cast_ref()?,
            rev_reg_index
                .try_into()
                .map_err(|_| err_msg!("Invalid credential revocation index"))?,
            timestamp
                .try_into()
                .map_err(|_| err_msg!("Invalid timestamp"))?,
            prev_rev_state
                .as_ref()
                .map(IndyObject::cast_ref)
                .transpose()?,
        )?;
        let rev_state = ObjectHandle::create(rev_state)?;
        unsafe { *rev_state_p = rev_state };
        Ok(())
    })
}

impl_indy_object!(CredentialRevocationState, "CredentialRevocationState");
