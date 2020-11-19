use ffi_support::FfiStr;
use indy_utils::Qualifiable;

use super::error::{catch_error, ErrorCode};
use super::object::{IndyObjectId, ObjectHandle};
use crate::services::{
    issuer::create_revocation_registry,
    tails::TailsFileWriter,
    types::{
        DidValue, IssuanceType, RegistryType, RevocationRegistry, RevocationRegistryDefinition,
        RevocationRegistryDefinitionPrivate, RevocationRegistryId, RevocationState,
    },
};

#[no_mangle]
pub extern "C" fn credx_create_revocation_registry(
    origin_did: FfiStr,
    cred_def: ObjectHandle,
    tag: FfiStr,
    rev_reg_type: FfiStr,
    issuance_type: FfiStr,
    max_cred_num: u32,
    tails_dir_path: FfiStr,
    reg_def_p: *mut ObjectHandle,
    reg_def_private_p: *mut ObjectHandle,
    reg_entry_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(reg_def_p);
        check_useful_c_ptr!(reg_def_private_p);
        check_useful_c_ptr!(reg_entry_p);
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
        let (reg_def, reg_def_private, reg_entry) = create_revocation_registry(
            &origin_did,
            cred_def.load()?.cast_ref()?,
            tag,
            rev_reg_type,
            issuance_type,
            max_cred_num,
            &mut tails_writer,
        )?;
        let reg_def = ObjectHandle::create(reg_def)?;
        let reg_def_private = ObjectHandle::create(reg_def_private)?;
        let reg_entry = ObjectHandle::create(reg_entry)?;
        unsafe {
            *reg_def_p = reg_def;
            *reg_def_private_p = reg_def_private;
            *reg_entry_p = reg_entry;
        };
        Ok(())
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

impl_indy_object!(RevocationState, "RevocationState");
