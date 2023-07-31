use ffi_support::FfiStr;

use super::error::{catch_error, ErrorCode};
use super::object::ObjectHandle;
use super::util::FfiStrList;
use crate::data_types::schema::Schema;
use crate::services::issuer::create_schema;

#[no_mangle]
pub extern "C" fn anoncreds_create_schema(
    schema_name: FfiStr,
    schema_version: FfiStr,
    issuer_id: FfiStr,
    attr_names: FfiStrList,
    result_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(result_p);
        let schema_name = schema_name
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing schema name"))?;
        let schema_version = schema_version
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing schema version"))?;
        let issuer_id = issuer_id
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing issuer_id"))?
            .try_into()?;
        let schema = create_schema(
            schema_name,
            schema_version,
            issuer_id,
            attr_names.to_string_vec()?.into(),
        )?;
        let handle = ObjectHandle::create(schema)?;
        unsafe { *result_p = handle };
        Ok(())
    })
}

impl_anoncreds_object!(Schema, "Schema");
impl_anoncreds_object_from_json!(Schema, anoncreds_schema_from_json);
