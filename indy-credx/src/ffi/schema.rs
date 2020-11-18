use std::os::raw::c_char;

use ffi_support::{rust_string_to_c, FfiStr};
use indy_utils::Qualifiable;

use super::error::{catch_error, ErrorCode};
use super::object::{IndyObjectId, ObjectHandle};
use super::util::FfiStrList;
use crate::services::{
    issuer::new_schema,
    types::{DidValue, Schema, SchemaId},
};

#[no_mangle]
pub extern "C" fn credx_create_schema(
    origin_did: FfiStr,
    schema_name: FfiStr,
    schema_version: FfiStr,
    attr_names: FfiStrList,
    seq_no: i64,
    result_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(result_p);
        let origin_did = DidValue::from_str(origin_did.as_str())?;
        let schema = new_schema(
            &origin_did,
            schema_name.as_str(),
            schema_version.as_str(),
            attr_names.to_string_vec()?.into(),
            if seq_no > 0 {
                Some(seq_no as u32)
            } else {
                None
            },
        )?;
        let handle = ObjectHandle::create(schema)?;
        unsafe { *result_p = handle };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn credx_schema_get_id(
    handle: ObjectHandle,
    result_p: *mut *const c_char,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(result_p);
        let schema = handle.load()?;
        let id = match schema.cast_ref::<Schema>()? {
            Schema::SchemaV1(s) => s.id.to_string(),
        };
        unsafe { *result_p = rust_string_to_c(id) };
        Ok(())
    })
}

impl_indy_object!(Schema, "Schema");
impl_indy_object_from_json!(Schema, credx_schema_from_json);

impl IndyObjectId for Schema {
    type Id = SchemaId;

    fn get_id(&self) -> Self::Id {
        match self {
            Schema::SchemaV1(s) => s.id.clone(),
        }
    }
}
