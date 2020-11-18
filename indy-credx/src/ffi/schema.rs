use ffi_support::FfiStr;
use indy_utils::Qualifiable;

use super::error::ErrorCode;
use super::object::ObjectHandle;
use crate::services::{issuer::new_schema, types::DidValue};

#[no_mangle]
pub extern "C" fn credx_create_schema(
    origin_did: FfiStr,
    schema_name: FfiStr,
    schema_version: FfiStr,
    attr_names: FfiStr,
    seq_no: i64,
    result_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_err! {
        check_useful_c_ptr!(result_p);
        let origin_did = DidValue::from_str(origin_did.as_str())?;
        let attr_names = serde_json::from_str(attr_names.as_str())?;
        let schema = new_schema(
            &origin_did,
            schema_name.as_str(),
            schema_version.as_str(),
            attr_names,
            if seq_no > 0 { Some(seq_no as u32) } else { None } )?;
        let handle = ObjectHandle::create(schema)?;
        unsafe { *result_p = handle };
        Ok(ErrorCode::Success)
    }
}
