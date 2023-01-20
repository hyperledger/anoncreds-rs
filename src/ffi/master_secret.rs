use super::error::{catch_error, ErrorCode};
use super::object::ObjectHandle;
use crate::services::{prover::create_master_secret, types::MasterSecret};

#[no_mangle]
pub extern "C" fn anoncreds_create_master_secret(master_secret_p: *mut ObjectHandle) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(master_secret_p);
        let secret = ObjectHandle::create(create_master_secret()?)?;
        unsafe { *master_secret_p = secret };
        Ok(())
    })
}

impl_anoncreds_object!(MasterSecret, "MasterSecret");
impl_anoncreds_object_from_json!(MasterSecret, anoncreds_master_secret_from_json);
