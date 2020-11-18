use super::error::{catch_error, ErrorCode};
use super::object::ObjectHandle;
use crate::services::{prover::new_master_secret, types::MasterSecret};

#[no_mangle]
pub extern "C" fn credx_create_master_secret(master_secret_p: *mut ObjectHandle) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(master_secret_p);
        let secret = ObjectHandle::create(new_master_secret()?)?;
        unsafe { *master_secret_p = secret };
        Ok(())
    })
}

impl_indy_object!(MasterSecret, "MasterSecret");
impl_indy_object_from_json!(MasterSecret, credx_master_secret_from_json);
