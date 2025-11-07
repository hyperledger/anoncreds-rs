use super::error::{ErrorCode, catch_error};
use crate::services::prover::create_link_secret;
use ffi_support::rust_string_to_c;
use std::os::raw::c_char;

#[unsafe(no_mangle)]
pub extern "C" fn anoncreds_create_link_secret(link_secret_p: *mut *const c_char) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(link_secret_p);
        let secret = create_link_secret()?;
        let dec_secret: String = secret.try_into()?;
        unsafe { *link_secret_p = rust_string_to_c(dec_secret) };
        Ok(())
    })
}
