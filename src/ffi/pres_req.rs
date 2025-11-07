use std::os::raw::c_char;

use ffi_support::rust_string_to_c;

use super::error::{catch_error, ErrorCode};
use crate::services::{types::PresentationRequest, verifier::generate_nonce};

impl_anoncreds_object!(PresentationRequest, "PresentationRequest");
impl_anoncreds_object_from_json!(
    PresentationRequest,
    anoncreds_presentation_request_from_json
);

#[unsafe(no_mangle)]
pub extern "C" fn anoncreds_generate_nonce(nonce_p: *mut *const c_char) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(nonce_p);
        let nonce = generate_nonce()?.to_string();
        unsafe { *nonce_p = rust_string_to_c(nonce) };
        Ok(())
    })
}
