use std::os::raw::c_char;

use ffi_support::rust_string_to_c;

pub static LIB_VERSION: &str = env!("CARGO_PKG_VERSION");

ffi_support::define_string_destructor!(credx_string_free);

#[macro_use]
mod macros;

mod error;
use self::error::ErrorCode;

mod object;

mod schema;

#[no_mangle]
pub extern "C" fn credx_set_default_logger() -> ErrorCode {
    catch_err! {
        env_logger::init();
        debug!("Initialized default logger");
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn credx_version() -> *mut c_char {
    rust_string_to_c(LIB_VERSION.to_owned())
}
