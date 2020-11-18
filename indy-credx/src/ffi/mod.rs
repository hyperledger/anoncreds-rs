use std::os::raw::c_char;

use ffi_support::rust_string_to_c;

pub static LIB_VERSION: &str = env!("CARGO_PKG_VERSION");

ffi_support::define_string_destructor!(credx_string_free);

#[macro_use]
mod macros;

mod error;
use self::error::{catch_error, ErrorCode};

#[macro_use]
mod object;

mod util;

mod cred;
mod cred_def;
mod cred_offer;
mod cred_req;
mod master_secret;
mod schema;

#[no_mangle]
pub extern "C" fn credx_set_default_logger() -> ErrorCode {
    catch_error(|| {
        env_logger::init();
        debug!("Initialized default logger");
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn credx_version() -> *mut c_char {
    rust_string_to_c(LIB_VERSION.to_owned())
}
