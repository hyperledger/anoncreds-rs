use std::os::raw::c_char;

use ffi_support::{ByteBuffer, rust_string_to_c};
use zeroize::Zeroize;

pub static LIB_VERSION: &str = env!("CARGO_PKG_VERSION");

ffi_support::define_string_destructor!(anoncreds_string_free);

#[unsafe(no_mangle)]
pub extern "C" fn anoncreds_buffer_free(buffer: ByteBuffer) {
    ffi_support::abort_on_panic::with_abort_on_panic(|| {
        buffer.destroy_into_vec().zeroize();
    });
}

#[macro_use]
mod macros;

mod error;
use self::error::{ErrorCode, catch_error};

#[macro_use]
mod object;

mod util;

mod cred_def;
mod cred_offer;
mod cred_req;
mod credential;
mod link_secret;
mod pres_req;
mod presentation;
mod revocation;
mod schema;

#[cfg(feature = "w3c")]
mod w3c;

#[unsafe(no_mangle)]
pub extern "C" fn anoncreds_set_default_logger() -> ErrorCode {
    catch_error(|| {
        env_logger::init();
        debug!("Initialized default logger");
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn anoncreds_version() -> *mut c_char {
    rust_string_to_c(LIB_VERSION.to_owned())
}
