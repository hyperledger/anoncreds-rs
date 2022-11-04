use crate::error::{Error, ErrorKind, Result};

use std::os::raw::c_char;
use std::panic::{catch_unwind, UnwindSafe};
use std::sync::RwLock;

use ffi_support::rust_string_to_c;

use once_cell::sync::Lazy;

static LAST_ERROR: Lazy<RwLock<Option<Error>>> = Lazy::new(|| RwLock::new(None));

#[derive(Debug, PartialEq, Copy, Clone, Serialize)]
#[repr(usize)]
pub enum ErrorCode {
    Success = 0,
    Input = 1,
    IOError = 2,
    InvalidState = 3,
    Unexpected = 4,
    CredentialRevoked = 5,
    InvalidUserRevocId = 6,
    ProofRejected = 7,
    RevocationRegistryFull = 8,
}

impl From<ErrorKind> for ErrorCode {
    fn from(kind: ErrorKind) -> ErrorCode {
        match kind {
            ErrorKind::Input => ErrorCode::Input,
            ErrorKind::IOError => ErrorCode::IOError,
            ErrorKind::InvalidState => ErrorCode::InvalidState,
            ErrorKind::Unexpected => ErrorCode::Unexpected,
            ErrorKind::CredentialRevoked => ErrorCode::CredentialRevoked,
            ErrorKind::InvalidUserRevocId => ErrorCode::InvalidUserRevocId,
            ErrorKind::ProofRejected => ErrorCode::ProofRejected,
            ErrorKind::RevocationRegistryFull => ErrorCode::RevocationRegistryFull,
        }
    }
}

impl<T> From<Result<T>> for ErrorCode {
    fn from(result: Result<T>) -> ErrorCode {
        match result {
            Ok(_) => ErrorCode::Success,
            Err(err) => ErrorCode::from(err.kind()),
        }
    }
}

#[no_mangle]
pub extern "C" fn credx_get_current_error(error_json_p: *mut *const c_char) -> ErrorCode {
    trace!("credx_get_current_error");

    let error = rust_string_to_c(get_current_error_json());
    unsafe { *error_json_p = error };

    ErrorCode::Success
}

pub fn catch_error<F>(f: F) -> ErrorCode
where
    F: FnOnce() -> Result<()> + UnwindSafe,
{
    match catch_unwind(f) {
        Ok(Ok(_)) => ErrorCode::Success,
        Ok(Err(err)) => {
            // lib error
            set_last_error(Some(err))
        }
        Err(_) => {
            // panic error
            let err = err_msg!(Unexpected, "Panic during execution");
            set_last_error(Some(err))
        }
    }
}

pub fn get_current_error_json() -> String {
    if let Some(err) = Option::take(&mut *LAST_ERROR.write().unwrap()) {
        let message = err.to_string();
        let code = ErrorCode::from(err.kind()) as usize;
        serde_json::json!({"code": code, "message": message}).to_string()
    } else {
        r#"{"code":0,"message":null}"#.to_owned()
    }
}

pub fn set_last_error(error: Option<Error>) -> ErrorCode {
    trace!("credx_set_last_error");
    let code = match error.as_ref() {
        Some(err) => err.kind().into(),
        None => ErrorCode::Success,
    };
    *LAST_ERROR.write().unwrap() = error;
    code
}
