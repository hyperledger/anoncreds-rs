macro_rules! catch_err {
    ($($e:tt)*) => {
        match std::panic::catch_unwind(move || -> $crate::error::Result<_> {$($e)*}) {
            Ok(Ok(a)) => a,
            Ok(Err(err)) => { // lib error
                $crate::ffi::error::set_last_error(Some(err))
            }
            Err(_) => { // panic error
                let err: $crate::error::Error = err_msg!(Unexpected, "Panic during execution");
                $crate::ffi::error::set_last_error(Some(err))
            }
        }
    }
}

macro_rules! check_useful_c_ptr {
    ($e:expr) => {
        if ($e).is_null() {
            return Err(err_msg!("Invalid pointer for result value"));
        }
    };
}
