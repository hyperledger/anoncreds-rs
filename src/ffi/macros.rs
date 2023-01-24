macro_rules! check_useful_c_ptr {
    ($e:expr) => {
        if ($e).is_null() {
            return Err(err_msg!(
                "Invalid pointer for result value: {}",
                stringify!($e)
            ));
        }
    };
}
