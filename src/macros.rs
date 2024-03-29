#[cfg(debug_assertions)]
macro_rules! secret {
    ($val:expr) => {{
        $val
    }};
}

#[cfg(not(debug_assertions))]
macro_rules! secret {
    ($val:expr) => {{
        "_"
    }};
}
