#[cfg(test)]
macro_rules! assert_kind {
    ($kind:ident, $var:expr) => {
        match $var {
            Err(e) => assert_eq!($crate::error::ErrorKind::$kind, e.kind()),
            _ => assert!(false, "Result expected to be error"),
        }
    };
}

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
