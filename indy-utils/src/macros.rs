#[macro_export]
macro_rules! unwrap_opt_or_return {
    ($opt:expr, $err:expr) => {
        match $opt {
            Some(val) => val,
            None => return $err,
        };
    };
}

#[macro_export]
macro_rules! unwrap_or_return {
    ($result:expr, $err:expr) => {
        match $result {
            Ok(res) => res,
            Err(_) => return $err,
        };
    };
}

#[macro_export]
macro_rules! unwrap_or_map_return {
    ($result:expr, $on_err:expr) => {
        match $result {
            Ok(res) => res,
            Err(err) => return ($on_err)(err),
        };
    };
}

#[macro_export]
macro_rules! in_closure {
    ($($e:tt)*) => {(|| -> Result<_, _> {$($e)*})()}
}

#[macro_export]
macro_rules! assert_match {
    ($pattern:pat, $var:expr) => {
        assert!(match $var {
            $pattern => true,
            _ => false,
        })
    };
    ($pattern:pat, $var:expr, $val_in_pattern:ident, $exp_value:expr) => {
        assert!(match $var {
            $pattern => $val_in_pattern == $exp_value,
            _ => false,
        })
    };
    ($pattern:pat, $var:expr, $val_in_pattern1:ident, $exp_value1:expr, $val_in_pattern2:ident, $exp_value2:expr) => {
        assert!(match $var {
            $pattern => $val_in_pattern1 == $exp_value1 && $val_in_pattern2 == $exp_value2,
            _ => false,
        })
    };
}

#[macro_export]
macro_rules! assert_kind {
    ($kind:expr, $var:expr) => {
        match $var {
            Err(e) => assert_eq!($kind, e.kind()),
            _ => assert!(false, "Result expected to be error"),
        }
    };
}

#[macro_export]
macro_rules! new_handle_type (($newtype:ident, $counter:ident) => (

    lazy_static! {
        static ref $counter: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct $newtype(pub usize);

    impl $newtype {
        #[allow(dead_code)]
        pub fn invalid() -> $newtype {
            $newtype(0)
        }
        #[allow(dead_code)]
        pub fn next() -> $newtype {
            $newtype($counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1)
        }
    }

    #[cfg(feature="std")]
    impl std::fmt::Display for $newtype {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}({})", stringify!($newtype), self.0)
        }
    }

    impl std::ops::Deref for $newtype {
        type Target = usize;
        fn deref(&self) -> &usize {
            &self.0
        }
    }
));

#[cfg(test)]
mod tests {
    new_handle_type!(TestHandle, TEST_HANDLE_CTR);
}
