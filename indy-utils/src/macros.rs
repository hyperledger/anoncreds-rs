macro_rules! unwrap_opt_or_return {
    ($opt:expr, $err:expr) => {
        match $opt {
            Some(val) => val,
            None => return $err,
        };
    };
}

/// Used to optionally add Serialize and Deserialize traits to Qualifiable types
#[cfg(feature = "serde")]
#[macro_export]
macro_rules! serde_derive_impl {
    ($def:item) => {
        #[derive(Serialize, Deserialize)]
        $def
    };
}

#[cfg(not(feature = "serde"))]
#[macro_export]
macro_rules! serde_derive_impl {
    ($def:item) => {
        $def
    };
}

/// Derive a new handle type having an atomically increasing sequence number
#[macro_export]
macro_rules! new_handle_type (($newtype:ident, $counter:ident) => (
    static $counter: $crate::once_cell::sync::Lazy<std::sync::atomic::AtomicUsize>
        = $crate::once_cell::sync::Lazy::new(|| std::sync::atomic::AtomicUsize::new(0));

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

    impl $crate::Validatable for $newtype {
        fn validate(&self) -> Result<(), $crate::ValidationError> {
            if(**self == 0) {
                Err("Invalid handle: zero".into())
            } else {
                Ok(())
            }
        }
    }
));

#[cfg(test)]
mod tests {
    new_handle_type!(TestHandle, TEST_HANDLE_CTR);
}
