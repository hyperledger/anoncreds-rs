/// Used to optionally add Serialize and Deserialize traits to Qualifiable types
#[macro_export]
macro_rules! serde_derive_impl {
    ($def:item) => {
        #[derive(Serialize, Deserialize)]
        $def
    };
}

/// Derive a new handle type having an atomically increasing sequence number
#[macro_export]
macro_rules! new_handle_type (($newtype:ident, $counter:ident) => (
    static $counter: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
    #[repr(transparent)]
    pub struct $newtype(pub usize);

    impl $newtype {
        #[allow(dead_code)]
        pub const fn invalid() -> $newtype {
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

    impl PartialEq<usize> for $newtype {
        fn eq(&self, other: &usize) -> bool {
            self.0 == *other
        }
    }

    impl $crate::utils::validation::Validatable for $newtype {
        fn validate(&self) -> std::result::Result<(), $crate::error::ValidationError> {
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

    #[test]
    fn test_handle_seq() {
        assert_eq!(TestHandle::next(), 1);
        assert_eq!(TestHandle::next(), 2);
    }
}
