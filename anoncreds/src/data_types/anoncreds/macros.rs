#[macro_export]
macro_rules! impl_anoncreds_object_identifier {
    ($i:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, Default)]
        pub struct $i(pub String);

        impl $i {
            pub fn new(s: impl Into<String>) -> Self {
                Self(s.into())
            }
        }

        impl Into<String> for $i {
            fn into(self) -> String {
                self.0
            }
        }

        impl From<String> for $i {
            fn from(value: String) -> Self {
                $i::new(value)
            }
        }

        impl From<&str> for $i {
            fn from(value: &str) -> Self {
                $i::new(value.to_owned())
            }
        }

        impl std::fmt::Display for $i {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}
