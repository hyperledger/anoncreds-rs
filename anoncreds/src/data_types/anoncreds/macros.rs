#[macro_export]
macro_rules! impl_anoncreds_object_identifier {
    ($i:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, Default)]
        pub struct $i(pub String);

        impl $i {
            pub fn new(s: impl Into<String>) -> Self {
                Self(s.into())
            }

            pub fn validated_new(
                s: impl Into<String>,
            ) -> Result<Self, crate::data_types::ValidationError> {
                let s = Self(s.into());
                s.validate()?;
                Ok(s)
            }
        }

        impl crate::data_types::Validatable for $i {
            fn validate(&self) -> Result<(), crate::data_types::ValidationError> {
                // TODO: better URI regex
                let uri_regex = regex::Regex::new(r".*").unwrap();
                uri_regex
                    .captures(&self.0)
                    .ok_or_else(|| {
                        indy_utils::invalid!(
                            "type: {}, identifier: {} is invalid. It MUST be a URI.",
                            stringify!($i),
                            self.0
                        )
                    })
                    .map(|_| ())
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
