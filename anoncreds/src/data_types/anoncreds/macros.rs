#[macro_export]
macro_rules! impl_anoncreds_object_identifier {
    ($i:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, Default)]
        pub struct $i(pub String);

        impl $i {
            pub fn new_unchecked(s: impl Into<String>) -> Self {
                Self(s.into())
            }

            pub fn new(s: impl Into<String>) -> Result<Self, $crate::data_types::ValidationError> {
                let s = Self(s.into());
                $crate::data_types::Validatable::validate(&s)?;
                Ok(s)
            }
        }

        impl $crate::data_types::Validatable for $i {
            fn validate(&self) -> Result<(), $crate::data_types::ValidationError> {
                if $crate::utils::validation::URI_IDENTIFIER
                    .captures(&self.0)
                    .is_some()
                {
                    return Ok(());
                }

                if $crate::utils::validation::LEGACY_IDENTIFIER
                    .captures(&self.0)
                    .is_some()
                {
                    return Ok(());
                }

                Err(indy_utils::invalid!(
                    "type: {}, identifier: {} is invalid. It MUST be a URI or legacy identifier.",
                    stringify!($i),
                    self.0
                ))
            }
        }

        impl From<$i> for String {
            fn from(i: $i) -> Self {
                i.0
            }
        }

        impl TryFrom<String> for $i {
            type Error = indy_utils::ValidationError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                $i::new(value)
            }
        }

        impl TryFrom<&str> for $i {
            type Error = indy_utils::ValidationError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
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
