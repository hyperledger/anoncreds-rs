#[macro_export]
macro_rules! impl_anoncreds_object_identifier {
    ($i:ident) => {
        use once_cell::sync::Lazy;
        use regex::Regex;

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
                // TODO: stricten the URI regex.
                // Right now everything after the first colon is allowed,
                // we might want to restrict this
                static REGEX_URI: Lazy<Regex> =
                    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9\+\-\.]+:.+$").unwrap());

                /// base58 alpahet as defined in
                /// https://datatracker.ietf.org/doc/html/draft-msporny-base58#section-2
                /// This is used for legacy indy identifiers that we will keep supporting for
                /// backwards compatibility. This might validate invalid identifiers if they happen
                /// to fall within the base58 alphabet, but there is not much we can do about that.
                static LEGACY_IDENTIFIER: Lazy<Regex> =
                    Lazy::new(|| Regex::new("^[1-9A-HJ-NP-Za-km-z]{21,22}$").unwrap());

                if REGEX_URI.captures(&self.0).is_some() {
                    return Ok(());
                }

                if LEGACY_IDENTIFIER.captures(&self.0).is_some() {
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
