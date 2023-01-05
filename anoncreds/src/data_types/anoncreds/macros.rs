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
                // TODO: stricten the URI regex.
                // Right now everything after the first colon is allowed, we might want to restrict
                // this
                let uri_regex = regex::Regex::new(r"^[a-zA-Z0-9\+\-\.]+:.+$").unwrap();
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

#[test]
fn regex_validation() {
    impl_anoncreds_object_identifier!(MockId);
    assert!(MockId::new("foo:bar").is_ok());
    assert!(MockId::new("did:sov:NcYxiDXkpYi6ov5FcYDi1e").is_ok());
    assert!(MockId::new("foo://example.com:8042/over/there?name=ferret#nose").is_ok());
    assert!(MockId::new("did:key:zUC7H7TxvhWmvfptpu2zSwo5EZ1kr3MPNsjovaD2ipbuzj").is_ok());
    assert!(MockId::new("did:key:zUC72to2eJiFMrt8a89LoaEPHC76QcfAxQdFys3nFGCmDK").is_ok());
    assert!(MockId::new("did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmg").is_ok());

    assert!(MockId::new("foo").is_err());
    assert!(MockId::new("bar").is_err());
    assert!(MockId::new("foo:").is_err());
    assert!(MockId::new("zUC7H7TxvhWmvfptpu2zSwo5EZ1kr3MPNsjovaD2ipbuzj").is_err());
    assert!(MockId::new("zUC72to2eJiFMrt8a89LoaEPHC76QcfAxQdFys3nFGCmDK").is_err());
    assert!(MockId::new("z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmg").is_err());
}
