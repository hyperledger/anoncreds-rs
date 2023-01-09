/// Thin wrapper for the issuer id. This can also be implemented with the
/// `impl_anoncreds_object_identifier` if we need validation for URI's.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct IssuerId(String);

impl From<String> for IssuerId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for IssuerId {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl From<IssuerId> for String {
    fn from(i: IssuerId) -> Self {
        i.0
    }
}
