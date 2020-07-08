use once_cell::sync::Lazy;

use regex::Regex;

use super::{Validatable, ValidationError};

pub(crate) static REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new("^([a-z0-9]+):([a-z0-9]+):(.*)$").unwrap());

/// Combine a prefix, method, and value into a qualified identifier
pub fn combine(prefix: &str, method: Option<&str>, entity: &str) -> String {
    match method {
        Some(method) => format!("{}:{}:{}", prefix, method, entity),
        _ => entity.to_owned(),
    }
}

/// Split a qualifiable identifier into its method and value components
pub fn split<'a>(prefix: &str, val: &'a str) -> (Option<&'a str>, &'a str) {
    match REGEX.captures(&val) {
        None => (None, val),
        Some(caps) => {
            if caps.get(1).map(|m| m.as_str()) == Some(prefix) {
                (
                    Some(caps.get(2).unwrap().as_str()),
                    caps.get(3).unwrap().as_str(),
                )
            } else {
                (None, val)
            }
        }
    }
}

/// Check if an identifier is qualified by a prefix and method
pub fn is_fully_qualified(entity: &str) -> bool {
    REGEX.captures(entity).is_some()
}

/// An identifier which can be qualified with a prefix and method
pub trait Qualifiable: From<String> + std::ops::Deref<Target = str> + Validatable {
    fn prefix() -> &'static str;

    fn combine(method: Option<&str>, entity: &str) -> Self {
        Self::from(combine(Self::prefix(), method, entity))
    }

    fn split<'a>(&'a self) -> (Option<&'a str>, &'a str) {
        split(Self::prefix(), self.deref())
    }

    fn get_method<'a>(&'a self) -> Option<&'a str> {
        let (method, _rest) = self.split();
        method
    }

    fn default_method(&self, method: Option<&str>) -> Self {
        let (prev_method, rest) = self.split();
        match prev_method {
            Some(_) => Self::from(self.to_string()),
            None => Self::combine(method, rest),
        }
    }

    fn replace_method(&self, method: Option<&str>) -> Self {
        let (_method, rest) = self.split();
        Self::combine(method, rest)
    }

    fn remove_method(&self, method: &str) -> Self {
        let (prev_method, rest) = self.split();
        if prev_method == Some(method) {
            Self::combine(None, rest)
        } else {
            Self::from(self.to_string())
        }
    }

    fn from_str(entity: &str) -> Result<Self, ValidationError> {
        let result = Self::from(entity.to_owned());
        result.validate()?;
        Ok(result)
    }

    fn is_fully_qualified(&self) -> bool {
        self.get_method().is_some()
    }

    fn to_qualified(&self, method: &str) -> Result<Self, ValidationError> {
        match self.split() {
            (None, rest) => Ok(Self::combine(Some(method), rest)),
            (Some(prev_method), rest) if prev_method == method => {
                Ok(Self::combine(Some(method), rest))
            }
            _ => Err(ValidationError::from(
                "Identifier is already qualified with another method",
            )),
        }
    }

    fn to_unqualified(&self) -> Self {
        let (_, rest) = self.split();
        Self::from(rest.to_owned())
    }
}

/// Derive a new `Qualifiable` string type
#[macro_export]
macro_rules! qualifiable_type {
    ($newtype:ident, $doc:expr) => {
        $crate::serde_derive_impl! {
            #[doc=$doc]
            #[derive(Debug, Clone, PartialEq, Eq, Hash)]
            pub struct $newtype(pub String);
        }

        impl From<String> for $newtype {
            fn from(val: String) -> Self {
                Self(val)
            }
        }

        impl std::ops::Deref for $newtype {
            type Target = str;
            fn deref(&self) -> &str {
                &self.0
            }
        }
    };
    ($newtype:ident) => {
        qualifiable_type!($newtype, "");
    };
}
