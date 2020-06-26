use std::convert::TryFrom;
use std::fmt;

#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize};

use crate::{ConversionError, ValidationError};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Nonce {
    value: String,
}

impl Nonce {
    #[cfg(any(feature = "cl", feature = "cl_native"))]
    pub fn new() -> Result<Self, ConversionError> {
        let val = crate::ursa::cl::new_nonce()
            .map_err(|err| ConversionError::from_msg(format!("Error creating nonce: {}", err)))?;
        Self::embed(&val)
    }

    pub fn from_dec<S: AsRef<str>>(value: S) -> Result<Self, ConversionError> {
        Self::validate(&value)?;
        Ok(Self {
            value: value.as_ref().to_string(),
        })
    }

    pub fn validate<S: AsRef<str>>(value: S) -> Result<(), ValidationError> {
        let strval = value.as_ref();
        if strval.is_empty() {
            return Err(ValidationError::from_msg("Invalid bignum: empty value"));
        }
        for c in strval.chars() {
            if c < '0' || c > '9' {
                return Err(ValidationError::from_msg("Invalid bignum value"));
            }
        }
        Ok(())
    }

    #[cfg(any(feature = "cl", feature = "cl_native"))]
    pub fn embed(value: &crate::ursa::cl::Nonce) -> Result<Self, ConversionError> {
        Ok(Self {
            value: value.to_dec()?,
        })
    }

    #[cfg(any(feature = "cl", feature = "cl_native"))]
    pub fn extract(&self) -> Result<crate::ursa::cl::Nonce, ConversionError> {
        crate::ursa::cl::Nonce::from_dec(&self.value).map_err(Into::into)
    }
}

impl From<i64> for Nonce {
    fn from(value: i64) -> Self {
        Self {
            value: value.to_string(),
        }
    }
}

impl From<u64> for Nonce {
    fn from(value: u64) -> Self {
        Self {
            value: value.to_string(),
        }
    }
}

impl TryFrom<&str> for Nonce {
    type Error = ConversionError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_dec(value)
    }
}

impl TryFrom<String> for Nonce {
    type Error = ConversionError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_dec(value)
    }
}

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.value.fmt(f)
    }
}

impl std::ops::Deref for Nonce {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

#[cfg(feature = "serde")]
impl<'a> Deserialize<'a> for Nonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        struct BigNumberVisitor;

        impl<'a> Visitor<'a> for BigNumberVisitor {
            type Value = Nonce;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("expected BigNumber")
            }

            fn visit_i64<E>(self, value: i64) -> Result<Nonce, E>
            where
                E: serde::de::Error,
            {
                Ok(Nonce::from(value))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Nonce, E>
            where
                E: serde::de::Error,
            {
                Ok(Nonce::from(value))
            }

            fn visit_str<E>(self, value: &str) -> Result<Nonce, E>
            where
                E: serde::de::Error,
            {
                Ok(Nonce::from_dec(value).map_err(E::custom)?)
            }
        }

        deserializer.deserialize_str(BigNumberVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_validate() {
        let valid = ["0", "1000000000000000000000000000000000"];
        for v in valid.iter() {
            assert!(Nonce::try_from(*v).is_ok())
        }

        let invalid = [
            "-1000000000000000000000000000000000",
            "-1",
            "notanumber",
            "",
            "-",
            "+1",
            "1a",
        ];
        for v in invalid.iter() {
            assert!(Nonce::try_from(*v).is_err())
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn nonce_serialize() {
        let val = Nonce::try_from("10000").unwrap();
        let ser = serde_json::to_string(&val).unwrap();
        assert_eq!(ser, "\"10000\"");
        let des = serde_json::from_str::<Nonce>(&ser).unwrap();
        assert_eq!(val, des);
    }

    #[cfg(all(feature = "serde", any(feature = "cl", feature = "cl_native")))]
    #[test]
    fn nonce_convert() {
        use crate::ursa::cl::Nonce as UNonce;

        let nonce = UNonce::new().unwrap();
        let ser = serde_json::to_string(&nonce).unwrap();
        let des = serde_json::from_str::<Nonce>(&ser).unwrap();
        let ser2 = serde_json::to_string(&des).unwrap();
        let nonce_des = serde_json::from_str::<UNonce>(&ser2).unwrap();
        assert_eq!(nonce, nonce_des);

        let nonce = Nonce::new().unwrap();
        let unonce = nonce.extract().unwrap();
        assert_eq!(nonce.to_string(), unonce.to_dec().unwrap());
    }
}
