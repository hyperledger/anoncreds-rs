use std::convert::TryFrom;
use std::fmt;

use serde::{de::Visitor, Deserialize, Deserializer, Serialize};

use crate::{ConversionError, ValidationError};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct BigNumber {
    value: String,
}

impl BigNumber {
    pub fn from_dec<S: AsRef<str>>(value: S) -> Result<Self, ConversionError> {
        Self::validate(&value)?;
        Ok(Self {
            value: value.as_ref().to_string(),
        })
    }

    pub fn validate<S: AsRef<str>>(value: S) -> Result<(), ValidationError> {
        let strval = value.as_ref();
        if strval.is_empty() || strval == "-" {
            return Err(ValidationError::from_msg("Invalid bignum: empty value"));
        }
        for (idx, c) in strval.chars().enumerate() {
            if (c < '0' || c > '9') && (idx > 0 || c != '-') {
                return Err(ValidationError::from_msg("Invalid bignum value"));
            }
        }
        Ok(())
    }
}

impl From<i64> for BigNumber {
    fn from(value: i64) -> Self {
        Self {
            value: value.to_string(),
        }
    }
}

impl From<u64> for BigNumber {
    fn from(value: u64) -> Self {
        Self {
            value: value.to_string(),
        }
    }
}

impl TryFrom<&str> for BigNumber {
    type Error = ConversionError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_dec(value)
    }
}

impl TryFrom<String> for BigNumber {
    type Error = ConversionError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_dec(value)
    }
}

impl fmt::Display for BigNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.value.fmt(f)
    }
}

impl std::ops::Deref for BigNumber {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

#[cfg(feature = "serde")]
impl<'a> Deserialize<'a> for BigNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        struct BigNumberVisitor;

        impl<'a> Visitor<'a> for BigNumberVisitor {
            type Value = BigNumber;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("expected BigNumber")
            }

            fn visit_i64<E>(self, value: i64) -> Result<BigNumber, E>
            where
                E: serde::de::Error,
            {
                Ok(BigNumber::from(value))
            }

            fn visit_u64<E>(self, value: u64) -> Result<BigNumber, E>
            where
                E: serde::de::Error,
            {
                Ok(BigNumber::from(value))
            }

            fn visit_str<E>(self, value: &str) -> Result<BigNumber, E>
            where
                E: serde::de::Error,
            {
                Ok(BigNumber::from_dec(value).map_err(E::custom)?)
            }
        }

        deserializer.deserialize_str(BigNumberVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bignum_validate() {
        let valid = [
            "-1000000000000000000000000000000000",
            "-1",
            "0",
            "1000000000000000000000000000000000",
        ];
        for v in valid.iter() {
            assert!(BigNumber::try_from(*v).is_ok())
        }

        let invalid = ["notanumber", "", "-", "+1", "1a"];
        for v in invalid.iter() {
            assert!(BigNumber::try_from(*v).is_err())
        }
    }

    #[test]
    fn bignum_serialize() {
        let val = BigNumber::try_from("10000").unwrap();
        let ser = serde_json::to_string(&val).unwrap();
        assert_eq!(ser, "\"10000\"");
        let des = serde_json::from_str::<BigNumber>(&ser).unwrap();
        assert_eq!(val, des);
    }

    #[cfg(any(feature = "cl", feature = "cl_native"))]
    #[test]
    fn bignum_convert() {
        use crate::ursa::cl::Nonce;

        let nonce = Nonce::new().unwrap();
        let ser = serde_json::to_string(&nonce).unwrap();
        let des = serde_json::from_str::<BigNumber>(&ser).unwrap();
        let ser2 = serde_json::to_string(&des).unwrap();
        let nonce_des = serde_json::from_str::<Nonce>(&ser2).unwrap();
        assert_eq!(nonce, nonce_des);
    }
}
