use std::convert::TryFrom;
use std::fmt;
use std::hash::{Hash, Hasher};

use crate::ursa::cl::{new_nonce, Nonce as UrsaNonce};
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

use crate::data_types::ConversionError;

pub struct Nonce {
    strval: String,
    native: UrsaNonce,
}

impl Nonce {
    #[inline]
    pub fn new() -> Result<Self, ConversionError> {
        let native = new_nonce()
            .map_err(|err| ConversionError::from_msg(format!("Error creating nonce: {err}")))?;
        Self::from_native(native)
    }

    #[inline]
    pub fn from_native(native: UrsaNonce) -> Result<Self, ConversionError> {
        let strval = native.to_dec().map_err(|e| e.to_string())?;
        Ok(Self { strval, native })
    }

    #[inline]
    pub fn as_native(&self) -> &UrsaNonce {
        &self.native
    }

    #[inline]
    pub fn into_native(self) -> UrsaNonce {
        self.native
    }

    pub fn from_dec<S: Into<String>>(value: S) -> Result<Self, ConversionError> {
        let strval = value.into();
        if strval.is_empty() {
            return Err("Invalid bignum: empty value".into());
        }
        for c in strval.chars() {
            if !matches!(c, '0'..='9') {
                return Err("Invalid bignum value".into());
            }
        }

        let native = UrsaNonce::from_dec(&strval).map_err(|e| e.to_string())?;
        Ok(Self { strval, native })
    }

    pub fn try_clone(&self) -> Result<Self, ConversionError> {
        Self::from_dec(self.strval.clone())
    }
}

impl Hash for Nonce {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.strval.hash(state);
    }
}

impl PartialEq for Nonce {
    fn eq(&self, other: &Nonce) -> bool {
        self.strval == other.strval
    }
}

impl Eq for Nonce {}

impl TryFrom<i64> for Nonce {
    type Error = ConversionError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Self::from_dec(value.to_string())
    }
}

impl TryFrom<u64> for Nonce {
    type Error = ConversionError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::from_dec(value.to_string())
    }
}

impl TryFrom<u128> for Nonce {
    type Error = ConversionError;

    fn try_from(value: u128) -> Result<Self, Self::Error> {
        Self::from_dec(value.to_string())
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

impl AsRef<str> for Nonce {
    fn as_ref(&self) -> &str {
        &self.strval
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Nonce").field(&self.strval).finish()
    }
}

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.strval.fmt(f)
    }
}

impl std::ops::Deref for Nonce {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.strval
    }
}

impl Serialize for Nonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.strval)
    }
}

impl<'a> Deserialize<'a> for Nonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        struct BigNumberVisitor;

        impl<'a> Visitor<'a> for BigNumberVisitor {
            type Value = Nonce;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("integer or string nonce")
            }

            fn visit_i64<E>(self, value: i64) -> Result<Nonce, E>
            where
                E: serde::de::Error,
            {
                Nonce::try_from(value).map_err(E::custom)
            }

            fn visit_u64<E>(self, value: u64) -> Result<Nonce, E>
            where
                E: serde::de::Error,
            {
                Nonce::try_from(value).map_err(E::custom)
            }

            fn visit_u128<E>(self, value: u128) -> Result<Nonce, E>
            where
                E: serde::de::Error,
            {
                Nonce::try_from(value).map_err(E::custom)
            }

            fn visit_str<E>(self, value: &str) -> Result<Nonce, E>
            where
                E: serde::de::Error,
            {
                Nonce::from_dec(value).map_err(E::custom)
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

    #[test]
    fn nonce_serialize() {
        let val = Nonce::try_from("10000").unwrap();
        let ser = serde_json::to_string(&val).unwrap();
        assert_eq!(ser, "\"10000\"");
        let des = serde_json::from_str::<Nonce>(&ser).unwrap();
        assert_eq!(val, des);
    }

    #[test]
    fn nonce_convert() {
        let nonce = UrsaNonce::new().expect("Error creating nonce");
        let ser = serde_json::to_string(&nonce).unwrap();
        let des = serde_json::from_str::<Nonce>(&ser).unwrap();
        let ser2 = serde_json::to_string(&des).unwrap();
        let nonce_des = serde_json::from_str::<UrsaNonce>(&ser2).unwrap();
        assert_eq!(nonce, nonce_des);

        let nonce = Nonce::new().unwrap();
        let strval = nonce.to_string();
        let unonce = nonce.into_native();
        assert_eq!(strval, unonce.to_dec().unwrap());
    }
}
