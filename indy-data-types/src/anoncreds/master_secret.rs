use std::convert::TryFrom;
use std::fmt;

#[cfg(any(feature = "cl", feature = "cl_native"))]
use crate::ursa::cl::{prover::Prover as UrsaProver, MasterSecret as UrsaMasterSecret};
#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

use crate::ConversionError;

pub struct MasterSecret {
    strval: String,
    #[cfg(any(feature = "cl", feature = "cl_native"))]
    native: UrsaMasterSecret,
}

impl MasterSecret {
    #[cfg(any(feature = "cl", feature = "cl_native"))]
    #[inline]
    pub fn new() -> Result<Self, ConversionError> {
        let native = UrsaProver::new_master_secret().map_err(|err| {
            ConversionError::from_msg(format!("Error creating master secret: {}", err))
        })?;
        Self::from_native(native)
    }

    #[cfg(any(feature = "cl", feature = "cl_native"))]
    #[inline]
    pub fn from_native(native: UrsaMasterSecret) -> Result<Self, ConversionError> {
        let strval = {
            match serde_json::to_value(&native)? {
                serde_json::Value::String(s) => s,
                _ => return Err(ConversionError::from_msg("Expected serialized string")),
            }
        };
        Ok(Self { strval, native })
    }

    #[cfg(any(feature = "cl", feature = "cl_native"))]
    #[inline]
    pub fn as_native(&self) -> &UrsaMasterSecret {
        &self.native
    }

    #[cfg(any(feature = "cl", feature = "cl_native"))]
    #[inline]
    pub fn into_native(self) -> UrsaMasterSecret {
        self.native
    }

    #[cfg(any(feature = "cl", feature = "cl_native"))]
    pub fn from_dec<S: Into<String>>(value: S) -> Result<Self, ConversionError> {
        let strval = value.into();
        let native = serde_json::from_value(serde_json::Value::String(strval.clone()))?;
        Ok(Self { strval, native })
    }

    #[cfg(not(any(feature = "cl", feature = "cl_native")))]
    pub fn from_dec<S: Into<String>>(value: S) -> Result<Self, ConversionError> {
        let strval = value.into();
        if strval.is_empty() {
            return Err("Invalid bignum: empty value".into());
        }
        for c in strval.chars() {
            if c < '0' || c > '9' {
                return Err("Invalid bignum value".into());
            }
        }
        Ok(Self { strval })
    }

    pub fn try_clone(&self) -> Result<Self, ConversionError> {
        Self::from_dec(self.strval.clone())
    }
}

impl PartialEq for MasterSecret {
    fn eq(&self, other: &MasterSecret) -> bool {
        self.strval == other.strval
    }
}

impl Eq for MasterSecret {}

impl TryFrom<i64> for MasterSecret {
    type Error = ConversionError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Self::from_dec(value.to_string())
    }
}

impl TryFrom<u64> for MasterSecret {
    type Error = ConversionError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::from_dec(value.to_string())
    }
}

impl TryFrom<&str> for MasterSecret {
    type Error = ConversionError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_dec(value)
    }
}

impl TryFrom<String> for MasterSecret {
    type Error = ConversionError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_dec(value)
    }
}

impl fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("MasterSecret")
            .field(if cfg!(test) {
                &self.strval
            } else {
                &"<hidden>"
            })
            .finish()
    }
}

#[cfg(feature = "serde")]
impl Serialize for MasterSecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.strval.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'a> Deserialize<'a> for MasterSecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        struct BigNumberVisitor;

        impl<'a> Visitor<'a> for BigNumberVisitor {
            type Value = MasterSecret;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("expected BigNumber")
            }

            fn visit_i64<E>(self, value: i64) -> Result<MasterSecret, E>
            where
                E: serde::de::Error,
            {
                Ok(MasterSecret::try_from(value).map_err(E::custom)?)
            }

            fn visit_u64<E>(self, value: u64) -> Result<MasterSecret, E>
            where
                E: serde::de::Error,
            {
                Ok(MasterSecret::try_from(value).map_err(E::custom)?)
            }

            fn visit_str<E>(self, value: &str) -> Result<MasterSecret, E>
            where
                E: serde::de::Error,
            {
                Ok(MasterSecret::from_dec(value).map_err(E::custom)?)
            }
        }

        deserializer.deserialize_str(BigNumberVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_secret_validate() {
        let valid = ["0", "1000000000000000000000000000000000"];
        for v in valid.iter() {
            assert!(MasterSecret::try_from(*v).is_ok())
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
            assert!(MasterSecret::try_from(*v).is_err())
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn master_secret_serialize() {
        let val = MasterSecret::try_from("10000").unwrap();
        let ser = serde_json::to_string(&val).unwrap();
        assert_eq!(ser, "\"10000\"");
        let des = serde_json::from_str::<MasterSecret>(&ser).unwrap();
        assert_eq!(val, des);
    }

    #[cfg(all(feature = "serde", any(feature = "cl", feature = "cl_native")))]
    #[test]
    fn master_secret_convert() {
        let secret = MasterSecret::new().expect("Error creating master secret");
        let ser = serde_json::to_string(&secret).unwrap();
        let des = serde_json::from_str::<UrsaMasterSecret>(&ser).unwrap();
        let secret2 = MasterSecret::from_native(des).unwrap();
        assert_eq!(secret, secret2);
    }
}
