use std::convert::TryFrom;
use std::fmt;
use std::ops::Deref;

#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize};

use crate::{ConversionError, ValidationError};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct GroupOrderElement {
    value: String,
}

impl GroupOrderElement {
    pub fn from_hex<S: AsRef<str>>(value: S) -> Result<Self, ConversionError> {
        Self::validate(&value)?;
        Ok(Self {
            value: value.as_ref().to_string(),
        })
    }

    pub fn validate<S: AsRef<str>>(value: S) -> Result<(), ValidationError> {
        let val = value.as_ref();
        if val.len() != 64 {
            return Err(ValidationError::from_msg(
                "Invalid point length: expected 64 characters",
            ));
        }
        for c in val.chars() {
            if (c < '0' || c > '9') && (c < 'A' || c > 'F') && (c < 'a' || c > 'f') {
                return Err(ValidationError::from_msg("Invalid point hex value"));
            }
        }
        Ok(())
    }
}

#[cfg(any(feature = "cl", feature = "cl_native"))]
impl super::ToUrsa for GroupOrderElement {
    type UrsaType = crate::ursa::pair::GroupOrderElement;

    fn to_ursa(&self) -> Result<Self::UrsaType, ConversionError> {
        Self::UrsaType::from_string(&self.value).map_err(Into::into)
    }
}

impl TryFrom<&str> for GroupOrderElement {
    type Error = ConversionError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_hex(value)
    }
}

impl TryFrom<String> for GroupOrderElement {
    type Error = ConversionError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_hex(value)
    }
}

impl fmt::Display for GroupOrderElement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.value.fmt(f)
    }
}

impl Deref for GroupOrderElement {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

#[cfg(feature = "serde")]
impl<'a> Deserialize<'a> for GroupOrderElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        struct EltVisitor;

        impl<'a> Visitor<'a> for EltVisitor {
            type Value = GroupOrderElement;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("expected GroupOrderElement")
            }

            fn visit_str<E>(self, value: &str) -> Result<GroupOrderElement, E>
            where
                E: serde::de::Error,
            {
                Ok(GroupOrderElement::from_hex(value).map_err(E::custom)?)
            }
        }

        deserializer.deserialize_str(EltVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_elt_validate() {
        assert!(GroupOrderElement::try_from(
            "1060F1BCEDC3EB2A59075D3C56687837F2EFFD4E7D53254F49D633618C187E06"
        )
        .is_ok());

        let invalid = [
            "",
            "notanumber",
            "1060F1BCEDC3EB",
            " 1060F1BCEDC3EB2A59075D3C56687837F2EFFD4E7D53254F49D633618C187E06",
            "1060F1BCEDC3EB2A59075D3C56687837F2EFFD4E7D53254F49D633618C187E06aaaa",
        ];
        for v in invalid.iter() {
            assert!(GroupOrderElement::try_from(*v).is_err())
        }
    }

    #[cfg(any(feature = "cl", feature = "cl_native"))]
    #[test]
    fn group_elt_convert() {
        use crate::ursa::pair::GroupOrderElement as Elt;

        let elt = Elt::new().unwrap();
        let ser = serde_json::to_string(&elt).unwrap();
        let des = serde_json::from_str::<GroupOrderElement>(&ser).unwrap();
        let ser2 = serde_json::to_string(&des).unwrap();
        let elt_des = serde_json::from_str::<Elt>(&ser2).unwrap();
        assert_eq!(elt_des, elt);
    }
}
