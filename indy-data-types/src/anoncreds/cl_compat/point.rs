use std::cmp::Ordering;
use std::convert::TryFrom;
use std::fmt;
use std::marker::PhantomData;
use std::ops::Deref;

#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize};

use super::GroupOrderElement;
use crate::{ConversionError, ValidationError};

pub type PointG1 = Point<G1>;
pub type PointG2 = Point<G2>;
pub type Pair = Point<Paired>;

fn validate_i32(val: &str) -> Result<(), ValidationError> {
    val.parse::<i32>()
        .map_err(|_| ValidationError::from_msg("Invalid numeric value"))?;
    Ok(())
}

#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Point<T: PointSize> {
    _pd: PhantomData<T>,
    value: String,
}

impl<T: PointSize> Point<T> {
    pub fn from_hex<S: AsRef<str>>(value: S) -> Result<Self, ConversionError> {
        Self::validate(&value)?;
        Ok(Self {
            _pd: PhantomData,
            value: value.as_ref().to_string(),
        })
    }

    pub fn validate<S: AsRef<str>>(value: S) -> Result<(), ValidationError> {
        let mut parts = value.as_ref().split_ascii_whitespace();
        for _ in 0..T::element_count() {
            match (parts.next(), parts.next()) {
                (Some(xs), Some(x)) => {
                    validate_i32(xs)?;
                    GroupOrderElement::validate(x)?;
                }
                _ => {
                    return Err(ValidationError::from_msg(
                        "Invalid point value: missing components",
                    ));
                }
            }
        }
        if parts.next().is_some() {
            return Err(ValidationError::from_msg(
                "Invalid point value: extra components",
            ));
        }
        Ok(())
    }
}

impl<T: PointSize> TryFrom<&str> for Point<T> {
    type Error = ConversionError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_hex(value)
    }
}

impl<T: PointSize> TryFrom<String> for Point<T> {
    type Error = ConversionError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_hex(value)
    }
}

impl<T: PointSize> Clone for Point<T> {
    fn clone(&self) -> Self {
        Self {
            _pd: PhantomData,
            value: self.value.clone(),
        }
    }
}

impl<T: PointSize> PartialEq<Point<T>> for Point<T> {
    fn eq(&self, other: &Point<T>) -> bool {
        self.to_ascii_lowercase() == other.to_ascii_lowercase()
    }
}

impl<T: PointSize> PartialOrd for Point<T> {
    fn partial_cmp(&self, other: &Point<T>) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: PointSize> Ord for Point<T> {
    fn cmp(&self, other: &Point<T>) -> Ordering {
        self.to_ascii_lowercase().cmp(&other.to_ascii_lowercase())
    }
}

impl<T: PointSize> Eq for Point<T> {}

impl<T: PointSize> fmt::Debug for Point<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Point {{ {:?} }}", &self.value)
    }
}

impl<T: PointSize> fmt::Display for Point<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.value.fmt(f)
    }
}

impl<T: PointSize> Deref for Point<T> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

#[cfg(feature = "serde")]
impl<'a, T: PointSize> Deserialize<'a> for Point<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        struct PointVisitor<S: PointSize> {
            _pd: PhantomData<S>,
        }

        impl<'a, S: PointSize> Visitor<'a> for PointVisitor<S> {
            type Value = Point<S>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("expected PointG1")
            }

            fn visit_str<E>(self, value: &str) -> Result<Point<S>, E>
            where
                E: serde::de::Error,
            {
                Ok(Point::from_hex(value).map_err(E::custom)?)
            }
        }

        deserializer.deserialize_str(PointVisitor { _pd: PhantomData })
    }
}

pub trait PointSize {
    fn element_count() -> usize;
}

pub struct G1;

impl PointSize for G1 {
    fn element_count() -> usize {
        3
    }
}

#[cfg(any(feature = "cl", feature = "cl_native"))]
impl super::ToUrsa for Point<G1> {
    type UrsaType = crate::ursa::pair::PointG1;

    fn to_ursa(&self) -> Result<Self::UrsaType, ConversionError> {
        Self::UrsaType::from_string(&self.value).map_err(Into::into)
    }
}

pub struct G2;

impl PointSize for G2 {
    fn element_count() -> usize {
        6
    }
}

#[cfg(any(feature = "cl", feature = "cl_native"))]
impl super::ToUrsa for Point<G2> {
    type UrsaType = crate::ursa::pair::PointG2;

    fn to_ursa(&self) -> Result<Self::UrsaType, ConversionError> {
        Self::UrsaType::from_string(&self.value).map_err(Into::into)
    }
}

pub struct Paired;

impl PointSize for Paired {
    fn element_count() -> usize {
        12
    }
}

#[cfg(any(feature = "cl", feature = "cl_native"))]
impl super::ToUrsa for Point<Paired> {
    type UrsaType = crate::ursa::pair::Pair;

    fn to_ursa(&self) -> Result<Self::UrsaType, ConversionError> {
        Self::UrsaType::from_string(&self.value).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn point_g1_validate() {
        assert!(PointG1::try_from(
            "1 1060F1BCEDC3EB2A59075D3C56687837F2EFFD4E7D53254F49D633618C187E06 1 151D97C6B986FB0EDA3E8539407B438236626EF9331DE0A6B3A20BF25E7B60BA 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8"
        ).is_ok());

        let invalid = [
            "",
            "notanumber",
            "1 1060F1BCEDC3EB",
            " 1060F1BCEDC3EB2A59075D3C56687837F2EFFD4E7D53254F49D633618C187E06",
            "1 1060F1BCEDC3EB2A59075D3C56687837F2EFFD4E7D53254F49D633618C187E06",
            "1 1060F1BCEDC3EB2A59075D3C56687837F2EFFD4E7D53254F49D633618C187E06 1 1060F1BCEDC3EB2A59075D3C56687837F2EFFD4E7D53254F49D633618C187E06 1 1060F1BCEDC3EB2A59075D3C56687837F2EFFD4E7D53254F49D633618C187E06 1 1060F1BCEDC3EB2A59075D3C56687837F2EFFD4E7D53254F49D633618C187E06",
        ];
        for v in invalid.iter() {
            assert!(PointG1::try_from(*v).is_err())
        }
    }

    #[test]
    fn point_g2_validate() {
        assert!(PointG2::try_from(
            "1 1060F1BCEDC3EB2A59075D3C56687837F2EFFD4E7D53254F49D633618C187E06 1 151D97C6B986FB0EDA3E8539407B438236626EF9331DE0A6B3A20BF25E7B60BA 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8"
        ).is_ok());

        let invalid = [
            "",
            "notanumber",
            "1 1060F1BCEDC3EB",
            " 1060F1BCEDC3EB2A59075D3C56687837F2EFFD4E7D53254F49D633618C187E06",
            "1 1060F1BCEDC3EB2A59075D3C56687837F2EFFD4E7D53254F49D633618C187E06",
            "1 1060F1BCEDC3EB2A59075D3C56687837F2EFFD4E7D53254F49D633618C187E06 1 1060F1BCEDC3EB2A59075D3C56687837F2EFFD4E7D53254F49D633618C187E06 1 1060F1BCEDC3EB2A59075D3C56687837F2EFFD4E7D53254F49D633618C187E06 1 1060F1BCEDC3EB2A59075D3C56687837F2EFFD4E7D53254F49D633618C187E06",
        ];
        for v in invalid.iter() {
            assert!(PointG2::try_from(*v).is_err())
        }
    }

    #[cfg(any(feature = "cl", feature = "cl_native"))]
    #[test]
    fn point_g1_convert() {
        use crate::ursa::pair::PointG1 as PtG1;

        let point = PtG1::new().unwrap();

        let ser = serde_json::to_string(&point).unwrap();
        let des = serde_json::from_str::<PointG1>(&ser).unwrap();
        let ser2 = serde_json::to_string(&des).unwrap();
        let pt_des = serde_json::from_str::<PtG1>(&ser2).unwrap();
        assert_eq!(pt_des, point);
    }

    #[cfg(any(feature = "cl", feature = "cl_native"))]
    #[test]
    fn point_g2_convert() {
        use crate::ursa::pair::PointG2 as PtG2;

        let point = PtG2::new().unwrap();

        let ser = serde_json::to_string(&point).unwrap();
        let des = serde_json::from_str::<PointG2>(&ser).unwrap();
        let ser2 = serde_json::to_string(&des).unwrap();
        let pt_des = serde_json::from_str::<PtG2>(&ser2).unwrap();
        assert_eq!(pt_des, point);
    }

    #[cfg(any(feature = "cl", feature = "cl_native"))]
    #[test]
    fn pair_convert() {
        use crate::ursa::pair::{Pair as UPair, PointG1 as UPointG1, PointG2 as UPointG2};

        let point_g1 = UPointG1::from_string("1 01FC3950C5B03061739A4621E205643FDCC1BFE2AC0F2996F46944F7AC340B 1 1056E3F5EE2EA7F7E340764B7BE8A38AAFE66C25573880810726812069BB11 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8").unwrap();
        let point_g2 = UPointG2::from_string("1 16027A65C15E16E00BFCAD948F216B5CFBE07B98876D8889A5DEE03DE7C57B 1 0EC9DBC2286A9485A0DA8525C5BE0F88E27C2B3C337E522DDC170C1764D615 1 1A021C8EFE70DCC7F81DD8E8CDC74F3D64E63E886C73B3A8B9849696E99FF3 1 2505CB0CFAAE75ACCAF60CB5A9F7E7A8250918155886E7FFF9A32D7B5A0500 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8 1 00000000000000000000000000000000000000000000000000000000000000").unwrap();
        let pair = UPair::pair(&point_g1, &point_g2).unwrap();
        let ser = serde_json::to_string(&pair).unwrap();
        let des = serde_json::from_str::<Pair>(&ser).unwrap();
        let ser2 = serde_json::to_string(&des).unwrap();
        let pair_des = serde_json::from_str::<UPair>(&ser2).unwrap();
        assert_eq!(pair_des, pair);
    }
}
