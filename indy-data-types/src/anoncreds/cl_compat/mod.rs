use std::collections::BTreeMap;
use std::collections::HashMap;

use crate::ConversionError;

#[macro_use]
mod macros;

mod bignum;
pub mod credential;
mod groupelt;
mod point;
pub mod proof;
pub mod revocation;

pub use bignum::BigNumber;
pub use groupelt::GroupOrderElement;
pub use point::{Pair, PointG1, PointG2};

pub type Nonce = BigNumber;

// this could be made more efficient by eliminating the intermediate form
// but not that easily
#[cfg(any(feature = "cl", feature = "cl_native"))]
pub(self) fn serde_convert<A, B>(a: A) -> Result<B, crate::ConversionError>
where
    A: serde::Serialize,
    B: for<'de> serde::Deserialize<'de>,
{
    let val = serde_json::to_value(&a)?;
    Ok(serde_json::from_value(val)?)
}

pub trait ToUrsa {
    type UrsaType;

    fn to_ursa(&self) -> Result<Self::UrsaType, ConversionError>;
}

impl<T: ToUrsa> ToUrsa for BTreeMap<String, T> {
    type UrsaType = BTreeMap<String, T::UrsaType>;

    fn to_ursa(&self) -> Result<Self::UrsaType, ConversionError> {
        self.iter().try_fold(BTreeMap::new(), |mut map, (k, v)| {
            map.insert(k.clone(), v.to_ursa()?);
            Ok(map)
        })
    }
}

impl<T: ToUrsa> ToUrsa for HashMap<String, T> {
    type UrsaType = HashMap<String, T::UrsaType>;

    fn to_ursa(&self) -> Result<Self::UrsaType, ConversionError> {
        self.iter().try_fold(HashMap::new(), |mut map, (k, v)| {
            map.insert(k.clone(), v.to_ursa()?);
            Ok(map)
        })
    }
}
