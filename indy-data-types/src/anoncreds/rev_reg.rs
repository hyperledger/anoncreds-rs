#[cfg(any(feature = "cl", feature = "cl_native"))]
use std::collections::HashSet;

use crate::Validatable;

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "ver"))]
pub enum RevocationRegistry {
    #[cfg_attr(feature = "serde", serde(rename = "1.0"))]
    RevocationRegistryV1(RevocationRegistryV1),
}

impl RevocationRegistry {
    #[cfg(any(feature = "cl", feature = "cl_native"))]
    pub fn initial_delta(&self) -> RevocationRegistryDelta {
        match self {
            Self::RevocationRegistryV1(v1) => {
                RevocationRegistryDelta::RevocationRegistryDeltaV1(RevocationRegistryDeltaV1 {
                    value: {
                        let empty = HashSet::new();
                        crate::ursa::cl::RevocationRegistryDelta::from_parts(
                            None, &v1.value, &empty, &empty,
                        )
                    },
                })
            }
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RevocationRegistryV1 {
    pub value: ursa_cl!(RevocationRegistry),
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "ver"))]
pub enum RevocationRegistryDelta {
    #[cfg_attr(feature = "serde", serde(rename = "1.0"))]
    RevocationRegistryDeltaV1(RevocationRegistryDeltaV1),
}

impl Validatable for RevocationRegistryDelta {}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct RevocationRegistryDeltaV1 {
    pub value: ursa_cl!(RevocationRegistryDelta),
}
