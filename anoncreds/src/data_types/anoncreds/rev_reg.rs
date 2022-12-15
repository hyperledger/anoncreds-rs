use std::collections::HashSet;

use crate::{data_types::Validatable, impl_anoncreds_object_identifier};

impl_anoncreds_object_identifier!(RevocationRegistryId);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "ver")]
pub enum RevocationRegistry {
    #[serde(rename = "1.0")]
    RevocationRegistryV1(RevocationRegistryV1),
}

impl RevocationRegistry {
    pub fn initial_delta(&self) -> RevocationRegistryDelta {
        match self {
            Self::RevocationRegistryV1(v1) => {
                RevocationRegistryDelta::RevocationRegistryDeltaV1(RevocationRegistryDeltaV1 {
                    value: {
                        let empty = HashSet::new();
                        ursa::cl::RevocationRegistryDelta::from_parts(
                            None, &v1.value, &empty, &empty,
                        )
                    },
                })
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationRegistryV1 {
    pub value: ursa::cl::RevocationRegistry,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "ver")]
pub enum RevocationRegistryDelta {
    #[serde(rename = "1.0")]
    RevocationRegistryDeltaV1(RevocationRegistryDeltaV1),
}

impl Validatable for RevocationRegistryDelta {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationRegistryDeltaV1 {
    pub value: ursa::cl::RevocationRegistryDelta,
}
