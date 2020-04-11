use crate::ursa::cl::{
    RevocationRegistry as CryptoRevocationRegistry,
    RevocationRegistryDelta as CryptoRevocationRegistryDelta,
};
use crate::utils::validation::Validatable;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "ver"))]
pub enum RevocationRegistry {
    #[cfg_attr(feature = "serde", serde(rename = "1.0"))]
    RevocationRegistryV1(RevocationRegistryV1),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RevocationRegistryV1 {
    pub value: CryptoRevocationRegistry,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "ver"))]
pub enum RevocationRegistryDelta {
    #[cfg_attr(feature = "serde", serde(rename = "1.0"))]
    RevocationRegistryDeltaV1(RevocationRegistryDeltaV1),
}

impl Validatable for RevocationRegistryDelta {}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct RevocationRegistryDeltaV1 {
    pub value: CryptoRevocationRegistryDelta,
}
