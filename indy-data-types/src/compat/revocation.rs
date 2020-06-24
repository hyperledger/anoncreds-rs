use std::collections::HashSet;

use super::{Pair, PointG2};

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct RevocationRegistry {
    accum: PointG2,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct RevocationRegistryDelta {
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    prev_accum: Option<PointG2>,
    accum: PointG2,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "HashSet::is_empty"))]
    #[cfg_attr(feature = "serde", serde(default))]
    issued: HashSet<u32>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "HashSet::is_empty"))]
    #[cfg_attr(feature = "serde", serde(default))]
    revoked: HashSet<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RevocationKeyPublic {
    z: Pair,
}
