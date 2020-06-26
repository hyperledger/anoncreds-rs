use super::cl::MasterSecret as CryptoMasterSecret;
use crate::{EmbedJson, Validatable};

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct MasterSecret {
    pub value: EmbedJson<CryptoMasterSecret>,
}

impl Validatable for MasterSecret {}
