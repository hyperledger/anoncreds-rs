use super::cl_compat::credential::MasterSecret as CryptoMasterSecret;
use crate::Validatable;

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct MasterSecret {
    pub value: CryptoMasterSecret,
}

impl Validatable for MasterSecret {}
