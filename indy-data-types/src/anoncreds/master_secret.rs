use crate::ursa::cl::MasterSecret as CryptoMasterSecret;
use crate::{ConversionError, TryClone, Validatable};

#[derive(Debug, Deserialize, Serialize)]
pub struct MasterSecret {
    pub value: CryptoMasterSecret,
}

// impl TryClone for MasterSecret {
//     fn try_clone(&self) -> Result<Self, ConversionError> {
//         Ok(Self {
//             value: self.value.try_clone()?,
//         })
//     }
// }

impl Validatable for MasterSecret {}
