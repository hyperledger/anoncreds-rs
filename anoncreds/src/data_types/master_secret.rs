use std::fmt;

use crate::error::ConversionError;
use serde::{Deserialize, Serialize};
use ursa::cl::{prover::Prover as UrsaProver, MasterSecret as UrsaMasterSecret};

#[derive(Serialize, Deserialize)]
pub struct MasterSecret {
    pub value: UrsaMasterSecret,
}

impl MasterSecret {
    #[inline]
    pub fn new() -> Result<Self, ConversionError> {
        let value = UrsaProver::new_master_secret().map_err(|err| {
            ConversionError::from_msg(format!("Error creating master secret: {err}"))
        })?;
        Ok(Self { value })
    }

    pub fn try_clone(&self) -> Result<Self, ConversionError> {
        Ok(Self {
            value: self.value.try_clone().map_err(|e| e.to_string())?,
        })
    }
}

impl fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("MasterSecret")
            .field(if cfg!(test) { &self.value } else { &"<hidden>" })
            .finish()
    }
}
