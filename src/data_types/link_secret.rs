use crate::error::ConversionError;
use crypto_bigint::{self, rand_core::OsRng, Encoding, Random, U256};
use serde::Serialize;
use zeroize::Zeroize;
use std::fmt;
use ursa::cl::MasterSecret;

// TODO: This should serialize to decimal and not lower le hex
#[derive(Zeroize, Clone, Copy, Serialize)]
pub struct LinkSecret(pub U256);

impl LinkSecret {
    pub fn new() -> Self {
        let bn = U256::random(&mut OsRng);
        Self(bn)
    }
}

impl fmt::Debug for LinkSecret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("LinkSecret")
            .field(if cfg!(test) { &self.0 } else { &"<hidden>" })
            .finish()
    }
}

impl TryInto<MasterSecret> for LinkSecret {
    type Error = ConversionError;

    fn try_into(self) -> Result<MasterSecret, Self::Error> {
        let j = serde_json::json!({
            "ms": self.0
        });
        serde_json::from_value(j)
            .map_err(|err| ConversionError::from_msg(format!("Error creating link secret: {err}")))
    }
}

impl TryInto<ursa::bn::BigNumber> for LinkSecret {
    type Error = ConversionError;

    fn try_into(self) -> Result<ursa::bn::BigNumber, Self::Error> {
        let b = self.0.to_be_bytes();
        ursa::bn::BigNumber::from_bytes(&b).map_err(|err| {
            ConversionError::from_msg(format!(
                "Error transforming link secret into bignumber: {err}"
            ))
        })
    }
}

impl Into<String> for LinkSecret {
    fn into(self) -> String {
        self.0.to_string()
    }
}

impl From<&str> for LinkSecret {
    fn from(value: &str) -> Self {
        Self(U256::from_be_hex(value))
    }
}

#[cfg(test)]
mod link_secret_tests {
    use super::*;

    #[test]
    fn should_create_new_link_secret() {
        let _ = LinkSecret::new();
    }

    #[test]
    fn should_convert_between_link_secret_and_ursa_bignumber() {
        let link_secret = LinkSecret::new();
        let bn: ursa::bn::BigNumber = link_secret.try_into().expect("Unable to convert between link secret and ursa bn");
        let s = serde_json::to_string(&link_secret).unwrap();
    }

    #[test]
    fn should_convert_between_string_and_link_secret_roundtrip() {
        let ls = "663D8C61E2F5DE3B00FDFB3F43C593B4BA8BAD2CF7178E65D89BFE1A817FB177";
        let link_secret = LinkSecret::try_from(ls).expect("Error creating link secret");
        let link_secret_str: String = link_secret.try_into().expect("Error creating link secret");
        assert_eq!(link_secret_str, ls);
    }

    #[test]
    fn should_convert_between_master_secret() {
        let link_secret = LinkSecret::new();
        println!("{link_secret:?}");
        let master_secret: MasterSecret = link_secret
            .try_into()
            .expect("Unable to tranform link secret into master secret");
    }
}
