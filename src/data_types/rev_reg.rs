use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};
use serde::Serialize;

use crate::cl::{Accumulator, RevocationRegistry as CryptoRevocationRegistry};
use crate::{impl_anoncreds_object_identifier, Error};

impl_anoncreds_object_identifier!(RevocationRegistryId);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationRegistry {
    pub value: CryptoRevocationRegistry,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct CLSignaturesRevocationRegistry(Accumulator);

impl TryFrom<&str> for CLSignaturesRevocationRegistry {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let accum = Accumulator::from_string(value)?;
        Ok(Self(accum))
    }
}

impl TryFrom<CryptoRevocationRegistry> for CLSignaturesRevocationRegistry {
    type Error = Error;

    fn try_from(value: CryptoRevocationRegistry) -> Result<Self, Self::Error> {
        let s = serde_json::to_string(&value)?;
        Ok(serde_json::from_str(&s)?)
    }
}

impl TryFrom<CLSignaturesRevocationRegistry> for CryptoRevocationRegistry {
    type Error = Error;

    fn try_from(value: CLSignaturesRevocationRegistry) -> Result<Self, Self::Error> {
        let s = serde_json::to_string(&value)?;
        let json = format!("{{\"accum\": {s}}}");
        Ok(serde_json::from_str(&json)?)
    }
}

impl<'de> Deserialize<'de> for CLSignaturesRevocationRegistry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CLSignaturesRevocationRegistryVisitor;

        impl<'de> Visitor<'de> for CLSignaturesRevocationRegistryVisitor {
            type Value = CLSignaturesRevocationRegistry;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "string or map")
            }

            fn visit_str<E: serde::de::Error>(
                self,
                value: &str,
            ) -> Result<CLSignaturesRevocationRegistry, E> {
                let accum = Accumulator::from_string(value).map_err(de::Error::custom)?;
                Ok(CLSignaturesRevocationRegistry(accum))
            }

            fn visit_map<V>(self, mut map: V) -> Result<CLSignaturesRevocationRegistry, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut accum = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        "currentAccumulator " | "accum" => {
                            if accum.is_some() {
                                return Err(de::Error::duplicate_field(
                                    "(accum|currentAccumulator)",
                                ));
                            }
                            accum = Some(map.next_value()?);
                        }
                        _ => (),
                    }
                }
                let accum: Accumulator =
                    accum.ok_or_else(|| de::Error::missing_field("(accum|currentAccumulator)"))?;
                Ok(CLSignaturesRevocationRegistry(accum))
            }
        }
        deserializer.deserialize_any(CLSignaturesRevocationRegistryVisitor)
    }
}
