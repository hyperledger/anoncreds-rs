use crate::{impl_anoncreds_object_identifier, Error};
use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};
use serde::Serialize;
use ursa::cl::Accumulator;

impl_anoncreds_object_identifier!(RevocationRegistryId);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationRegistry {
    pub value: ursa::cl::RevocationRegistry,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct UrsaRevocationRegistry(Accumulator);

impl TryFrom<&str> for UrsaRevocationRegistry {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let accum = Accumulator::from_string(value)?;
        Ok(Self(accum))
    }
}

impl TryFrom<ursa::cl::RevocationRegistry> for UrsaRevocationRegistry {
    type Error = Error;

    fn try_from(value: ursa::cl::RevocationRegistry) -> Result<Self, Self::Error> {
        let s = serde_json::to_string(&value)?;
        Ok(serde_json::from_str(&s)?)
    }
}

impl TryFrom<UrsaRevocationRegistry> for ursa::cl::RevocationRegistry {
    type Error = Error;

    fn try_from(value: UrsaRevocationRegistry) -> Result<Self, Self::Error> {
        let s = serde_json::to_string(&value)?;
        let json = format!("{{\"accum\": {s}}}");
        Ok(serde_json::from_str(&json)?)
    }
}

impl<'de> Deserialize<'de> for UrsaRevocationRegistry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UrsaRevocationRegistryVisitor;

        impl<'de> Visitor<'de> for UrsaRevocationRegistryVisitor {
            type Value = UrsaRevocationRegistry;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "string or map")
            }

            fn visit_str<E: serde::de::Error>(
                self,
                value: &str,
            ) -> Result<UrsaRevocationRegistry, E> {
                let accum = Accumulator::from_string(value).map_err(de::Error::custom)?;
                Ok(UrsaRevocationRegistry(accum))
            }

            fn visit_map<V>(self, mut map: V) -> Result<UrsaRevocationRegistry, V::Error>
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
                Ok(UrsaRevocationRegistry(accum))
            }
        }
        deserializer.deserialize_any(UrsaRevocationRegistryVisitor)
    }
}
