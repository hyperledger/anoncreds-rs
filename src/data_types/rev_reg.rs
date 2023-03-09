use bitvec::vec::BitVec;
use serde::{
    de::{self, Deserializer, Error as DeError, MapAccess, SeqAccess, Visitor},
    ser::{SerializeSeq, Serializer},
    Deserialize, Serialize,
};
use std::collections::{BTreeSet, HashSet};
use ursa::cl::Accumulator;

use crate::{error, impl_anoncreds_object_identifier, Error};

use super::{issuer_id::IssuerId, rev_reg_def::RevocationRegistryDefinitionId};

impl_anoncreds_object_identifier!(RevocationRegistryId);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationRegistry {
    pub value: ursa::cl::RevocationRegistry,
}

impl RevocationRegistry {
    pub fn initial_delta(&self) -> RevocationRegistryDelta {
        RevocationRegistryDelta {
            value: {
                let empty = HashSet::new();
                ursa::cl::RevocationRegistryDelta::from_parts(None, &self.value, &empty, &empty)
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationRegistryDelta {
    pub value: ursa::cl::RevocationRegistryDelta,
}

impl Validatable for RevocationRegistryDelta {}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct UrsaRevocationRegistry(Accumulator);

impl TryFrom<&str> for UrsaRevocationRegistry {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let accum = Accumulator::from_string(value)?;
        Ok(UrsaRevocationRegistry(accum))
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
                        "accum" => {
                            if accum.is_some() {
                                return Err(de::Error::duplicate_field(
                                    "(accum|currentAccumulator)",
                                ));
                            }
                            accum = Some(map.next_value()?);
                        }
                        "currentAccumulator" => {
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationStatusList {
    #[serde(skip_serializing_if = "Option::is_none")]
    rev_reg_def_id: Option<RevocationRegistryDefinitionId>,
    issuer_id: IssuerId,
    #[serde(with = "serde_revocation_list")]
    revocation_list: bitvec::vec::BitVec,
    #[serde(rename = "currentAccumulator", skip_serializing_if = "Option::is_none")]
    registry: Option<UrsaRevocationRegistry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<u64>,
}

impl TryFrom<&RevocationStatusList> for Option<ursa::cl::RevocationRegistry> {
    type Error = Error;

    fn try_from(value: &RevocationStatusList) -> Result<Self, Self::Error> {
        value.registry.clone().map(TryInto::try_into).transpose()
    }
}

impl From<&RevocationStatusList> for Option<UrsaRevocationRegistry> {
    fn from(rev_status_list: &RevocationStatusList) -> Option<UrsaRevocationRegistry> {
        rev_status_list.registry.clone().map(Into::into)
    }
}

impl TryFrom<&RevocationStatusList> for Option<RevocationRegistry> {
    type Error = Error;

    fn try_from(value: &RevocationStatusList) -> Result<Self, Self::Error> {
        let value = match value.registry {
            Some(registry) => {
                let reg: ursa::cl::RevocationRegistry = registry.try_into()?;
                Some(RevocationRegistry { value: reg })
            }
            None => None,
        };

        Ok(value)
    }
}

impl RevocationStatusList {
    pub(crate) fn id(&self) -> Option<RevocationRegistryDefinitionId> {
        self.rev_reg_def_id.clone()
    }

    pub(crate) fn timestamp(&self) -> Option<u64> {
        self.timestamp
    }

    pub(crate) fn state(&self) -> &bitvec::vec::BitVec {
        &self.revocation_list
    }

    pub fn set_registry(&mut self, registry: ursa::cl::RevocationRegistry) -> Result<(), Error> {
        self.registry = Some(registry.try_into()?);
        Ok(())
    }

    pub(crate) fn state_owned(&self) -> bitvec::vec::BitVec {
        self.revocation_list.clone()
    }

    pub(crate) fn get(&self, idx: usize) -> Option<bool> {
        self.revocation_list.get(idx).as_deref().copied()
    }

    pub(crate) fn update(
        &mut self,
        registry: Option<ursa::cl::RevocationRegistry>,
        issued: Option<BTreeSet<u32>>,
        revoked: Option<BTreeSet<u32>>,
        timestamp: Option<u64>,
    ) -> Result<(), error::Error> {
        // only update if input is Some
        if let Some(reg) = registry {
            self.registry = Some(reg.try_into()?)
        };
        if let Some(issued) = issued {
            // issued credentials are assigned `false`
            // i.e. NOT revoked
            for i in issued {
                let mut bit = self.revocation_list.get_mut(i as usize).ok_or_else(|| {
                    error::Error::from_msg(
                        crate::ErrorKind::Unexpected,
                        "Update Revocation List Index Out of Range",
                    )
                })?;
                *bit = false;
            }
        }
        if let Some(revoked) = revoked {
            // revoked credentials are assigned `true`
            // i.e. IS revoked
            for i in revoked {
                let mut bit = self.revocation_list.get_mut(i as usize).ok_or_else(|| {
                    error::Error::from_msg(
                        crate::ErrorKind::Unexpected,
                        "Update Revocation List Index Out of Range",
                    )
                })?;
                *bit = true;
            }
        }
        // only update if input is Some
        if let Some(t) = timestamp {
            self.timestamp = Some(t);
        }
        Ok(())
    }

    pub fn new(
        rev_reg_def_id: Option<&str>,
        issuer_id: IssuerId,
        revocation_list: bitvec::vec::BitVec,
        registry: Option<UrsaRevocationRegistry>,
        timestamp: Option<u64>,
    ) -> Result<Self, error::Error> {
        Ok(RevocationStatusList {
            rev_reg_def_id: rev_reg_def_id
                .map(RevocationRegistryDefinitionId::new)
                .transpose()?,
            issuer_id,
            revocation_list,
            registry,
            timestamp,
        })
    }
}

pub mod serde_revocation_list {
    use super::*;
    pub fn serialize<S>(state: &bitvec::vec::BitVec, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = s.serialize_seq(Some(state.len()))?;
        for element in state {
            let e = *element as i32;
            seq.serialize_element(&e)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<bitvec::vec::BitVec, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct JsonBitStringVisitor;

        impl<'de> Visitor<'de> for JsonBitStringVisitor {
            type Value = bitvec::vec::BitVec;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(
                    formatter,
                    "a seq containing revocation state, i.e. [1, 0, 1]"
                )
            }

            fn visit_seq<S>(self, mut v: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                // TODO: do we have a min size for this?
                let mut bv = BitVec::with_capacity(v.size_hint().unwrap_or_default());
                while let Some(ele) = v.next_element()? {
                    match ele {
                        0 => bv.push(false),
                        1 => bv.push(true),
                        _ => {
                            return Err(S::Error::custom("invalid revocation state"));
                        }
                    }
                }
                Ok(bv)
            }
        }
        deserializer.deserialize_seq(JsonBitStringVisitor)
    }
}

#[cfg(test)]
mod rev_reg_tests {
    use super::*;
    use bitvec::prelude::*;

    const REVOCATION_LIST: &str = r#"
        {
            "revRegDefId": "reg",
            "revocationList": [1, 1, 1, 1],
            "issuerId": "mock:uri",
            "currentAccumulator":  "1 1379509F4D411630D308A5ABB4F422FCE6737B330B1C5FD286AA5C26F2061E60 1 235535CC45D4816C7686C5A402A230B35A62DDE82B4A652E384FD31912C4E4BB 1 0C94B61595FCAEFC892BB98A27D524C97ED0B7ED1CC49AD6F178A59D4199C9A4 1 172482285606DEE8500FC8A13E6A35EC071F8B84F0EB4CD3DD091C0B4CD30E5E 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000",
			 "timestamp": 1234
        }"#;

    const REVOCATION_LIST_WITHOUT_ISSUER_ID: &str = r#"
        {
            "revRegDefId": "reg",
            "revocationList": [1, 1, 1, 1],
            "currentAccumulator":  "1 1379509F4D411630D308A5ABB4F422FCE6737B330B1C5FD286AA5C26F2061E60 1 235535CC45D4816C7686C5A402A230B35A62DDE82B4A652E384FD31912C4E4BB 1 0C94B61595FCAEFC892BB98A27D524C97ED0B7ED1CC49AD6F178A59D4199C9A4 1 172482285606DEE8500FC8A13E6A35EC071F8B84F0EB4CD3DD091C0B4CD30E5E 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000",
			 "timestamp": 1234
        }"#;

    #[test]
    fn json_rev_list_can_be_deserialized() {
        let des = serde_json::from_str::<RevocationStatusList>(REVOCATION_LIST).unwrap();
        let expected_state = bitvec![1;4];
        assert_eq!(des.state(), &expected_state);
    }

    #[test]
    fn json_rev_list_can_not_be_deserialized_without_issuer_id() {
        let res = serde_json::from_str::<RevocationStatusList>(REVOCATION_LIST_WITHOUT_ISSUER_ID);
        assert!(res.is_err());
    }

    #[test]
    fn test_revocation_list_roundtrip_serde() {
        let des_from_json = serde_json::from_str::<RevocationStatusList>(REVOCATION_LIST).unwrap();
        let ser = serde_json::to_string(&des_from_json).unwrap();
        let des = serde_json::from_str::<RevocationStatusList>(&ser).unwrap();
        let ser2 = serde_json::to_string(&des).unwrap();
        assert_eq!(ser, ser2)
    }

    #[test]
    fn update_rev_status_list_works() {
        let mut list = serde_json::from_str::<RevocationStatusList>(REVOCATION_LIST).unwrap();
        let list_status = list.state_owned();
        assert_eq!(list.timestamp().unwrap(), 1234);
        assert_eq!(list_status.get(0usize).unwrap(), true);

        list.update(None, Some(BTreeSet::from([0u32])), None, Some(1245))
            .unwrap();
        assert_eq!(list.get(0usize).unwrap(), false);
        assert_eq!(list.timestamp().unwrap(), 1245);
    }
}
