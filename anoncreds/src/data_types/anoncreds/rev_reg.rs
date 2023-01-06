use bitvec::vec::BitVec;
use serde::{
    de::{Deserializer, Error as DeError, SeqAccess, Visitor},
    ser::{SerializeSeq, Serializer},
};
use std::collections::HashSet;

use crate::{data_types::Validatable, error, impl_anoncreds_object_identifier};

impl_anoncreds_object_identifier!(RevocationRegistryId);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "ver")]
pub enum RevocationRegistry {
    #[serde(rename = "1.0")]
    RevocationRegistryV1(RevocationRegistryV1),
}

impl RevocationRegistry {
    pub fn initial_delta(&self) -> RevocationRegistryDelta {
        match self {
            Self::RevocationRegistryV1(v1) => {
                RevocationRegistryDelta::RevocationRegistryDeltaV1(RevocationRegistryDeltaV1 {
                    value: {
                        let empty = HashSet::new();
                        ursa::cl::RevocationRegistryDelta::from_parts(
                            None, &v1.value, &empty, &empty,
                        )
                    },
                })
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationRegistryV1 {
    pub value: ursa::cl::RevocationRegistry,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "ver")]
pub enum RevocationRegistryDelta {
    #[serde(rename = "1.0")]
    RevocationRegistryDeltaV1(RevocationRegistryDeltaV1),
}

impl Validatable for RevocationRegistryDelta {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationRegistryDeltaV1 {
    pub value: ursa::cl::RevocationRegistryDelta,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationStatusList {
    rev_reg_id: RevocationRegistryId,
    #[serde(with = "serde_revocation_list")]
    revocation_list: bitvec::vec::BitVec,
    #[serde(flatten)]
    registry: ursa::cl::RevocationRegistry,
    timestamp: u64,
}

impl From<&RevocationStatusList> for ursa::cl::RevocationRegistry {
    fn from(rev_reg_list: &RevocationStatusList) -> ursa::cl::RevocationRegistry {
        rev_reg_list.registry.clone()
    }
}

impl RevocationStatusList {
    pub(crate) fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub(crate) fn state(&self) -> &bitvec::vec::BitVec {
        &self.revocation_list
    }

    pub(crate) fn state_owned(&self) -> bitvec::vec::BitVec {
        self.revocation_list.clone()
    }

    pub fn new(
        rev_reg_id: &str,
        revocation_list: bitvec::vec::BitVec,
        registry: ursa::cl::RevocationRegistry,
        timestamp: u64,
    ) -> Result<Self, error::Error> {
        Ok(RevocationStatusList {
            rev_reg_id: RevocationRegistryId::new(rev_reg_id)?,
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
                    "a seq containing revoation state, i.e. [1, 0, 1]"
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
mod tests {
    use super::*;
    use bitvec::prelude::*;

    const REVOCATION_LIST: &str = r#"
        {
            "revRegId": "reg",
            "revocationList": [1, 1, 1, 1],
            "accum":  "1 1379509F4D411630D308A5ABB4F422FCE6737B330B1C5FD286AA5C26F2061E60 1 235535CC45D4816C7686C5A402A230B35A62DDE82B4A652E384FD31912C4E4BB 1 0C94B61595FCAEFC892BB98A27D524C97ED0B7ED1CC49AD6F178A59D4199C9A4 1 172482285606DEE8500FC8A13E6A35EC071F8B84F0EB4CD3DD091C0B4CD30E5E 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000",
			 "timestamp": 1234
        }"#;

    #[test]
    fn json_rev_list_can_be_deserialized() {
        let des = serde_json::from_str::<RevocationStatusList>(REVOCATION_LIST).unwrap();
        let expected_state = bitvec![1;4];
        assert_eq!(des.state(), &expected_state);
    }

    #[test]
    fn test_revocation_list_roundtrip_serde() {
        let des_from_json = serde_json::from_str::<RevocationStatusList>(REVOCATION_LIST).unwrap();
        let ser = serde_json::to_string(&des_from_json).unwrap();
        let des = serde_json::from_str::<RevocationStatusList>(&ser).unwrap();
        let ser2 = serde_json::to_string(&des).unwrap();
        assert_eq!(ser, ser2)
    }
}
