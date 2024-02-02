pub mod base64_msgpack {
    use serde::{de::Visitor, ser::Error, Deserialize, Serialize};
    use std::marker::PhantomData;

    use crate::utils::{base64, msg_pack};

    pub const BASE_HEADER: &str = "u";

    pub fn serialize<T, S>(obj: &T, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        T: Serialize,
        S: serde::Serializer,
    {
        let msg_pack_encoded = msg_pack::encode(obj).map_err(S::Error::custom)?;
        let base64_encoded = base64::encode(msg_pack_encoded);
        serializer.collect_str(&format_args!("{}{}", BASE_HEADER, base64_encoded))
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> std::result::Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
        T: for<'a> Deserialize<'a>,
    {
        struct DeserVisitor<VT>(PhantomData<VT>);

        impl<'v, VT> Visitor<'v> for DeserVisitor<VT>
        where
            VT: for<'a> Deserialize<'a>,
        {
            type Value = VT;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("expected base64-msgpack encoded value")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let Some(obj) = v.strip_prefix(BASE_HEADER).and_then(|v| {
                    base64::decode(v).ok()
                }).and_then(|v| {
                    msg_pack::decode(&v).ok()
                }) else {
                    return Err(E::custom(format!("Unexpected multibase base header: {:?}", v)))
                };
                Ok(obj)
            }
        }

        deserializer.deserialize_str(DeserVisitor(PhantomData))
    }
}

#[cfg(test)]
mod tests {

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestObject {
        type_: String,
        value: i32,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(transparent)]
    struct Container(#[serde(with = "super::base64_msgpack")] TestObject);

    #[test]
    fn base64_msgpack_serde_works() {
        let obj = Container(TestObject {
            type_: "Test".to_string(),
            value: 1,
        });
        let encoded = serde_json::to_string(&obj).unwrap();
        assert_eq!("\"ugqV0eXBlX6RUZXN0pXZhbHVlAQ\"", encoded);
        let decoded: Container = serde_json::from_str(&encoded).unwrap();
        assert_eq!(obj, decoded)
    }
}
