use serde::{de, Deserialize, Deserializer};
use serde_json::Value;

use crate::utils::validation::URI_IDENTIFIER;

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct URI(pub String);

impl From<&str> for URI {
    fn from(uri: &str) -> Self {
        URI(uri.to_string())
    }
}

impl<'de> Deserialize<'de> for URI {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
    {
        let v = Value::deserialize(deserializer)?;

        let id: String = Deserialize::deserialize(v).map_err(de::Error::custom)?;

        URI_IDENTIFIER.captures(&id).ok_or(de::Error::custom(
            "CredentialWC3 `id` validation failed: not URI id is passed",
        ))?;

        Ok(URI(id))
    }
}