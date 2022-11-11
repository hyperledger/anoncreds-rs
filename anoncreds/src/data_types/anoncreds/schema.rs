use crate::data_types::identifiers::schema::SchemaId;
use crate::data_types::utils::Qualifiable;
use crate::data_types::{Validatable, ValidationError};

use std::collections::HashSet;
use std::iter::FromIterator;

pub const MAX_ATTRIBUTES_COUNT: usize = 125;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "ver")]
pub enum Schema {
    #[serde(rename = "1.0")]
    SchemaV1(SchemaV1),
}

impl Schema {
    pub fn id(&self) -> &SchemaId {
        match self {
            Schema::SchemaV1(s) => &s.id,
        }
    }

    pub fn to_unqualified(self) -> Schema {
        match self {
            Schema::SchemaV1(schema) => Schema::SchemaV1(SchemaV1 {
                id: schema.id.to_unqualified(),
                name: schema.name,
                version: schema.version,
                attr_names: schema.attr_names,
                seq_no: schema.seq_no,
            }),
        }
    }
}

impl Validatable for Schema {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Schema::SchemaV1(schema) => schema.validate(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaV1 {
    pub id: SchemaId,
    pub name: String,
    pub version: String,
    #[serde(rename = "attrNames")]
    pub attr_names: AttributeNames,
    pub seq_no: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeNames(pub HashSet<String>);

impl AttributeNames {
    pub fn new() -> Self {
        AttributeNames(HashSet::new())
    }
}

impl From<&[&str]> for AttributeNames {
    fn from(attrs: &[&str]) -> Self {
        let mut attrset = HashSet::new();
        for attr in attrs {
            attrset.insert(attr.to_string());
        }
        Self(attrset)
    }
}

impl From<Vec<String>> for AttributeNames {
    fn from(attrs: Vec<String>) -> Self {
        Self(HashSet::from_iter(attrs))
    }
}

impl From<HashSet<String>> for AttributeNames {
    fn from(attrs: HashSet<String>) -> Self {
        Self(attrs)
    }
}

impl Into<HashSet<String>> for AttributeNames {
    fn into(self) -> HashSet<String> {
        self.0
    }
}

impl Validatable for SchemaV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.attr_names.validate()?;
        self.id.validate()?;
        if let Some((_, _, name, version)) = self.id.parts() {
            if name != self.name {
                return Err(format!(
                    "Inconsistent Schema Id and Schema Name: {:?} and {}",
                    self.id, self.name,
                )
                .into());
            }
            if version != self.version {
                return Err(format!(
                    "Inconsistent Schema Id and Schema Version: {:?} and {}",
                    self.id, self.version,
                )
                .into());
            }
        }
        Ok(())
    }
}

impl Validatable for AttributeNames {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.0.is_empty() {
            return Err("Empty list of Schema attributes has been passed".into());
        }

        if self.0.len() > MAX_ATTRIBUTES_COUNT {
            return Err(format!(
                "The number of Schema attributes {} cannot be greater than {}",
                self.0.len(),
                MAX_ATTRIBUTES_COUNT
            )
            .into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod test_schema_validation {
    use super::*;

    fn _schema_id_qualified() -> SchemaId {
        SchemaId("schema:sov:did:sov:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0".to_string())
    }

    #[test]
    fn test_valid_schema() {
        let schema_json = json!({
            "id": _schema_id_qualified(),
            "name": "gvt",
            "ver": "1.0",
            "version": "1.0",
            "attrNames": ["aaa", "bbb", "ccc"],
        })
        .to_string();

        let schema: SchemaV1 = serde_json::from_str(&schema_json).unwrap();
        schema.validate().unwrap();
        assert_eq!(schema.name, "gvt");
        assert_eq!(schema.version, "1.0");
    }

    #[test]
    fn test_invalid_name_schema() {
        let schema_json = json!({
            "id": _schema_id_qualified(),
            "name": "gvt1",
            "ver": "1.0",
            "version": "1.0",
            "attrNames": ["aaa", "bbb", "ccc"],
        })
        .to_string();

        let schema: SchemaV1 = serde_json::from_str(&schema_json).unwrap();
        schema.validate().unwrap_err();
    }

    #[test]
    fn test_invalid_version_schema() {
        let schema_json = json!({
            "id": _schema_id_qualified(),
            "name": "gvt",
            "ver": "1.0",
            "version": "1.1",
            "attrNames": ["aaa", "bbb", "ccc"],
        })
        .to_string();

        let schema: SchemaV1 = serde_json::from_str(&schema_json).unwrap();
        schema.validate().unwrap_err();
    }
}
