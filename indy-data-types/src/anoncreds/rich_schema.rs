use crate::identifiers::rich_schema::RichSchemaId;
use crate::{Validatable, ValidationError};

#[macro_export]
macro_rules! build_rs_operation {
    ($self:ident, $operation:ident, $identifier:expr, $rich_schema:expr) => {{
        $self.build(
            $operation(RichSchemaBaseOperation::new(
                $rich_schema,
                $operation::get_txn_type().to_string(),
            )),
            Some($identifier),
        )
    }};
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RSContent(pub String);

impl Validatable for RSContent {
    fn validate(&self) -> Result<(), ValidationError> {
        // ToDo: Add JSON-LD validation if needed
        return Ok(());
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RichSchema {
    pub id: RichSchemaId,
    pub content: RSContent,
    pub rs_name: String,
    pub rs_version: String,
    pub rs_type: String,
    pub ver: String,
}

impl RichSchema {
    pub fn new(
        id: RichSchemaId,
        content: RSContent,
        rs_name: String,
        rs_version: String,
        rs_type: String,
        ver: String,
    ) -> Self {
        Self {
            id,
            content,
            rs_name,
            rs_version,
            rs_type,
            ver,
        }
    }
}

impl Validatable for RichSchema {
    fn validate(&self) -> Result<(), ValidationError> {
        let _rs_type: RSType =
            serde_json::from_value(serde_json::value::Value::String(self.rs_type.clone()))
                .map_err(|_err| _err.to_string())?;
        return self.id.validate();
    }
}

#[derive(Serialize, Debug, Deserialize, Clone)]
pub enum RSType {
    #[serde(rename = "sch")]
    Sch,
    #[serde(rename = "map")]
    Map,
    #[serde(rename = "ctx")]
    Ctx,
    #[serde(rename = "enc")]
    Enc,
    #[serde(rename = "cdf")]
    Cdf,
    #[serde(rename = "pdf")]
    Pdf,
}

impl RSType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sch => "sch",
            Self::Map => "map",
            Self::Ctx => "ctx",
            Self::Enc => "enc",
            Self::Cdf => "cdf",
            Self::Pdf => "pdf",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn _rich_schema_id() -> RichSchemaId {
        RichSchemaId::new("did:sov:some_hash_value".to_string())
    }

    fn _rs_schema() -> RichSchema {
        RichSchema::new(
            _rich_schema_id(),
            RSContent(r#"{"json": "ld"; "valid": "object"}"#.to_string()),
            "test_rich_schema".to_string(),
            "first_version".to_string(),
            RSType::Sch.as_str().to_owned(),
            "1".to_string(),
        )
    }

    #[test]
    fn test_fail_on_wrong_rs_type() {
        let mut rs_schema = _rs_schema();
        rs_schema.rs_type = "SomeOtherType".to_string();
        let err = rs_schema.validate().unwrap_err();
        assert!(err.to_string().contains("unknown variant `SomeOtherType`"));
    }
}
