use super::constants::RICH_SCHEMA;
use super::RequestType;
use crate::ledger::constants::{GET_RICH_SCHEMA_BY_ID, GET_RICH_SCHEMA_BY_METADATA};
use crate::ledger::identifiers::rich_schema::RichSchemaId;
use crate::utils::validation::{Validatable, ValidationError};

pub const MAX_ATTRIBUTES_COUNT: usize = 125;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RSContent {
    jsld_string: String,
}

impl RSContent {
    // ToDo: Should it be json-ld validated object or something like that? For now, String object using is enough
    pub fn new(jsld_string: String) -> Self {
        Self { jsld_string }
    }

    pub fn loads(jsld: String) -> Self {
        // ToDo: Add JSON-LD object creation from string
        Self { jsld_string: jsld }
    }
}

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
    pub rs_type: i32,
    pub ver: i32,
}

impl RichSchema {
    pub fn new(
        id: RichSchemaId,
        content: RSContent,
        rs_name: String,
        rs_version: String,
        rs_type: i32,
        ver: i32,
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
        // ToDo: add specific validation
        return self.id.validate();
        //     Ok(()) => {
        //         match self.content.validate(){
        //             Ok(()) => return Ok(()),
        //             Err(_) => return Err(_),
        //         };
        //     },
        //     Err(_) => return Err(_),
        // }
    }
}

#[derive(Serialize, Debug)]
pub struct RichSchemaOperation {
    #[serde(rename = "type")]
    pub _type: String,
    pub id: RichSchemaId,
    pub content: RSContent,
    pub rs_name: String,
    pub rs_version: String,
    pub rs_type: i32,
    pub ver: i32,
}

impl RichSchemaOperation {
    pub fn new(rs_schema: RichSchema) -> RichSchemaOperation {
        RichSchemaOperation {
            _type: Self::get_txn_type().to_string(),
            id: rs_schema.id,
            content: rs_schema.content,
            rs_name: rs_schema.rs_name,
            rs_version: rs_schema.rs_version,
            rs_type: rs_schema.rs_type,
            ver: rs_schema.ver,
        }
    }
}

impl RequestType for RichSchemaOperation {
    fn get_txn_type<'a>() -> &'a str {
        RICH_SCHEMA
    }
}

// Get RichSchema object from ledger using RichSchema's ID.

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetRichSchemaById {
    #[serde(rename = "type")]
    pub id: RichSchemaId,
}

impl GetRichSchemaById {
    pub fn new(id: RichSchemaId) -> Self {
        Self { id }
    }
}

impl Validatable for GetRichSchemaById {
    fn validate(&self) -> Result<(), ValidationError> {
        // ToDo: add specific validation if needed
        return self.id.validate();
    }
}

#[derive(Serialize, Debug)]
pub struct GetRichSchemaByIdOperation {
    #[serde(rename = "type")]
    pub _type: String,
    pub id: RichSchemaId,
}

impl GetRichSchemaByIdOperation {
    pub fn new(get_rs: GetRichSchemaById) -> Self {
        Self {
            _type: Self::get_txn_type().to_string(),
            id: get_rs.id,
        }
    }
}

impl Validatable for GetRichSchemaByIdOperation {
    fn validate(&self) -> Result<(), ValidationError> {
        // ToDo: add specific validation
        return self.id.validate();
    }
}

impl RequestType for GetRichSchemaByIdOperation {
    fn get_txn_type<'a>() -> &'a str {
        GET_RICH_SCHEMA_BY_ID
    }
}

// Get RichSchema object from ledger using metadata:
//      rs_type: Rich Schema object's type enum
//      rs_name: Rich Schema object's name,
//      rs_version: Rich Schema object's version,

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetRichSchemaByMetadata {
    pub rs_type: i32,
    pub rs_name: String,
    pub rs_version: String,
}

impl GetRichSchemaByMetadata {
    pub fn new(rs_type: i32, rs_name: String, rs_version: String) -> Self {
        Self {
            rs_type,
            rs_name,
            rs_version,
        }
    }
}

#[derive(Serialize, Debug)]
pub struct GetRichSchemaByMetadataOperation {
    #[serde(rename = "type")]
    pub _type: String,
    pub rs_type: i32,
    pub rs_name: String,
    pub rs_version: String,
}

impl GetRichSchemaByMetadataOperation {
    pub fn new(get_rs: GetRichSchemaByMetadata) -> Self {
        Self {
            _type: Self::get_txn_type().to_string(),
            rs_type: get_rs.rs_type,
            rs_name: get_rs.rs_name,
            rs_version: get_rs.rs_version,
        }
    }
}

impl RequestType for GetRichSchemaByMetadataOperation {
    fn get_txn_type<'a>() -> &'a str {
        GET_RICH_SCHEMA_BY_METADATA
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn _rich_schema_id() -> RichSchemaId {
        RichSchemaId::new("did:sov:some_hash_value".to_string())
    }

    fn _get_rs_by_id() -> GetRichSchemaById {
        GetRichSchemaById::new(_rich_schema_id())
    }

    fn _get_rs_by_metadata() -> GetRichSchemaByMetadata {
        GetRichSchemaByMetadata::new(
            42,
            "test_rich_schema".to_string(),
            "first_version".to_string(),
        )
    }

    fn _get_rs_by_metadata_op() -> GetRichSchemaByMetadataOperation {
        GetRichSchemaByMetadataOperation::new(_get_rs_by_metadata())
    }

    fn _rs_schema_v1() -> RichSchema {
        RichSchema::new(
            _rich_schema_id(),
            RSContent::new(r#"{"json": "ld"; "valid": "object"}"#.to_string()),
            "test_rich_schema".to_string(),
            "first_version".to_string(),
            42,
            1,
        )
    }

    fn _rs_operation() -> RichSchemaOperation {
        RichSchemaOperation::new(_rs_schema_v1())
    }

    fn _get_rs_op_by_id() -> GetRichSchemaByIdOperation {
        GetRichSchemaByIdOperation::new(_get_rs_by_id())
    }

    #[test]
    fn _check_type_rs_op() {
        assert_eq!(_rs_operation()._type, RICH_SCHEMA)
    }

    #[test]
    fn _check_type_get_rs_by_id_op() {
        assert_eq!(_get_rs_op_by_id()._type, GET_RICH_SCHEMA_BY_ID)
    }
    #[test]
    fn _check_type_get_rs_by_metadata_op() {
        assert_eq!(_get_rs_by_metadata_op()._type, GET_RICH_SCHEMA_BY_METADATA)
    }
}
