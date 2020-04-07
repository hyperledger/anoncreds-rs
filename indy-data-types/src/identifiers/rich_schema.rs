use crate::utils::qualifier::Qualifiable;
use crate::utils::validation::{Validatable, ValidationError};

qualifiable_type!(RichSchemaId, "A rich schema identifier");

impl RichSchemaId {
    pub const PREFIX: &'static str = "rich_schema";
    pub fn new(did_string: String) -> RichSchemaId {
        // ToDo: add RichSchema specific id forming if needed
        return RichSchemaId(did_string);
    }
}

impl Validatable for RichSchemaId {
    fn validate(&self) -> Result<(), ValidationError> {
        // ToDO: add RichSchema ID specific validation
        return Ok(());
    }
}

impl Qualifiable for RichSchemaId {
    fn prefix() -> &'static str {
        Self::PREFIX
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn _rs_id_qualified() -> RichSchemaId {
        RichSchemaId("did:sov:some_hash_value_or_something_else".to_string())
    }

    fn _rs_id_unqualified() -> RichSchemaId {
        RichSchemaId("some_other:sov:some_hash_value_or_something_else".to_string())
    }

    #[test]
    fn _validate_qualified_rs_id() {
        assert_eq!(_rs_id_qualified().validate().unwrap(), ())
    }

    // #[test]
    // fn _validate_unqualified_rs_id() {
    //     assert_eq!(_rs_id_unqualified().validate().unwrap(), false)
    // }
}
