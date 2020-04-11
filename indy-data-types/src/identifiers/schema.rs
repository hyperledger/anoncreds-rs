use crate::utils::qualifier::{self, Qualifiable};
use crate::{Validatable, ValidationError};
use indy_utils::did::DidValue;
use indy_utils::qualifiable_type;

use super::DELIMITER;

qualifiable_type!(SchemaId, "A V1 schema identifier");

impl SchemaId {
    pub const PREFIX: &'static str = "schema";
    pub const MARKER: &'static str = "2";

    pub fn new(did: &DidValue, name: &str, version: &str) -> SchemaId {
        let id = format!(
            "{}{}{}{}{}{}{}",
            did.0,
            DELIMITER,
            Self::MARKER,
            DELIMITER,
            name,
            DELIMITER,
            version
        );
        Self::from(qualifier::combine(
            Self::PREFIX,
            did.get_method(),
            id.as_str(),
        ))
    }

    pub fn parts(&self) -> Option<(Option<&str>, DidValue, String, String)> {
        let parts = self.0.split_terminator(DELIMITER).collect::<Vec<&str>>();

        if parts.len() == 1 {
            // 1
            return None;
        }

        if parts.len() == 4 {
            // NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0
            let did = parts[0].to_string();
            let name = parts[2].to_string();
            let version = parts[3].to_string();
            return Some((None, DidValue(did), name, version));
        }

        if parts.len() == 8 {
            // schema:sov:did:sov:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0
            let method = parts[1];
            let did = parts[2..5].join(DELIMITER);
            let name = parts[6].to_string();
            let version = parts[7].to_string();
            return Some((Some(method), DidValue(did), name, version));
        }

        None
    }
}

impl Qualifiable for SchemaId {
    fn prefix() -> &'static str {
        Self::PREFIX
    }

    fn combine(method: Option<&str>, entity: &str) -> Self {
        let sid = Self(entity.to_owned());
        match sid.parts() {
            Some((_, did, name, version)) => {
                Self::new(&did.default_method(method), &name, &version)
            }
            None => sid,
        }
    }

    fn to_unqualified(&self) -> Self {
        match self.parts() {
            Some((method, did, name, version)) => {
                let did = if let Some(method) = method {
                    did.remove_method(method)
                } else {
                    did
                };
                Self::new(&did, &name, &version)
            }
            None => self.clone(),
        }
    }
}

impl Validatable for SchemaId {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.0.parse::<i32>().is_ok() {
            return Ok(());
        }

        self.parts().ok_or(format!(
            "SchemaId validation failed: {:?}, doesn't match pattern",
            self.0
        ))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn _did() -> DidValue {
        DidValue("NcYxiDXkpYi6ov5FcYDi1e".to_string())
    }

    fn _did_qualified() -> DidValue {
        DidValue("did:sov:NcYxiDXkpYi6ov5FcYDi1e".to_string())
    }

    fn _schema_id_seq_no() -> SchemaId {
        SchemaId("1".to_string())
    }

    fn _schema_id_unqualified() -> SchemaId {
        SchemaId("NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0".to_string())
    }

    fn _schema_id_qualified() -> SchemaId {
        SchemaId("schema:sov:did:sov:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0".to_string())
    }

    fn _schema_id_invalid() -> SchemaId {
        SchemaId("NcYxiDXkpYi6ov5FcYDi1e:2".to_string())
    }

    mod to_unqualified {
        use super::*;

        #[test]
        fn test_schema_id_unqualify_for_id_as_seq_no() {
            assert_eq!(_schema_id_seq_no(), _schema_id_seq_no().to_unqualified());
        }

        #[test]
        fn test_schema_id_parts_for_id_as_unqualified() {
            assert_eq!(
                _schema_id_unqualified(),
                _schema_id_unqualified().to_unqualified()
            );
        }

        #[test]
        fn test_schema_id_parts_for_id_as_qualified() {
            assert_eq!(
                _schema_id_unqualified(),
                _schema_id_qualified().to_unqualified()
            );
        }

        #[test]
        fn test_schema_id_parts_for_invalid_unqualified() {
            assert_eq!(_schema_id_invalid(), _schema_id_invalid().to_unqualified());
        }
    }

    mod parts {
        use super::*;

        #[test]
        fn test_schema_id_parts_for_id_as_seq_no() {
            assert!(_schema_id_seq_no().parts().is_none());
        }

        #[test]
        fn test_schema_id_parts_for_id_as_unqualified() {
            let (_, did, _, _) = _schema_id_unqualified().parts().unwrap();
            assert_eq!(_did(), did);
        }

        #[test]
        fn test_schema_id_parts_for_id_as_qualified() {
            let (_, did, _, _) = _schema_id_qualified().parts().unwrap();
            assert_eq!(_did_qualified(), did);
        }

        #[test]
        fn test_schema_id_parts_for_invalid_unqualified() {
            assert!(_schema_id_invalid().parts().is_none());
        }
    }

    mod validate {
        use super::*;

        #[test]
        fn test_validate_schema_id_as_seq_no() {
            _schema_id_seq_no().validate().unwrap();
        }

        #[test]
        fn test_validate_schema_id_as_unqualified() {
            _schema_id_unqualified().validate().unwrap();
        }

        #[test]
        fn test_validate_schema_id_as_fully_qualified() {
            _schema_id_qualified().validate().unwrap();
        }

        #[test]
        fn test_validate_schema_id_for_invalid_unqualified() {
            _schema_id_invalid().validate().unwrap_err();
        }

        #[test]
        fn test_validate_schema_id_for_invalid_fully_qualified() {
            let id = SchemaId("schema:sov:NcYxiDXkpYi6ov5FcYDi1e:2:1.0".to_string());
            id.validate().unwrap_err();
        }
    }

    mod to_qualified {
        use super::*;

        #[test]
        fn test_schema_to_qualified() {
            assert_eq!(
                _schema_id_unqualified().to_qualified("sov").unwrap(),
                _schema_id_qualified()
            )
        }
    }
}
