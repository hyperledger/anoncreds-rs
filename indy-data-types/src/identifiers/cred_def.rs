use super::schema::SchemaId;
use crate::common::did::DidValue;
use crate::utils::qualifier::{self, Qualifiable};
use crate::utils::validation::{Validatable, ValidationError};

use super::DELIMITER;

qualifiable_type!(CredentialDefinitionId);

impl CredentialDefinitionId {
    pub const PREFIX: &'static str = "creddef";
    pub const MARKER: &'static str = "3";

    pub fn new(
        did: &DidValue,
        schema_id: &SchemaId,
        signature_type: &str,
        tag: &str,
    ) -> CredentialDefinitionId {
        let tag = if tag.is_empty() {
            format!("")
        } else {
            format!("{}{}", DELIMITER, tag)
        };
        let id = format!(
            "{}{}{}{}{}{}{}{}",
            did.0,
            DELIMITER,
            Self::MARKER,
            DELIMITER,
            signature_type,
            DELIMITER,
            schema_id.0,
            tag
        );
        Self::from(qualifier::combine(
            Self::PREFIX,
            did.get_method(),
            id.as_str(),
        ))
    }

    pub fn parts(&self) -> Option<(Option<&str>, DidValue, String, SchemaId, String)> {
        let parts = self.0.split_terminator(DELIMITER).collect::<Vec<&str>>();

        if parts.len() == 4 {
            // Th7MpTaRZVRYnPiabds81Y:3:CL:1
            let did = parts[0].to_string();
            let signature_type = parts[2].to_string();
            let schema_id = parts[3].to_string();
            let tag = String::new();
            return Some((
                None,
                DidValue(did),
                signature_type,
                SchemaId(schema_id),
                tag,
            ));
        }

        if parts.len() == 5 {
            // Th7MpTaRZVRYnPiabds81Y:3:CL:1:tag
            let did = parts[0].to_string();
            let signature_type = parts[2].to_string();
            let schema_id = parts[3].to_string();
            let tag = parts[4].to_string();
            return Some((
                None,
                DidValue(did),
                signature_type,
                SchemaId(schema_id),
                tag,
            ));
        }

        if parts.len() == 7 {
            // NcYxiDXkpYi6ov5FcYDi1e:3:CL:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0
            let did = parts[0].to_string();
            let signature_type = parts[2].to_string();
            let schema_id = parts[3..7].join(DELIMITER);
            let tag = String::new();
            return Some((
                None,
                DidValue(did),
                signature_type,
                SchemaId(schema_id),
                tag,
            ));
        }

        if parts.len() == 8 {
            // NcYxiDXkpYi6ov5FcYDi1e:3:CL:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0:tag
            let did = parts[0].to_string();
            let signature_type = parts[2].to_string();
            let schema_id = parts[3..7].join(DELIMITER);
            let tag = parts[7].to_string();
            return Some((
                None,
                DidValue(did),
                signature_type,
                SchemaId(schema_id),
                tag,
            ));
        }

        if parts.len() == 9 {
            // creddef:sov:did:sov:NcYxiDXkpYi6ov5FcYDi1e:3:CL:3:tag
            let method = parts[1];
            let did = parts[2..5].join(DELIMITER);
            let signature_type = parts[6].to_string();
            let schema_id = parts[7].to_string();
            let tag = parts[8].to_string();
            return Some((
                Some(method),
                DidValue(did),
                signature_type,
                SchemaId(schema_id),
                tag,
            ));
        }

        if parts.len() == 16 {
            // creddef:sov:did:sov:NcYxiDXkpYi6ov5FcYDi1e:3:CL:schema:sov:did:sov:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0:tag
            let method = parts[1];
            let did = parts[2..5].join(DELIMITER);
            let signature_type = parts[6].to_string();
            let schema_id = parts[7..15].join(DELIMITER);
            let tag = parts[15].to_string();
            return Some((
                Some(method),
                DidValue(did),
                signature_type,
                SchemaId(schema_id),
                tag,
            ));
        }

        None
    }

    pub fn issuer_did(&self) -> Option<DidValue> {
        self.parts().map(|(_, did, _, _, _)| did)
    }
}

impl Qualifiable for CredentialDefinitionId {
    fn prefix() -> &'static str {
        Self::PREFIX
    }

    fn combine(method: Option<&str>, entity: &str) -> Self {
        let cid = Self(entity.to_owned());
        match cid.parts() {
            Some((_, did, sigtype, schema_id, tag)) => Self::new(
                &did.default_method(method),
                &schema_id.default_method(method),
                &sigtype,
                &tag,
            ),
            None => cid,
        }
    }

    fn to_unqualified(&self) -> Self {
        match self.parts() {
            Some((_, did, sig_type, schema_id, tag)) => Self::new(
                &did.to_unqualified(),
                &schema_id.to_unqualified(),
                &sig_type,
                &tag,
            ),
            None => self.clone(),
        }
    }
}

impl Validatable for CredentialDefinitionId {
    fn validate(&self) -> Result<(), ValidationError> {
        self.parts().ok_or(invalid!(
            "Credential Definition Id validation failed: {:?}, doesn't match pattern",
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

    fn _signature_type() -> String {
        "CL".to_string()
    }

    fn _tag() -> String {
        "tag".to_string()
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

    fn _cred_def_id_unqualified() -> CredentialDefinitionId {
        CredentialDefinitionId(
            "NcYxiDXkpYi6ov5FcYDi1e:3:CL:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0:tag".to_string(),
        )
    }

    fn _cred_def_id_unqualified_with_schema_as_seq_no() -> CredentialDefinitionId {
        CredentialDefinitionId("NcYxiDXkpYi6ov5FcYDi1e:3:CL:1:tag".to_string())
    }

    fn _cred_def_id_unqualified_with_schema_as_seq_no_without_tag() -> CredentialDefinitionId {
        CredentialDefinitionId("NcYxiDXkpYi6ov5FcYDi1e:3:CL:1".to_string())
    }

    fn _cred_def_id_unqualified_without_tag() -> CredentialDefinitionId {
        CredentialDefinitionId(
            "NcYxiDXkpYi6ov5FcYDi1e:3:CL:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0".to_string(),
        )
    }

    fn _cred_def_id_qualified_with_schema_as_seq_no() -> CredentialDefinitionId {
        CredentialDefinitionId("creddef:sov:did:sov:NcYxiDXkpYi6ov5FcYDi1e:3:CL:1:tag".to_string())
    }

    fn _cred_def_id_qualified() -> CredentialDefinitionId {
        CredentialDefinitionId("creddef:sov:did:sov:NcYxiDXkpYi6ov5FcYDi1e:3:CL:schema:sov:did:sov:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0:tag".to_string())
    }

    mod to_unqualified {
        use super::*;

        #[test]
        fn test_cred_def_id_parts_for_id_as_unqualified() {
            assert_eq!(
                _cred_def_id_unqualified(),
                _cred_def_id_unqualified().to_unqualified()
            );
        }

        #[test]
        fn test_cred_def_id_parts_for_id_as_unqualified_without_tag() {
            assert_eq!(
                _cred_def_id_unqualified_without_tag(),
                _cred_def_id_unqualified_without_tag().to_unqualified()
            );
        }

        #[test]
        fn test_cred_def_id_parts_for_id_as_unqualified_without_tag_with_schema_as_seq_no() {
            assert_eq!(
                _cred_def_id_unqualified_with_schema_as_seq_no(),
                _cred_def_id_unqualified_with_schema_as_seq_no().to_unqualified()
            );
        }

        #[test]
        fn test_cred_def_id_parts_for_id_as_unqualified_without_tag_with_schema_as_seq_no_without_tag(
        ) {
            assert_eq!(
                _cred_def_id_unqualified_with_schema_as_seq_no_without_tag(),
                _cred_def_id_unqualified_with_schema_as_seq_no_without_tag().to_unqualified()
            );
        }

        #[test]
        fn test_cred_def_id_parts_for_id_as_qualified() {
            assert_eq!(
                _cred_def_id_unqualified(),
                _cred_def_id_qualified().to_unqualified()
            );
        }

        #[test]
        fn test_cred_def_id_parts_for_id_as_qualified_with_schema_as_seq_no() {
            assert_eq!(
                _cred_def_id_unqualified_with_schema_as_seq_no(),
                _cred_def_id_qualified_with_schema_as_seq_no().to_unqualified()
            );
        }
    }

    mod parts {
        use super::*;

        #[test]
        fn test_cred_def_id_parts_for_id_as_unqualified() {
            let (_, did, signature_type, schema_id, tag) =
                _cred_def_id_unqualified().parts().unwrap();
            assert_eq!(_did(), did);
            assert_eq!(_signature_type(), signature_type);
            assert_eq!(_schema_id_unqualified(), schema_id);
            assert_eq!(_tag(), tag);
        }

        #[test]
        fn test_cred_def_id_parts_for_id_as_unqualified_without_tag() {
            let (_, did, signature_type, schema_id, tag) =
                _cred_def_id_unqualified_without_tag().parts().unwrap();
            assert_eq!(_did(), did);
            assert_eq!(_signature_type(), signature_type);
            assert_eq!(_schema_id_unqualified(), schema_id);
            assert_eq!(String::new(), tag);
        }

        #[test]
        fn test_cred_def_id_parts_for_id_as_unqualified_with_schema_as_seq() {
            let (_, did, signature_type, schema_id, tag) =
                _cred_def_id_unqualified_with_schema_as_seq_no()
                    .parts()
                    .unwrap();
            assert_eq!(_did(), did);
            assert_eq!(_signature_type(), signature_type);
            assert_eq!(_schema_id_seq_no(), schema_id);
            assert_eq!(_tag(), tag);
        }

        #[test]
        fn test_cred_def_id_parts_for_id_as_unqualified_with_schema_as_seq_without_tag() {
            let (_, did, signature_type, schema_id, tag) =
                _cred_def_id_unqualified_with_schema_as_seq_no_without_tag()
                    .parts()
                    .unwrap();
            assert_eq!(_did(), did);
            assert_eq!(_signature_type(), signature_type);
            assert_eq!(_schema_id_seq_no(), schema_id);
            assert_eq!(String::new(), tag);
        }

        #[test]
        fn test_cred_def_id_parts_for_id_as_qualified() {
            let (_, did, signature_type, schema_id, tag) =
                _cred_def_id_qualified().parts().unwrap();
            assert_eq!(_did_qualified(), did);
            assert_eq!(_signature_type(), signature_type);
            assert_eq!(_schema_id_qualified(), schema_id);
            assert_eq!(_tag(), tag);
        }

        #[test]
        fn test_cred_def_id_parts_for_id_as_qualified_with_schema_as_seq() {
            let (_, did, signature_type, schema_id, tag) =
                _cred_def_id_qualified_with_schema_as_seq_no()
                    .parts()
                    .unwrap();
            assert_eq!(_did_qualified(), did);
            assert_eq!(_signature_type(), signature_type);
            assert_eq!(_schema_id_seq_no(), schema_id);
            assert_eq!(_tag(), tag);
        }
    }

    mod validate {
        use super::*;

        #[test]
        fn test_validate_cred_def_id_as_unqualified() {
            _cred_def_id_unqualified().validate().unwrap();
        }

        #[test]
        fn test_validate_cred_def_id_as_unqualified_without_tag() {
            _cred_def_id_unqualified_without_tag().validate().unwrap();
        }

        #[test]
        fn test_validate_cred_def_id_as_unqualified_with_schema_as_seq_no() {
            _cred_def_id_unqualified_with_schema_as_seq_no()
                .validate()
                .unwrap();
        }

        #[test]
        fn test_validate_cred_def_id_as_unqualified_with_schema_as_seq_no_without_tag() {
            _cred_def_id_unqualified_with_schema_as_seq_no_without_tag()
                .validate()
                .unwrap();
        }

        #[test]
        fn test_validate_cred_def_id_as_fully_qualified() {
            _cred_def_id_qualified().validate().unwrap();
        }

        #[test]
        fn test_validate_cred_def_id_as_fully_qualified_with_schema_as_seq_no() {
            _cred_def_id_qualified_with_schema_as_seq_no()
                .validate()
                .unwrap();
        }
    }

    mod to_qualified {
        use super::*;

        #[test]
        fn test_red_def_to_qualified() {
            assert_eq!(
                _cred_def_id_unqualified().to_qualified("sov").unwrap(),
                _cred_def_id_qualified()
            )
        }
    }
}
