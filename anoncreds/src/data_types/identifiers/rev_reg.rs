use once_cell::sync::Lazy;

use regex::Regex;

use super::cred_def::CredentialDefinitionId;
use super::DELIMITER;
use crate::data_types::utils::{qualifiable, Qualifiable};
use crate::data_types::{Validatable, ValidationError};
use indy_utils::did::DidValue;
use indy_utils::qualifiable_type;

static QUALIFIED_REV_REG_ID: Lazy<Regex> = Lazy::new(|| {
    Regex::new("(^revreg:(?P<method>[a-z0-9]+):)?(?P<did>.+):4:(?P<cred_def_id>.+):(?P<rev_reg_type>.+):(?P<tag>.+)$").unwrap()
});

qualifiable_type!(RevocationRegistryId, "A revocation registry identifier");

impl RevocationRegistryId {
    pub const PREFIX: &'static str = "revreg";
    pub const MARKER: &'static str = "4";

    pub fn new(
        did: &DidValue,
        cred_def_id: &CredentialDefinitionId,
        rev_reg_type: &str,
        tag: &str,
    ) -> RevocationRegistryId {
        let id = format!(
            "{}{}{}{}{}{}{}{}{}",
            did.0,
            DELIMITER,
            Self::MARKER,
            DELIMITER,
            cred_def_id.0,
            DELIMITER,
            rev_reg_type,
            DELIMITER,
            tag
        );
        Self::from(qualifiable::combine(
            Self::PREFIX,
            did.get_method(),
            id.as_str(),
        ))
    }

    pub fn parts(&self) -> Option<(DidValue, CredentialDefinitionId, String, String)> {
        match QUALIFIED_REV_REG_ID.captures(&self.0) {
            Some(caps) => Some((
                DidValue(caps["did"].to_string()),
                CredentialDefinitionId(caps["cred_def_id"].to_string()),
                caps["rev_reg_type"].to_string(),
                caps["tag"].to_string(),
            )),
            None => None,
        }
    }
}

impl Qualifiable for RevocationRegistryId {
    fn prefix() -> &'static str {
        Self::PREFIX
    }

    fn combine(method: Option<&str>, entity: &str) -> Self {
        let sid = Self(entity.to_owned());
        match sid.parts() {
            Some((did, cred_def_id, rev_reg_type, tag)) => Self::new(
                &did.default_method(method),
                &cred_def_id.default_method(method),
                &rev_reg_type,
                &tag,
            ),
            None => sid,
        }
    }

    fn to_unqualified(&self) -> Self {
        match self.parts() {
            Some((did, cred_def_id, rev_reg_type, tag)) => Self::new(
                &did.to_unqualified(),
                &cred_def_id.to_unqualified(),
                &rev_reg_type,
                &tag,
            ),
            None => self.clone(),
        }
    }
}

impl Validatable for RevocationRegistryId {
    fn validate(&self) -> Result<(), ValidationError> {
        self.parts().ok_or(format!(
            "Revocation Registry Id validation failed: {:?}, doesn't match pattern",
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

    fn _rev_reg_type() -> String {
        "CL_ACCUM".to_string()
    }

    fn _tag() -> String {
        "TAG_1".to_string()
    }

    fn _did_qualified() -> DidValue {
        DidValue("did:sov:NcYxiDXkpYi6ov5FcYDi1e".to_string())
    }

    fn _cred_def_id_unqualified() -> CredentialDefinitionId {
        CredentialDefinitionId(
            "NcYxiDXkpYi6ov5FcYDi1e:3:CL:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0:tag".to_string(),
        )
    }

    fn _cred_def_id_qualified() -> CredentialDefinitionId {
        CredentialDefinitionId("creddef:sov:did:sov:NcYxiDXkpYi6ov5FcYDi1e:3:CL:schema:sov:did:sov:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0:tag".to_string())
    }

    fn _rev_reg_id_unqualified() -> RevocationRegistryId {
        RevocationRegistryId("NcYxiDXkpYi6ov5FcYDi1e:4:NcYxiDXkpYi6ov5FcYDi1e:3:CL:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0:tag:CL_ACCUM:TAG_1".to_string())
    }

    fn _rev_reg_id_qualified() -> RevocationRegistryId {
        RevocationRegistryId("revreg:sov:did:sov:NcYxiDXkpYi6ov5FcYDi1e:4:creddef:sov:did:sov:NcYxiDXkpYi6ov5FcYDi1e:3:CL:schema:sov:did:sov:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0:tag:CL_ACCUM:TAG_1".to_string())
    }

    mod to_unqualified {
        use super::*;

        #[test]
        fn test_rev_reg_id_parts_for_id_as_unqualified() {
            assert_eq!(
                _rev_reg_id_unqualified(),
                _rev_reg_id_unqualified().to_unqualified()
            );
        }

        #[test]
        fn test_rev_reg_id_parts_for_id_as_qualified() {
            assert_eq!(
                _rev_reg_id_unqualified(),
                _rev_reg_id_qualified().to_unqualified()
            );
        }
    }

    mod parts {
        use super::*;

        #[test]
        fn test_rev_reg_id_parts_for_id_as_unqualified() {
            let (did, cred_def_id, rev_reg_type, tag) = _rev_reg_id_unqualified().parts().unwrap();
            assert_eq!(_did(), did);
            assert_eq!(_cred_def_id_unqualified(), cred_def_id);
            assert_eq!(_rev_reg_type(), rev_reg_type);
            assert_eq!(_tag(), tag);
        }

        #[test]
        fn test_rev_reg_id_parts_for_id_as_qualified() {
            let (did, cred_def_id, rev_reg_type, tag) = _rev_reg_id_qualified().parts().unwrap();
            assert_eq!(_did_qualified(), did);
            assert_eq!(_cred_def_id_qualified(), cred_def_id);
            assert_eq!(_rev_reg_type(), rev_reg_type);
            assert_eq!(_tag(), tag);
        }
    }

    mod validate {
        use super::*;

        #[test]
        fn test_validate_rev_reg_id_as_unqualified() {
            _rev_reg_id_unqualified().validate().unwrap();
        }

        #[test]
        fn test_validate_rev_reg_id_as_fully_qualified() {
            _rev_reg_id_qualified().validate().unwrap();
        }
    }

    mod to_qualified {
        use super::*;

        #[test]
        fn test_red_def_to_qualified() {
            assert_eq!(
                _rev_reg_id_unqualified().to_qualified("sov").unwrap(),
                _rev_reg_id_qualified()
            )
        }
    }
}
