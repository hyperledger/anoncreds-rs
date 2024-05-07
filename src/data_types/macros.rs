#[macro_export]
macro_rules! impl_anoncreds_object_identifier {
    ($i:ident) => {
        use regex::Regex;
        use std::hash::{Hash, Hasher};
        use $crate::error::ValidationError;
        use $crate::utils::validation::{
            Validatable, LEGACY_CRED_DEF_IDENTIFIER, LEGACY_DID_IDENTIFIER,
            LEGACY_REV_REG_DEF_IDENTIFIER, LEGACY_SCHEMA_IDENTIFIER, URI_IDENTIFIER,
        };

        #[derive(Debug, Clone, Deserialize, Serialize, Default)]
        pub struct $i(pub String);

        impl $i {
            pub fn new_unchecked(s: impl Into<String>) -> Self {
                Self(s.into())
            }

            pub fn new(s: impl Into<String>) -> Result<Self, ValidationError> {
                let s = Self(s.into());
                Validatable::validate(&s)?;
                Ok(s)
            }

            pub fn is_legacy_did_identifier(&self) -> bool {
                LEGACY_DID_IDENTIFIER.captures(&self.0).is_some()
            }

            pub fn is_legacy_cred_def_identifier(&self) -> bool {
                LEGACY_CRED_DEF_IDENTIFIER.captures(&self.0).is_some()
            }

            pub fn is_legacy_rev_reg_def_identifier(&self) -> bool {
                LEGACY_REV_REG_DEF_IDENTIFIER.captures(&self.0).is_some()
            }

            pub fn is_legacy_schema_identifier(&self) -> bool {
                LEGACY_SCHEMA_IDENTIFIER.captures(&self.0).is_some()
            }

            pub fn is_uri(&self) -> bool {
                URI_IDENTIFIER.captures(&self.0).is_some()
            }
            fn get_legacy_regex(&self) -> Result<Regex, ValidationError> {
                match stringify!($i) {
                    "IssuerId" => Ok(LEGACY_DID_IDENTIFIER.clone()),
                    "CredentialDefinitionId" => Ok(LEGACY_CRED_DEF_IDENTIFIER.clone()),
                    "SchemaId" => Ok(LEGACY_SCHEMA_IDENTIFIER.clone()),
                    "RevocationRegistryDefinitionId" => Ok(LEGACY_REV_REG_DEF_IDENTIFIER.clone()),
                    invalid_name => Err($crate::invalid!(
                        "type: {} does not have a validation regex",
                        invalid_name,
                    )),
                }
            }
            fn to_legacy_identifier(&self) -> Result<String, ValidationError> {
                let legacy_regex = self.get_legacy_regex()?;
                let did_indy_regex = Regex::new(r"^(?:[^:]+:)+([1-9A-HJ-NP-Za-km-z]{21,22})(?:/[^/]+){2}/([^/]+)/([^/]+)/([^/]+)(?:/([^/]+))?$").unwrap();
                if let Some(captures) = did_indy_regex.captures(&self.0){
                    let mut normalized_id = String::new();
                    let mut index = 0;
                    for cap in captures.iter().skip(1) {
                        if let Some(mch) = cap {
                            let mut new_suffix = mch.as_str();
                            if index == 1{
                                new_suffix = match mch.as_str(){
                                    "SCHEMA" => "2",
                                    "CLAIM_DEF" => "3",
                                    "REV_REG_DEF" => "4",
                                    "REV_REG_ENTRY" => "5",
                                    _ => return Err($crate::invalid!("Invalid object type: {}", mch.as_str())),
                                };
                            }
                            normalized_id += (new_suffix.to_owned() + "/").as_str();
                        }
                        index += 1;
                    }
                    return Ok(normalized_id)
                }else if let Some(captures) = legacy_regex.captures(&self.0) {
                    let mut normalized_id = String::new();
                    for cap in captures.iter().skip(1) {
                        if let Some(mch) = cap {
                            normalized_id += (mch.as_str().to_owned() + "/").as_str();
                        }
                    }
                    return Ok(normalized_id)
                }
                Ok(self.0.to_string())
            }
        }

        impl PartialEq for $i {
            fn eq(&self, other: &Self) -> bool {
                if self.0 == other.0 {
                    true
                } else if let Ok(self_legacy) = self.to_legacy_identifier() {
                    // if identifiers are not equal try making them both legacy identifiers and compare
                    if let Ok(other_legacy) = other.to_legacy_identifier() {
                        return self_legacy == other_legacy;
                    }
                    false
                } else {
                    false
                }
            }
        }

        impl Eq for $i {}

        impl Hash for $i {
            fn hash<H: Hasher>(&self, state: &mut H) {
                if let Ok(legacy) = self.to_legacy_identifier() {
                    legacy.hash(state);
                } else {
                    self.0.hash(state);
                }
            }
        }

        impl Validatable for $i {
            fn validate(&self) -> Result<(), ValidationError> {
                let legacy_regex = self.get_legacy_regex()?;

                if $crate::utils::validation::URI_IDENTIFIER
                    .captures(&self.0)
                    .is_some()
                {
                    return Ok(());
                }

                if legacy_regex.captures(&self.0).is_some() {
                    return Ok(());
                }

                Err($crate::invalid!(
                    "type: {}, identifier: {} is invalid. It MUST be a URI or legacy identifier.",
                    stringify!($i),
                    self.0
                ))
            }
        }

        impl From<$i> for String {
            fn from(i: $i) -> Self {
                i.0
            }
        }

        impl TryFrom<String> for $i {
            type Error = ValidationError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                $i::new(value)
            }
        }

        impl TryFrom<&str> for $i {
            type Error = ValidationError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                $i::new(value.to_owned())
            }
        }

        impl std::fmt::Display for $i {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

#[cfg(test)]
mod test_legacy_id_matching {
    use crate::{
        data_types::{
            cred_def::CredentialDefinitionId, rev_reg_def::RevocationRegistryDefinitionId,
            schema::SchemaId,
        },
        error::ValidationError,
    };

    // use super::*;
    #[test]
    fn test_eq() -> Result<(), ValidationError> {
        // test schema id matching
        let did_indy_schema_id =
            SchemaId::new("did:indy:sovrin:F72i3Y3Q4i466efjYJYCHM/anoncreds/v0/SCHEMA/npdb/4.3.4")?;
        let legacy_indy_schema_id = SchemaId::new("F72i3Y3Q4i466efjYJYCHM:2:npdb:4.3.4")?;
        assert!(did_indy_schema_id.eq(&legacy_indy_schema_id));

        // test cred def id matching
        let did_indy_cred_def_id = CredentialDefinitionId::new(
            "did:indy:sovrin:5nDyJVP1NrcPAttP3xwMB9/anoncreds/v0/CLAIM_DEF/56495/npdb",
        )?;
        let legacy_indy_cred_def_id =
            CredentialDefinitionId::new("5nDyJVP1NrcPAttP3xwMB9:3:CL:56495:npdb")?;
        assert!(did_indy_cred_def_id.eq(&legacy_indy_cred_def_id));

        // test rev reg def id matching
        let did_indy_rev_reg_def_id = RevocationRegistryDefinitionId::new(
            "did:indy:sovrin:5nDyJVP1NrcPAttP3xwMB9/anoncreds/v0/REV_REG_DEF/56495/npdb/TAG1",
        )?;
        let legacy_indy_rev_reg_def_id = RevocationRegistryDefinitionId::new(
            "5nDyJVP1NrcPAttP3xwMB9:4:5nDyJVP1NrcPAttP3xwMB9:3:CL:56495:npdb:CL_ACCUM:TAG1",
        )?;
        assert!(did_indy_rev_reg_def_id.eq(&legacy_indy_rev_reg_def_id));
        Ok(())
    }

    #[test]
    fn test_hashmap() -> Result<(), ValidationError> {
        use std::collections::HashMap;
        let mut map = HashMap::new();
        let did_indy_schema_id =
            SchemaId::new("did:indy:sovrin:F72i3Y3Q4i466efjYJYCHM/anoncreds/v0/SCHEMA/npdb/4.3.4")?;
        let legacy_indy_schema_id = SchemaId::new("F72i3Y3Q4i466efjYJYCHM:2:npdb:4.3.4")?;
        map.insert(did_indy_schema_id.clone(), "schema_id");
        assert_eq!(map.get(&legacy_indy_schema_id), Some(&"schema_id"));

        let legacy_indy_schema_id = SchemaId::new("F72i3Y3Q4i466efjYJYCHM:2:npdb:4.3.5")?;
        map.insert(legacy_indy_schema_id.clone(), "schema_id2");
        assert_eq!(map.get(&legacy_indy_schema_id), Some(&"schema_id2"));

        // test cred def id matching
        let did_indy_cred_def_id = CredentialDefinitionId::new(
            "did:indy:sovrin:5nDyJVP1NrcPAttP3xwMB9/anoncreds/v0/CLAIM_DEF/56495/npdb",
        )?;
        let legacy_indy_cred_def_id =
            CredentialDefinitionId::new("5nDyJVP1NrcPAttP3xwMB9:3:CL:56495:npdb")?;
        let mut map = HashMap::new();
        map.insert(did_indy_cred_def_id, "cred_def_id");
        assert_eq!(map.get(&legacy_indy_cred_def_id), Some(&"cred_def_id"));

        // test rev reg def id matching
        let did_indy_rev_reg_def_id = RevocationRegistryDefinitionId::new(
            "did:indy:sovrin:5nDyJVP1NrcPAttP3xwMB9/anoncreds/v0/REV_REG_DEF/56495/npdb/TAG1",
        )?;
        let legacy_indy_rev_reg_def_id = RevocationRegistryDefinitionId::new(
            "5nDyJVP1NrcPAttP3xwMB9:4:5nDyJVP1NrcPAttP3xwMB9:3:CL:56495:npdb:CL_ACCUM:TAG1",
        )?;
        let mut map = HashMap::new();
        map.insert(did_indy_rev_reg_def_id, "rev_reg_def_id");
        assert_eq!(
            map.get(&legacy_indy_rev_reg_def_id),
            Some(&"rev_reg_def_id")
        );
        Ok(())
    }
}
