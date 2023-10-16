use anoncreds_core::data_types::schema::SchemaId;
use anoncreds_core::data_types::issuer_id::IssuerId;
use anoncreds_core::data_types::rev_reg::RevocationRegistryId;
use anoncreds_core::data_types::rev_reg_def::RevocationRegistryDefinitionId;
use anoncreds_core::data_types::cred_def::CredentialDefinitionId;
use anoncreds_core::types::{
    AttributeNames, 
    AttributeValues as AnoncredsAttributeValues
};
use anoncreds_core::data_types::credential::CredentialValues as AnoncredsCredentialValues;
use crate::UniffiCustomTypeConverter;
use std::collections::HashMap;

/// Make sure [AttributeNames] implements [UniffiCustomTypeConverter] so that UniFFI can use it as
/// it is a Tuple Struct in Rust
impl UniffiCustomTypeConverter for AttributeNames {
    type Builtin = Vec<String>;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        Ok(AttributeNames(val))
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.0
    }
}

/// Make sure [IssuerId] implements [UniffiCustomTypeConverter] so that UniFFI can use it as
/// it is Rust [macro_rules]
impl UniffiCustomTypeConverter for IssuerId {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        Ok(IssuerId(val))
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.0
    }
}

/// Make sure [SchemaId] implements [UniffiCustomTypeConverter] so that UniFFI can use it as
/// it is Rust [macro_rules]
impl UniffiCustomTypeConverter for SchemaId {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        Ok(SchemaId(val))
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.0
    }
}

/// Make sure [CredentialDefinitionId] implements [UniffiCustomTypeConverter] so that UniFFI can use it as
/// it is Rust [macro_rules]
impl UniffiCustomTypeConverter for CredentialDefinitionId {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        Ok(CredentialDefinitionId(val))
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.0
    }
}

/// Make sure [RevocationRegistryDefinitionId] implements [UniffiCustomTypeConverter] so that UniFFI can use it as
/// it is Rust [macro_rules]
impl UniffiCustomTypeConverter for RevocationRegistryDefinitionId {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        Ok(RevocationRegistryDefinitionId(val))
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.0
    }
}

/// Make sure [RevocationRegistryId] implements [UniffiCustomTypeConverter] so that UniFFI can use it as
/// it is a Tuple Struct in Rust
impl UniffiCustomTypeConverter for RevocationRegistryId {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        Ok(RevocationRegistryId(val))
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.0
    }
}

pub struct CredentialValues {
    pub values: HashMap<String, AttributeValues>
}

impl From<AnoncredsCredentialValues> for CredentialValues {
    fn from(acr: AnoncredsCredentialValues) -> Self {
        let mapped: HashMap<String, AttributeValues> = acr.0.iter()
            .map(|(k, v)| (k.clone(), v.clone().into()))
            .collect();
        return CredentialValues { values: mapped }
    }
}

impl From<CredentialValues> for AnoncredsCredentialValues {
    fn from(def: CredentialValues) -> AnoncredsCredentialValues {
        let mapped: HashMap<String, AnoncredsAttributeValues> = def.values.into_iter()
            .map(|(k, v)| (k, v.into()))
            .collect();
        AnoncredsCredentialValues(mapped)
    }
}

pub struct AttributeValues {
    pub raw: String,
    pub encoded: String,
}

impl From<AnoncredsAttributeValues> for AttributeValues {
    fn from(acr: AnoncredsAttributeValues) -> Self {
        return AttributeValues { raw: acr.raw, encoded: acr.encoded }
    }
}

impl From<AttributeValues> for AnoncredsAttributeValues {
    fn from(def: AttributeValues) -> AnoncredsAttributeValues {
        AnoncredsAttributeValues { raw: def.raw, encoded: def.encoded }
    }
}