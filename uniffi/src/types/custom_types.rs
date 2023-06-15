use crate::types::error::AnoncredsError;
use anoncreds_core::data_types::schema::SchemaId;
use anoncreds_core::data_types::issuer_id::IssuerId;
use anoncreds_core::data_types::rev_reg::RevocationRegistryId;
use anoncreds_core::data_types::rev_reg_def::RevocationRegistryDefinitionId;
use anoncreds_core::data_types::cred_def::CredentialDefinitionId;
use anoncreds_core::types::{
    AttributeNames, 
    AttributeValues
};
use anoncreds_core::data_types::credential::CredentialValues;
use crate::UniffiCustomTypeConverter;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_json::Result as SerdeResult;

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

// /// Make sure [CredentialValues] implements [UniffiCustomTypeConverter] so that UniFFI can use it as
// /// it is a Tuple Struct in Rust
impl UniffiCustomTypeConverter for CredentialValues {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        let json: HashMap<String, AttributeValues> = serde_json::from_str(&val).map_err(|_| AnoncredsError::ConversionError)?;
        Ok(CredentialValues(json))
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        serde_json::to_string(&obj.0).unwrap()
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