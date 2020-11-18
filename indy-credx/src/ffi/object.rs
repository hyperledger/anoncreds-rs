use std::collections::BTreeMap;
use std::fmt::Debug;
use std::os::raw::c_char;
use std::sync::{Arc, Mutex};

use ffi_support::rust_string_to_c;
use indy_utils::new_handle_type;
use once_cell::sync::Lazy;
use serde::Serialize;

use super::error::ErrorCode;
use crate::error::Result;
use crate::services::types::{
    Credential, CredentialDefinition, CredentialDefinitionPrivate, CredentialKeyCorrectnessProof,
    CredentialOffer, CredentialRequest, CredentialRequestMetadata, MasterSecret, Presentation,
    RevocationRegistry, RevocationRegistryDefinition, RevocationRegistryDefinitionPrivate,
    RevocationState, Schema,
};

pub(crate) static FFI_OBJECTS: Lazy<Mutex<BTreeMap<ObjectHandle, IndyObject>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

new_handle_type!(ObjectHandle, FFI_OBJECT_COUNTER);

impl ObjectHandle {
    pub(crate) fn create<O: AnyIndyObject + 'static>(value: O) -> Result<Self> {
        let handle = Self::next();
        FFI_OBJECTS
            .lock()
            .map_err(|_| err_msg!("Error locking object store"))?
            .insert(handle, IndyObject::new(value));
        Ok(handle)
    }

    pub(crate) fn load(&self) -> Result<IndyObject> {
        FFI_OBJECTS
            .lock()
            .map_err(|_| err_msg!("Error locking object store"))?
            .get(self)
            .cloned()
            .ok_or_else(|| err_msg!("Invalid object handle"))
    }

    pub(crate) fn remove(&self) -> Result<IndyObject> {
        FFI_OBJECTS
            .lock()
            .map_err(|_| err_msg!("Error locking object store"))?
            .remove(self)
            .ok_or_else(|| err_msg!("Invalid object handle"))
    }
}

#[derive(Clone, Debug)]
#[repr(transparent)]
pub(crate) struct IndyObject(Arc<dyn AnyIndyObject>);

impl IndyObject {
    pub fn new<O: AnyIndyObject + 'static>(value: O) -> Self {
        Self(Arc::new(value))
    }
}

pub(crate) trait ToJson {
    fn to_json(&self) -> Result<String>;
}

impl ToJson for IndyObject {
    #[inline]
    fn to_json(&self) -> Result<String> {
        self.0.to_json()
    }
}

impl<T> ToJson for T
where
    T: Serialize,
{
    fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(err_map!("Error serializing object"))
    }
}

pub(crate) trait AnyIndyObject: Debug + ToJson + Send + Sync {
    fn type_name(&self) -> &'static str;
}

macro_rules! impl_indy_object {
    ($ident:path, $name:expr) => {
        impl AnyIndyObject for $ident {
            fn type_name(&self) -> &'static str {
                $name
            }
        }
    };
}

impl_indy_object!(Credential, "Credential");
impl_indy_object!(CredentialDefinitionPrivate, "CredentialDefinitionPrivate");
impl_indy_object!(CredentialDefinition, "CredentialDefinition");
impl_indy_object!(
    CredentialKeyCorrectnessProof,
    "CredentialKeyCorrectnessProof"
);
impl_indy_object!(CredentialOffer, "CredentialOffer");
impl_indy_object!(CredentialRequest, "CredentialRequest");
impl_indy_object!(CredentialRequestMetadata, "CredentialRequestMetadata");
impl_indy_object!(Schema, "Schema");

impl_indy_object!(MasterSecret, "MasterSecret");
impl_indy_object!(Presentation, "Presentation");
impl_indy_object!(RevocationRegistry, "RevocationRegistry");
impl_indy_object!(RevocationRegistryDefinition, "RevocationRegistryDefinition");
impl_indy_object!(
    RevocationRegistryDefinitionPrivate,
    "RevocationRegistryDefinitionPrivate"
);
impl_indy_object!(RevocationState, "RevocationState");

#[no_mangle]
pub extern "C" fn credx_object_get_json(
    handle: ObjectHandle,
    result_p: *mut *const c_char,
) -> ErrorCode {
    catch_err! {
        check_useful_c_ptr!(result_p);
        let obj = handle.load()?;
        let strval = obj.to_json()?;
        unsafe { *result_p = rust_string_to_c(strval) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn credx_object_free(handle: ObjectHandle) {
    handle.remove().ok();
}
