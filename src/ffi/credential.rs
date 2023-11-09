use std::os::raw::c_char;
use std::ptr;

use ffi_support::{FfiStr, rust_string_to_c};

use super::error::{catch_error, ErrorCode};
use super::object::{AnoncredsObject, ObjectHandle};
use super::util::FfiStrList;
use crate::data_types::{
    link_secret::LinkSecret,
    w3c::credential::W3CCredential as W3CCredential,
};
use crate::data_types::credential::{CredentialValuesEncoding, RawCredentialValues};
use crate::error::Result;
use crate::services::{
    helpers::encode_credential_attribute,
    issuer::{create_credential, create_w3c_credential},
    prover::{process_credential, process_w3c_credential},
    types::{Credential, CredentialRevocationConfig, MakeCredentialValues},
};
use crate::conversion::{credential_from_w3c, credential_to_w3c};
use crate::data_types::w3c::credential_proof::NonAnonCredsDataIntegrityProof;
use crate::data_types::w3c::uri::URI;
use crate::Error;
use crate::types::{CredentialValues, MakeRawCredentialValues};

#[derive(Debug)]
#[repr(C)]
pub struct FfiCredRevInfo {
    reg_def: ObjectHandle,
    reg_def_private: ObjectHandle,
    status_list: ObjectHandle,
    reg_idx: i64,
}

struct RevocationConfig {
    reg_def: AnoncredsObject,
    reg_def_private: AnoncredsObject,
    status_list: AnoncredsObject,
    reg_idx: u32,
}

impl TryFrom<&FfiCredRevInfo> for RevocationConfig {
    type Error = Error;

    fn try_from(value: &FfiCredRevInfo) -> Result<Self> {
        Ok(Self {
            reg_def: value.reg_def.load()?,
            reg_def_private: value.reg_def_private.load()?,
            reg_idx: value
                .reg_idx
                .try_into()
                .map_err(|_| err_msg!("Invalid revocation index"))?,
            status_list: value.status_list.load()?,
        })
    }
}

impl<'a> TryFrom<&'a RevocationConfig> for CredentialRevocationConfig<'a> {
    type Error = Error;

    fn try_from(value: &'a RevocationConfig) -> Result<Self> {
        Ok(CredentialRevocationConfig {
            reg_def: value.reg_def.cast_ref()?,
            reg_def_private: value.reg_def_private.cast_ref()?,
            registry_idx: value.reg_idx,
            status_list: value.status_list.cast_ref()?,
        })
    }
}

impl_anoncreds_object!(Credential, "Credential");
impl_anoncreds_object_from_json!(Credential, anoncreds_credential_from_json);

impl_anoncreds_object!(W3CCredential, "W3CCredential");
impl_anoncreds_object_from_json!(W3CCredential, anoncreds_w3c_credential_from_json);

#[no_mangle]
pub extern "C" fn anoncreds_create_credential(
    cred_def: ObjectHandle,
    cred_def_private: ObjectHandle,
    cred_offer: ObjectHandle,
    cred_request: ObjectHandle,
    attr_names: FfiStrList,
    attr_raw_values: FfiStrList,
    attr_enc_values: FfiStrList,
    revocation: *const FfiCredRevInfo,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(cred_p);

        let cred_values = _encoded_credential_values(attr_names, attr_raw_values, attr_enc_values)?;
        let revocation_config = _revocation_config(revocation)?;

        let cred = create_credential(
            cred_def.load()?.cast_ref()?,
            cred_def_private.load()?.cast_ref()?,
            cred_offer.load()?.cast_ref()?,
            cred_request.load()?.cast_ref()?,
            cred_values.into(),
            revocation_config
                .as_ref()
                .map(TryInto::try_into)
                .transpose()?,
        )?;
        let cred = ObjectHandle::create(cred)?;
        unsafe {
            *cred_p = cred;
        };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn anoncreds_encode_credential_attributes(
    attr_raw_values: FfiStrList,
    result_p: *mut *const c_char,
) -> ErrorCode {
    catch_error(|| {
        let mut result = String::new();
        for raw_val in attr_raw_values.as_slice() {
            let enc_val = encode_credential_attribute(
                raw_val
                    .as_opt_str()
                    .ok_or_else(|| err_msg!("Missing attribute raw value"))?,
            )?;
            if !result.is_empty() {
                result.push(',');
            }
            result.push_str(enc_val.as_str());
        }
        unsafe { *result_p = rust_string_to_c(result) };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn anoncreds_process_credential(
    cred: ObjectHandle,
    cred_req_metadata: ObjectHandle,
    link_secret: FfiStr,
    cred_def: ObjectHandle,
    rev_reg_def: ObjectHandle,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(cred_p);

        let link_secret = _link_secret(link_secret)?;

        let mut cred = cred
            .load()?
            .cast_ref::<Credential>()?
            .try_clone()
            .map_err(err_map!(Unexpected, "Error copying credential"))?;
        process_credential(
            &mut cred,
            cred_req_metadata.load()?.cast_ref()?,
            &link_secret,
            cred_def.load()?.cast_ref()?,
            rev_reg_def
                .opt_load()?
                .as_ref()
                .map(AnoncredsObject::cast_ref)
                .transpose()?,
        )?;
        let cred = ObjectHandle::create(cred)?;
        unsafe { *cred_p = cred };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn anoncreds_credential_get_attribute(
    handle: ObjectHandle,
    name: FfiStr,
    result_p: *mut *const c_char,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(result_p);
        let cred = handle.load()?;
        let cred = cred.cast_ref::<Credential>()?;
        let val = match name.as_opt_str().unwrap_or_default() {
            "schema_id" => rust_string_to_c(cred.schema_id.clone()),
            "cred_def_id" => rust_string_to_c(cred.cred_def_id.to_string()),
            "rev_reg_id" => cred
                .rev_reg_id
                .as_ref()
                .map_or(ptr::null_mut(), |s| rust_string_to_c(s.to_string())),
            "rev_reg_index" => cred
                .signature
                .extract_index()
                .map_or(ptr::null_mut(), |s| rust_string_to_c(s.to_string())),
            s => return Err(err_msg!("Unsupported attribute: {}", s)),
        };
        unsafe { *result_p = val };
        Ok(())
    })
}

/// Create Credential in W3C form according to the specification.
///
/// # Params
/// cred_def:              object handle pointing to the credential definition
/// cred_def_private:      object handle pointing to the private part of credential definition
/// cred_offer:            object handle pointing to the credential offer
/// cred_request:          object handle pointing to the credential request
/// attr_names:            list of attribute names
/// attr_raw_values:       list of attribute raw values
/// encoding:              encoding algorithm to apply for attribute values
/// revocation:            object handle pointing to the credential revocation info
/// cred_p:                reference that will contain credential (in W3C form) instance pointer
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_w3c_create_credential(
    cred_def: ObjectHandle,
    cred_def_private: ObjectHandle,
    cred_offer: ObjectHandle,
    cred_request: ObjectHandle,
    attr_names: FfiStrList,
    attr_raw_values: FfiStrList,
    encoding: FfiStr,
    revocation: *const FfiCredRevInfo,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(cred_p);

        let cred_values = _raw_credential_values(attr_names, attr_raw_values)?;
        let revocation_config = _revocation_config(revocation)?;
        let encoding = encoding.as_opt_str().map(CredentialValuesEncoding::from);

        let cred = create_w3c_credential(
            cred_def.load()?.cast_ref()?,
            cred_def_private.load()?.cast_ref()?,
            cred_offer.load()?.cast_ref()?,
            cred_request.load()?.cast_ref()?,
            cred_values.into(),
            revocation_config
                .as_ref()
                .map(TryInto::try_into)
                .transpose()?,
            encoding,
        )?;
        let cred = ObjectHandle::create(cred)?;
        unsafe {
            *cred_p = cred;
        };
        Ok(())
    })
}

/// Process an incoming W3C credential received from the issuer.
///
/// # Params
/// cred:                  object handle pointing to the credential in W3C form
/// cred_req_metadata:     object handle pointing to the credential request metadata
/// link_secret:           holder link secret
/// cred_def:              object handle pointing to the credential definition
/// rev_reg_def:           object handle pointing to the revocation registry definition
/// cred_p:                reference that will contain credential (in W3C form) instance pointer
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_w3c_process_credential(
    cred: ObjectHandle,
    cred_req_metadata: ObjectHandle,
    link_secret: FfiStr,
    cred_def: ObjectHandle,
    rev_reg_def: ObjectHandle,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(cred_p);

        let link_secret = _link_secret(link_secret)?;

        let mut cred = cred
            .load()?
            .cast_ref::<W3CCredential>()?
            .clone();
        process_w3c_credential(
            &mut cred,
            cred_req_metadata.load()?.cast_ref()?,
            &link_secret,
            cred_def.load()?.cast_ref()?,
            rev_reg_def
                .opt_load()?
                .as_ref()
                .map(AnoncredsObject::cast_ref)
                .transpose()?,
        )?;
        let cred = ObjectHandle::create(cred)?;
        unsafe { *cred_p = cred };
        Ok(())
    })
}

/// Convert credential in legacy form into W3C AnonCreds credential form
///
/// # Params
/// cred:       object handle pointing to credential in legacy form to convert
/// cred_p:     reference that will contain converted credential (in W3C form) instance pointer
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_credential_to_w3c(
    cred: ObjectHandle,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(cred_p);

        let credential = cred.load()?;
        let credential = credential.cast_ref::<Credential>()?;

        let w3c_credential = credential_to_w3c(&credential)?;
        let w3c_cred = ObjectHandle::create(w3c_credential)?;

        unsafe { *cred_p = w3c_cred };
        Ok(())
    })
}

/// Convert credential in W3C form into legacy credential form
///
/// # Params
/// cred:       object handle pointing to credential in W3C form to convert
/// cred_p:     reference that will contain converted credential (in legacy form) instance pointer
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_credential_from_w3c(
    cred: ObjectHandle,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(cred_p);

        let credential = cred.load()?;
        let credential = credential.cast_ref::<W3CCredential>()?;

        let credential = credential_from_w3c(&credential)?;
        let cred = ObjectHandle::create(credential)?;

        unsafe { *cred_p = cred };
        Ok(())
    })
}

/// Add Non-Anoncreds Data Integrity proof signature to W3C AnonCreds credential
///
/// # Params
/// cred -      object handle pointing to W3C AnonCreds credential
/// proof -     data integrity proof as JSON string
/// cred_p:     reference that will contain update credential
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_w3c_credential_add_non_anoncreds_integrity_proof(
    cred: ObjectHandle,
    proof: FfiStr,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(cred_p);

        let proof = proof
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing proof"))?;
        let proof = NonAnonCredsDataIntegrityProof::try_from(proof)
            .map_err(|_| err_msg!("Unable to parse proof"))?;

        let mut cred = cred
            .load()?
            .cast_ref::<W3CCredential>()?
            .clone();

        cred.add_non_anoncreds_identity_proof(proof);

        let cred = ObjectHandle::create(cred)?;
        unsafe { *cred_p = cred };

        Ok(())
    })
}

/// Set id to W3C AnonCreds credential
///
/// # Params
/// cred -      object handle pointing to W3C AnonCreds credential
/// id -        id to add into credential
/// cred_p:     reference that will contain update credential
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_w3c_credential_id(
    cred: ObjectHandle,
    id: FfiStr,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(cred_p);

        let id = id
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing id"))?;

        let mut cred = cred
            .load()?
            .cast_ref::<W3CCredential>()?
            .clone();

        cred.set_id(URI::from(id));

        let cred = ObjectHandle::create(cred)?;
        unsafe { *cred_p = cred };

        Ok(())
    })
}

/// Set subject id to W3C AnonCreds credential
///
/// # Params
/// cred -      object handle pointing to W3C AnonCreds credential
/// id -        subject id to add into credential
/// cred_p:     reference that will contain update credential
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_w3c_credential_subject_id(
    cred: ObjectHandle,
    id: FfiStr,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(cred_p);

        let id = id
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing id"))?;

        let mut cred = cred
            .load()?
            .cast_ref::<W3CCredential>()?
            .clone();

        cred.set_subject_id(URI::from(id));

        let cred = ObjectHandle::create(cred)?;
        unsafe { *cred_p = cred };

        Ok(())
    })
}

/// Add context to W3C AnonCreds credential
///
/// # Params
/// cred -      object handle pointing to W3C AnonCreds credential
/// context -   context to add into credential
/// cred_p:     reference that will contain update credential
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_w3c_credential_add_context(
    cred: ObjectHandle,
    context: FfiStr,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(cred_p);

        let context = context
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing context"))?;

        let mut cred = cred
            .load()?
            .cast_ref::<W3CCredential>()?
            .clone();

        cred.add_context(URI::from(context));

        let cred = ObjectHandle::create(cred)?;
        unsafe { *cred_p = cred };

        Ok(())
    })
}

/// Add type to W3C AnonCreds credential
///
/// # Params
/// cred -      object handle pointing to W3C AnonCreds credential
/// type -      type to add into credential
/// cred_p:     reference that will contain update credential
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_w3c_credential_add_type(
    cred: ObjectHandle,
    type_: FfiStr,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(cred_p);

        let type_ = type_
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing type"))?;

        let mut cred = cred
            .load()?
            .cast_ref::<W3CCredential>()?
            .clone();

        cred.add_type(type_.to_string());

        let cred = ObjectHandle::create(cred)?;
        unsafe { *cred_p = cred };

        Ok(())
    })
}

fn _encoded_credential_values(
    attr_names: FfiStrList,
    attr_raw_values: FfiStrList,
    attr_enc_values: FfiStrList,
) -> Result<CredentialValues> {
    if attr_names.is_empty() {
        return Err(err_msg!("Cannot create credential with no attribute"));
    }
    if attr_names.len() != attr_raw_values.len() {
        return Err(err_msg!(
                "Mismatch between length of attribute names and raw values"
            ));
    }
    let enc_values = attr_enc_values.as_slice();
    let mut cred_values = MakeCredentialValues::default();
    for (attr_idx, (name, raw)) in attr_names
        .as_slice()
        .iter()
        .zip(attr_raw_values.as_slice())
        .enumerate()
    {
        let name = name
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing attribute name"))?
            .to_string();
        let raw = raw
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing attribute raw value"))?
            .to_string();
        let encoded = if attr_idx < enc_values.len() {
            enc_values[attr_idx].as_opt_str().map(str::to_string)
        } else {
            None
        };
        if let Some(encoded) = encoded {
            cred_values.add_encoded(name, raw, encoded);
        } else {
            cred_values.add_raw(name, raw)?;
        }
    }
    Ok(cred_values.into())
}

fn _raw_credential_values(
    attr_names: FfiStrList,
    attr_raw_values: FfiStrList,
) -> Result<RawCredentialValues> {
    if attr_names.is_empty() {
        return Err(err_msg!("Cannot create credential with no attribute"));
    }
    if attr_names.len() != attr_raw_values.len() {
        return Err(err_msg!(
                "Mismatch between length of attribute names and raw values"
            ));
    }
    let mut cred_values = MakeRawCredentialValues::default();
    for (name, raw) in attr_names
        .as_slice()
        .iter()
        .zip(attr_raw_values.as_slice())
    {
        let name = name
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing attribute name"))?
            .to_string();
        let raw = raw
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing attribute raw value"))?
            .to_string();
        cred_values.add(name, raw);
    }
    Ok(cred_values.into())
}

fn _revocation_config(revocation: *const FfiCredRevInfo) -> Result<Option<RevocationConfig>> {
    let revocation_config = if revocation.is_null() {
        None
    } else {
        let revocation = unsafe { &*revocation };
        Some(RevocationConfig::try_from(revocation)?)
    };
    Ok(revocation_config)
}

fn _link_secret(
    link_secret: FfiStr,
) -> Result<LinkSecret> {
    let link_secret = link_secret
        .as_opt_str()
        .ok_or_else(|| err_msg!("Missing link secret"))?;
    let link_secret = LinkSecret::try_from(link_secret)?;
    Ok(link_secret)
}