use std::ffi::c_char;
use std::ptr;
use crate::data_types::w3c::VerifiableCredentialSpecVersion;
use ffi_support::{FfiStr, rust_string_to_c};

use crate::data_types::w3c::credential::W3CCredential;
use crate::data_types::w3c::credential_attributes::CredentialAttributes;
use crate::data_types::w3c::proof::CredentialProofDetails;
use crate::error::Result;
use crate::ffi::credential::{FfiCredRevInfo, _link_secret, _revocation_config};
use crate::ffi::error::{catch_error, ErrorCode};
use crate::ffi::object::{AnoncredsObject, ObjectHandle};
use crate::ffi::util::FfiStrList;
use crate::types::Credential;
use crate::w3c::credential_conversion::{credential_from_w3c, credential_to_w3c};
use crate::w3c::issuer::create_credential;
use crate::w3c::prover::process_credential;
use crate::w3c::types::MakeCredentialAttributes;

impl_anoncreds_object!(W3CCredential, "W3CCredential");
impl_anoncreds_object_from_json!(W3CCredential, anoncreds_w3c_credential_from_json);

/// Create Credential in W3C form according to the specification.
///
/// # Params
/// cred_def:              object handle pointing to the credential definition
/// cred_def_private:      object handle pointing to the private part of credential definition
/// cred_offer:            object handle pointing to the credential offer
/// cred_request:          object handle pointing to the credential request
/// attr_names:            list of attribute names
/// attr_raw_values:       list of attribute raw values
/// revocation:            object handle pointing to the credential revocation info
/// version:               version of w3c verifiable credential specification (1.1 or 2.0) to use
/// cred_p:                reference that will contain credential (in W3C form) instance pointer
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_create_w3c_credential(
    cred_def: ObjectHandle,
    cred_def_private: ObjectHandle,
    cred_offer: ObjectHandle,
    cred_request: ObjectHandle,
    attr_names: FfiStrList,
    attr_raw_values: FfiStrList,
    revocation: *const FfiCredRevInfo,
    version: FfiStr,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(cred_p);

        let cred_values = _credential_attributes(attr_names, attr_raw_values)?;
        let revocation_config = _revocation_config(revocation)?;
        let version = match version.as_opt_str() {
            Some(value) => Some(VerifiableCredentialSpecVersion::try_from(value)?),
            None => None,
        };

        let cred = create_credential(
            cred_def.load()?.cast_ref()?,
            cred_def_private.load()?.cast_ref()?,
            cred_offer.load()?.cast_ref()?,
            cred_request.load()?.cast_ref()?,
            cred_values,
            revocation_config
                .as_ref()
                .map(TryInto::try_into)
                .transpose()?,
            version,
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
pub extern "C" fn anoncreds_process_w3c_credential(
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

        let mut cred = cred.load()?.cast_ref::<W3CCredential>()?.clone();
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

/// Convert credential in legacy form into W3C AnonCreds credential form
///
/// # Params
/// cred:       object handle pointing to credential in legacy form to convert
/// cred_def:   object handle pointing to the credential definition
/// version:    version of w3c verifiable credential specification (1.1 or 2.0) to use
/// cred_p:     reference that will contain converted credential (in W3C form) instance pointer
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_credential_to_w3c(
    cred: ObjectHandle,
    cred_def: ObjectHandle,
    version: FfiStr,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(cred_p);

        let credential = cred.load()?;
        let credential = credential.cast_ref::<Credential>()?;
        let version = match version.as_opt_str() {
            Some(value) => Some(VerifiableCredentialSpecVersion::try_from(value)?),
            None => None,
        };

        let w3c_credential = credential_to_w3c(credential, cred_def.load()?.cast_ref()?, version)?;
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

        let credential = credential_from_w3c(credential)?;
        let cred = ObjectHandle::create(credential)?;

        unsafe { *cred_p = cred };
        Ok(())
    })
}

/// Get credential signature information required for proof building and verification
/// This information is aggregated from `anoncredsvc-2023` and `anoncredspresvc-2023` proofs.
/// It's needed for Holder and Verifier for public entities resolving
///     {`schema_id`, `cred_def_id`, `rev_reg_id`, `rev_reg_index`, `timestamp`}
///
/// # Params
/// handle:                object handle pointing to the credential (in W3 form)
/// result_p:              reference that will contain credential information
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_w3c_credential_get_integrity_proof_details(
    handle: ObjectHandle,
    cred_proof_info_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(cred_proof_info_p);
        let cred = handle.load()?;
        let cred = cred.cast_ref::<W3CCredential>()?;
        let data_integrity_proof = cred.get_data_integrity_proof()?;
        let cred_info = data_integrity_proof.get_credential_proof_details()?;
        let cred_info = ObjectHandle::create(cred_info)?;
        unsafe { *cred_proof_info_p = cred_info };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn anoncreds_w3c_credential_proof_get_attribute(
    handle: ObjectHandle,
    name: FfiStr,
    result_p: *mut *const c_char,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(result_p);
        let cred = handle.load()?;
        let cred = cred.cast_ref::<CredentialProofDetails>()?;
        let val = match name.as_opt_str().unwrap_or_default() {
            "schema_id" => rust_string_to_c(cred.schema_id.clone()),
            "cred_def_id" => rust_string_to_c(cred.cred_def_id.to_string()),
            "rev_reg_id" => cred
                .rev_reg_id
                .as_ref()
                .map_or(ptr::null_mut(), |s| rust_string_to_c(s.to_string())),
            "rev_reg_index" => cred
                .rev_reg_index
                .map_or(ptr::null_mut(), |s| rust_string_to_c(s.to_string())),
            "timestamp" => cred
                .timestamp
                .map_or(ptr::null_mut(), |s| rust_string_to_c(s.to_string())),
            s => return Err(err_msg!("Unsupported attribute: {}", s)),
        };
        unsafe { *result_p = val };
        Ok(())
    })
}

impl_anoncreds_object!(CredentialProofDetails, "CredentialProofInfo");

pub(crate) fn _credential_attributes(
    attr_names: FfiStrList,
    attr_raw_values: FfiStrList,
) -> Result<CredentialAttributes> {
    if attr_names.is_empty() {
        return Err(err_msg!("Cannot create credential with no attribute"));
    }
    if attr_names.len() != attr_raw_values.len() {
        return Err(err_msg!(
            "Mismatch between length of attribute names and raw values"
        ));
    }
    let mut cred_values = MakeCredentialAttributes::default();
    for (name, raw) in attr_names.as_slice().iter().zip(attr_raw_values.as_slice()) {
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
