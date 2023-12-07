use crate::data_types::w3c::presentation::W3CPresentation;
use crate::ffi::credential::_link_secret;
use crate::ffi::error::{catch_error, ErrorCode};
use crate::ffi::object::ObjectHandle;
use crate::ffi::presentation::{
    FfiCredentialEntry, FfiCredentialProve, FfiNonrevokedIntervalOverride, _credentials,
    _nonrevoke_interval_override, _prepare_cred_defs, _prepare_schemas, _present_credentials,
    _rev_reg_defs, _rev_status_list,
};
use crate::ffi::util::{FfiList, FfiStrList};
use crate::w3c::prover::create_presentation;
use crate::w3c::verifier::verify_presentation;
use ffi_support::FfiStr;

impl_anoncreds_object!(W3CPresentation, "W3CPresentation");
impl_anoncreds_object_from_json!(W3CPresentation, anoncreds_w3c_presentation_from_json);

/// Create W3C Presentation according to the specification.
///
/// # Params
/// pres_req:               object handle pointing to presentation request
/// credentials:            credentials (in W3C form) to use for presentation preparation
/// credentials_prove:      attributes and predicates to prove per credential
/// link_secret:            holder link secret
/// schemas:                list of credential schemas
/// schema_ids:             list of schemas ids
/// cred_defs:              list of credential definitions
/// cred_def_ids:           list of credential definitions ids
/// presentation_p:         reference that will contain created presentation (in W3C form) instance pointer.
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_create_w3c_presentation(
    pres_req: ObjectHandle,
    credentials: FfiList<FfiCredentialEntry>,
    credentials_prove: FfiList<FfiCredentialProve>,
    link_secret: FfiStr,
    schemas: FfiList<ObjectHandle>,
    schema_ids: FfiStrList,
    cred_defs: FfiList<ObjectHandle>,
    cred_def_ids: FfiStrList,
    presentation_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(presentation_p);

        let link_secret = _link_secret(link_secret)?;
        let cred_defs = _prepare_cred_defs(cred_defs, cred_def_ids)?;
        let schemas = _prepare_schemas(schemas, schema_ids)?;
        let credentials = _credentials(credentials)?;
        let present_creds = _present_credentials(&credentials, credentials_prove)?;

        let presentation = create_presentation(
            pres_req.load()?.cast_ref()?,
            present_creds,
            &link_secret,
            &schemas,
            &cred_defs,
        )?;

        let presentation = ObjectHandle::create(presentation)?;
        unsafe { *presentation_p = presentation };
        Ok(())
    })
}

/// Verity W3C styled Presentation
///
/// # Params
/// presentation:                   object handle pointing to presentation
/// pres_req:                       object handle pointing to presentation request
/// schemas:                        list of credential schemas
/// schema_ids:                     list of schemas ids
/// cred_defs:                      list of credential definitions
/// cred_def_ids:                   list of credential definitions ids
/// rev_reg_defs:                   list of revocation definitions
/// rev_reg_def_ids:                list of revocation definitions ids
/// rev_status_list:                revocation status list
/// nonrevoked_interval_override:   not-revoked interval
/// result_p:                       reference that will contain presentation verification result.
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_verify_w3c_presentation(
    presentation: ObjectHandle,
    pres_req: ObjectHandle,
    schemas: FfiList<ObjectHandle>,
    schema_ids: FfiStrList,
    cred_defs: FfiList<ObjectHandle>,
    cred_def_ids: FfiStrList,
    rev_reg_defs: FfiList<ObjectHandle>,
    rev_reg_def_ids: FfiStrList,
    rev_status_list: FfiList<ObjectHandle>,
    nonrevoked_interval_override: FfiList<FfiNonrevokedIntervalOverride>,
    result_p: *mut i8,
) -> ErrorCode {
    catch_error(|| {
        let cred_defs = _prepare_cred_defs(cred_defs, cred_def_ids)?;
        let schemas = _prepare_schemas(schemas, schema_ids)?;
        let rev_reg_defs = _rev_reg_defs(rev_reg_defs, rev_reg_def_ids)?;
        let rev_status_lists = _rev_status_list(rev_status_list)?;
        let map_nonrevoked_interval_override =
            _nonrevoke_interval_override(nonrevoked_interval_override)?;

        let verify = verify_presentation(
            presentation.load()?.cast_ref()?,
            pres_req.load()?.cast_ref()?,
            &schemas,
            &cred_defs,
            rev_reg_defs.as_ref(),
            rev_status_lists,
            Some(&map_nonrevoked_interval_override),
        )?;
        unsafe { *result_p = i8::from(verify) };
        Ok(())
    })
}
