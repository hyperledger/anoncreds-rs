use std::collections::HashMap;

use ffi_support::FfiStr;

use super::error::{catch_error, ErrorCode};
use super::object::{IndyObjectList, ObjectHandle};
use super::util::{FfiList, FfiStrList};
use crate::services::{
    prover::create_presentation,
    types::{Presentation, RequestedCredentials},
    verifier::verify_presentation,
};

impl_indy_object!(Presentation, "Presentation");
impl_indy_object_from_json!(Presentation, credx_presentation_from_json);

#[derive(Debug)]
#[repr(C)]
pub struct FfiCredentialProve<'a> {
    cred_idx: i64,
    referent: FfiStr<'a>,
    is_predicate: i8,
    reveal: i8,
    timestamp: i64,
}

#[no_mangle]
pub extern "C" fn credx_create_presentation(
    pres_req: ObjectHandle,
    self_attest_names: FfiStrList,
    self_attest_values: FfiStrList,
    creds: FfiList<ObjectHandle>,
    creds_prove: FfiList<FfiCredentialProve>,
    master_secret: ObjectHandle,
    schemas: FfiList<ObjectHandle>,
    cred_defs: FfiList<ObjectHandle>,
    presentation_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(presentation_p);
        if self_attest_names.len() != self_attest_values.len() {
            return Err(err_msg!(
                "Inconsistent lengths for self-attested value parameters"
            ));
        }

        let creds = IndyObjectList::load(creds.as_slice())?;
        let mut map_creds = HashMap::with_capacity(creds.len());
        for (idx, cred) in creds.iter().enumerate() {
            map_creds.insert(idx.to_string(), cred.cast_ref()?);
        }

        let schemas = IndyObjectList::load(schemas.as_slice())?;
        let cred_defs = IndyObjectList::load(cred_defs.as_slice())?;

        let mut req_creds = RequestedCredentials::default();
        for (name, raw) in self_attest_names
            .as_slice()
            .into_iter()
            .zip(self_attest_values.as_slice())
        {
            let name = name
                .as_opt_str()
                .ok_or_else(|| err_msg!("Missing attribute name"))?
                .to_string();
            let raw = raw
                .as_opt_str()
                .ok_or_else(|| err_msg!("Missing attribute raw value"))?
                .to_string();
            req_creds.add_self_attested(name, raw);
        }
        for prove in creds_prove.as_slice() {
            if prove.cred_idx < 0 || prove.cred_idx as usize >= creds.len() {
                return Err(err_msg!("Invalid index for credential reference"));
            }
            let referent = prove
                .referent
                .as_opt_str()
                .ok_or_else(|| err_msg!("Missing referent for credential proof info"))?
                .to_string();
            let timestamp = if prove.timestamp < 0 {
                None
            } else {
                Some(prove.timestamp as u64)
            };
            if prove.is_predicate == 0 {
                req_creds.add_requested_attribute(
                    referent,
                    prove.cred_idx.to_string(),
                    timestamp,
                    prove.reveal != 0,
                );
            } else {
                req_creds.add_requested_predicate(referent, prove.cred_idx.to_string(), timestamp);
            }
        }

        let map_rev_states = HashMap::new();

        let presentation = create_presentation(
            pres_req.load()?.cast_ref()?,
            &map_creds,
            &req_creds,
            master_secret.load()?.cast_ref()?,
            &schemas.refs()?,
            &cred_defs.refs()?,
            &map_rev_states,
        )?;
        let presentation = ObjectHandle::create(presentation)?;
        unsafe { *presentation_p = presentation };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn credx_verify_presentation(
    presentation: ObjectHandle,
    pres_req: ObjectHandle,
    schemas: FfiList<ObjectHandle>,
    cred_defs: FfiList<ObjectHandle>,
    result_p: *mut i8,
) -> ErrorCode {
    catch_error(|| {
        let schemas = IndyObjectList::load(schemas.as_slice())?;
        let cred_defs = IndyObjectList::load(cred_defs.as_slice())?;
        let rev_reg_defs = HashMap::new();
        let rev_regs = HashMap::new();
        let verify = verify_presentation(
            presentation.load()?.cast_ref()?,
            pres_req.load()?.cast_ref()?,
            &schemas.refs()?,
            &cred_defs.refs()?,
            &rev_reg_defs,
            &rev_regs,
        )?;
        unsafe { *result_p = verify as i8 };
        Ok(())
    })
}
