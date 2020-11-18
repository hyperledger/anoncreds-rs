use std::collections::HashMap;

use ffi_support::FfiStr;

use super::error::{catch_error, ErrorCode};
use super::object::ObjectHandle;
use super::util::{FfiList, FfiStrList};
use crate::error::Result;
use crate::services::{
    prover::create_presentation,
    types::{CredentialDefinition, Presentation, RequestedCredentials, Schema},
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
    proof_req: ObjectHandle,
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

        let load_creds = creds
            .as_slice()
            .into_iter()
            .map(ObjectHandle::load)
            .collect::<Result<Vec<_>>>()?;
        let mut map_creds = HashMap::with_capacity(load_creds.len());
        for (idx, cred) in load_creds.iter().enumerate() {
            map_creds.insert(idx.to_string(), cred.cast_ref()?);
        }

        let load_schemas = schemas
            .as_slice()
            .into_iter()
            .map(ObjectHandle::load)
            .collect::<Result<Vec<_>>>()?;
        let mut map_schemas = HashMap::with_capacity(load_schemas.len());
        for schema in load_schemas.iter() {
            let schema = schema.cast_ref()?;
            let sid = match schema {
                Schema::SchemaV1(s) => s.id.clone(),
            };
            map_schemas.insert(sid, schema);
        }

        let load_cred_defs = cred_defs
            .as_slice()
            .into_iter()
            .map(ObjectHandle::load)
            .collect::<Result<Vec<_>>>()?;
        let mut map_cred_defs = HashMap::with_capacity(load_cred_defs.len());
        for cred_def in load_cred_defs.iter() {
            let cred_def = cred_def.cast_ref()?;
            let cid = match cred_def {
                CredentialDefinition::CredentialDefinitionV1(c) => c.id.clone(),
            };
            map_cred_defs.insert(cid, cred_def);
        }

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
            if prove.cred_idx < 0 || prove.cred_idx as usize >= load_creds.len() {
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
            proof_req.load()?.cast_ref()?,
            &map_creds,
            &req_creds,
            master_secret.load()?.cast_ref()?,
            &map_schemas,
            &map_cred_defs,
            &map_rev_states,
        )?;
        let presentation = ObjectHandle::create(presentation)?;
        unsafe { *presentation_p = presentation };
        Ok(())
    })
}
