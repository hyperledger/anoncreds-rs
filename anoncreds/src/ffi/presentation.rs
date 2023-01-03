use std::collections::HashMap;

use ffi_support::FfiStr;

use super::error::{catch_error, ErrorCode};
use super::object::{AnonCredsObject, AnonCredsObjectList, ObjectHandle};
use super::util::{FfiList, FfiStrList};
use crate::data_types::anoncreds::cred_def::{CredentialDefinition, CredentialDefinitionId};
use crate::data_types::anoncreds::rev_reg::RevocationRegistryId;
use crate::data_types::anoncreds::rev_reg_def::{
    RevocationRegistryDefinition, RevocationRegistryDefinitionId,
};
use crate::data_types::anoncreds::schema::{Schema, SchemaId};
use crate::error::Result;
use crate::services::{
    prover::create_presentation,
    types::{PresentCredentials, Presentation},
    verifier::verify_presentation,
};

impl_anoncreds_object!(Presentation, "Presentation");
impl_anoncreds_object_from_json!(Presentation, anoncreds_presentation_from_json);

#[derive(Debug)]
#[repr(C)]
pub struct FfiCredentialEntry {
    credential: ObjectHandle,
    timestamp: i64,
    rev_state: ObjectHandle,
}

impl FfiCredentialEntry {
    fn load(&self) -> Result<CredentialEntry> {
        let credential = self.credential.load()?;
        let timestamp = if self.timestamp < 0 {
            None
        } else {
            Some(self.timestamp as u64)
        };
        let rev_state = self.rev_state.opt_load()?;
        Ok(CredentialEntry {
            credential,
            timestamp,
            rev_state,
        })
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct FfiCredentialProve<'a> {
    entry_idx: i64,
    referent: FfiStr<'a>,
    is_predicate: i8,
    reveal: i8,
}

struct CredentialEntry {
    credential: AnonCredsObject,
    timestamp: Option<u64>,
    rev_state: Option<AnonCredsObject>,
}

#[no_mangle]
pub extern "C" fn anoncreds_create_presentation(
    pres_req: ObjectHandle,
    credentials: FfiList<FfiCredentialEntry>,
    credentials_prove: FfiList<FfiCredentialProve>,
    self_attest_names: FfiStrList,
    self_attest_values: FfiStrList,
    master_secret: ObjectHandle,
    schemas: FfiList<ObjectHandle>,
    schema_ids: FfiStrList,
    cred_defs: FfiList<ObjectHandle>,
    cred_def_ids: FfiStrList,
    presentation_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(presentation_p);

        if self_attest_names.len() != self_attest_values.len() {
            return Err(err_msg!(
                "Inconsistent lengths for self-attested value parameters"
            ));
        }

        if schemas.len() != schema_ids.len() {
            return Err(err_msg!("Inconsistent lengths for schemas and schemas ids"));
        }

        if cred_defs.len() != cred_def_ids.len() {
            return Err(err_msg!(
                "Inconsistent lengths for cred defs and cred def ids"
            ));
        }

        let entries = {
            let credentials = credentials.as_slice();
            credentials.iter().try_fold(
                Vec::with_capacity(credentials.len()),
                |mut r, ffi_entry| {
                    r.push(ffi_entry.load()?);
                    Result::Ok(r)
                },
            )?
        };

        let self_attested = if !self_attest_names.is_empty() {
            let mut self_attested = HashMap::new();
            for (name, raw) in self_attest_names
                .as_slice()
                .iter()
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
                self_attested.insert(name, raw);
            }
            Some(self_attested)
        } else {
            None
        };

        let mut present_creds = PresentCredentials::default();

        for (entry_idx, entry) in entries.iter().enumerate() {
            let mut add_cred = present_creds.add_credential(
                entry.credential.cast_ref()?,
                entry.timestamp,
                entry
                    .rev_state
                    .as_ref()
                    .map(AnonCredsObject::cast_ref)
                    .transpose()?,
            );

            for prove in credentials_prove.as_slice() {
                if prove.entry_idx < 0 {
                    return Err(err_msg!("Invalid credential index"));
                }
                if prove.entry_idx as usize != entry_idx {
                    continue;
                }

                let referent = prove
                    .referent
                    .as_opt_str()
                    .ok_or_else(|| err_msg!("Missing referent for credential proof info"))?
                    .to_string();

                if prove.is_predicate == 0 {
                    add_cred.add_requested_attribute(referent, prove.reveal != 0);
                } else {
                    add_cred.add_requested_predicate(referent);
                }
            }
        }

        let mut schema_identifiers: Vec<SchemaId> = vec![];
        for schema_id in schema_ids.as_slice().iter() {
            let s = SchemaId::new(schema_id.as_str())?;
            schema_identifiers.push(s);
        }

        let mut cred_def_identifiers: Vec<CredentialDefinitionId> = vec![];
        for cred_def_id in cred_def_ids.as_slice().iter() {
            let cred_def_id = CredentialDefinitionId::new(cred_def_id.as_str())?;
            cred_def_identifiers.push(cred_def_id);
        }

        let schemas = AnonCredsObjectList::load(schemas.as_slice())?;
        let schemas = schemas.refs_map::<SchemaId, Schema>(&schema_identifiers)?;

        let cred_defs = AnonCredsObjectList::load(cred_defs.as_slice())?;
        let cred_defs = cred_defs
            .refs_map::<CredentialDefinitionId, CredentialDefinition>(&cred_def_identifiers)?;

        let presentation = create_presentation(
            pres_req.load()?.cast_ref()?,
            present_creds,
            self_attested,
            master_secret.load()?.cast_ref()?,
            &schemas,
            &cred_defs,
        )?;
        let presentation = ObjectHandle::create(presentation)?;
        unsafe { *presentation_p = presentation };
        Ok(())
    })
}

#[derive(Debug)]
#[repr(C)]
pub struct FfiRevocationEntry {
    def_entry_idx: i64,
    entry: ObjectHandle,
    timestamp: i64,
}

impl FfiRevocationEntry {
    fn load(&self) -> Result<(usize, AnonCredsObject, u64)> {
        let def_entry_idx = self
            .def_entry_idx
            .try_into()
            .map_err(|_| err_msg!("Invalid revocation registry entry index"))?;
        let entry = self.entry.load()?;
        let timestamp = self
            .timestamp
            .try_into()
            .map_err(|_| err_msg!("Invalid timestamp for revocation entry"))?;
        Ok((def_entry_idx, entry, timestamp))
    }
}

#[no_mangle]
pub extern "C" fn anoncreds_verify_presentation(
    presentation: ObjectHandle,
    pres_req: ObjectHandle,
    schemas: FfiList<ObjectHandle>,
    schema_ids: FfiStrList,
    cred_defs: FfiList<ObjectHandle>,
    cred_def_ids: FfiStrList,
    rev_reg_defs: FfiList<ObjectHandle>,
    rev_reg_def_ids: FfiStrList,
    rev_reg_entries: FfiList<FfiRevocationEntry>,
    result_p: *mut i8,
) -> ErrorCode {
    catch_error(|| {
        if schemas.len() != schema_ids.len() {
            return Err(err_msg!("Inconsistent lengths for schemas and schemas ids"));
        }

        if cred_defs.len() != cred_def_ids.len() {
            return Err(err_msg!(
                "Inconsistent lengths for cred defs and cred def ids"
            ));
        }

        if rev_reg_defs.len() != rev_reg_def_ids.len() {
            return Err(err_msg!(
                "Inconsistent lengths for rev reg defs and rev reg def ids"
            ));
        }

        let rev_reg_entries = {
            let entries = rev_reg_entries.as_slice();
            entries
                .iter()
                .try_fold(Vec::with_capacity(entries.len()), |mut r, ffi_entry| {
                    r.push(ffi_entry.load()?);
                    Result::Ok(r)
                })?
        };
        let mut rev_regs = HashMap::new();
        for (idx, entry, timestamp) in rev_reg_entries.iter() {
            if *idx > rev_reg_defs.len() {
                return Err(err_msg!("Invalid revocation registry entry index"));
            }
            let id = rev_reg_def_ids.as_slice()[*idx].as_str().to_owned();
            let id = RevocationRegistryId::new(id)?;
            rev_regs
                .entry(id)
                .or_insert_with(HashMap::new)
                .insert(*timestamp, entry.cast_ref()?);
        }

        let mut schema_identifiers: Vec<SchemaId> = vec![];
        for schema_id in schema_ids.as_slice().iter() {
            let s = SchemaId::new(schema_id.as_str())?;
            schema_identifiers.push(s);
        }

        let mut cred_def_identifiers: Vec<CredentialDefinitionId> = vec![];
        for cred_def_id in cred_def_ids.as_slice().iter() {
            let cred_def_id = CredentialDefinitionId::new(cred_def_id.as_str())?;
            cred_def_identifiers.push(cred_def_id);
        }

        let mut rev_reg_def_identifiers: Vec<RevocationRegistryDefinitionId> = vec![];
        for rev_reg_def_id in rev_reg_def_ids.as_slice().iter() {
            let rev_reg_def_id = RevocationRegistryDefinitionId::new(rev_reg_def_id.as_str())?;
            rev_reg_def_identifiers.push(rev_reg_def_id);
        }

        let schemas = AnonCredsObjectList::load(schemas.as_slice())?;
        let schemas = schemas.refs_map::<SchemaId, Schema>(&schema_identifiers)?;

        let cred_defs = AnonCredsObjectList::load(cred_defs.as_slice())?;
        let cred_defs = cred_defs
            .refs_map::<CredentialDefinitionId, CredentialDefinition>(&cred_def_identifiers)?;

        let rev_reg_defs = AnonCredsObjectList::load(rev_reg_defs.as_slice())?;
        let rev_reg_defs = rev_reg_defs
            .refs_map::<RevocationRegistryDefinitionId, RevocationRegistryDefinition>(
                &rev_reg_def_identifiers,
            )?;

        let verify = verify_presentation(
            presentation.load()?.cast_ref()?,
            pres_req.load()?.cast_ref()?,
            &schemas,
            &cred_defs,
            Some(&rev_reg_defs),
            Some(&rev_regs),
        )?;
        unsafe { *result_p = verify as i8 };
        Ok(())
    })
}
