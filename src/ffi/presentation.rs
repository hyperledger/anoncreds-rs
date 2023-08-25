use super::error::{catch_error, ErrorCode};
use super::object::{AnoncredsObject, AnoncredsObjectList, ObjectHandle};
use super::util::{FfiList, FfiStrList};
use crate::data_types::cred_def::{CredentialDefinition, CredentialDefinitionId};
use crate::data_types::link_secret::LinkSecret;
use crate::data_types::presentation::Presentation;
use crate::data_types::rev_reg_def::RevocationRegistryDefinition;
use crate::data_types::rev_reg_def::RevocationRegistryDefinitionId;
use crate::data_types::rev_status_list::RevocationStatusList;
use crate::data_types::schema::{Schema, SchemaId};
use crate::error::Result;
use crate::services::prover::create_presentation;
use crate::services::types::PresentCredentials;
use crate::services::verifier::verify_presentation;
use ffi_support::FfiStr;
use std::collections::HashMap;

impl_anoncreds_object!(Presentation, "Presentation");
impl_anoncreds_object_from_json!(Presentation, anoncreds_presentation_from_json);

#[derive(Debug)]
#[repr(C)]
pub struct FfiCredentialEntry {
    credential: ObjectHandle,
    timestamp: i32,
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
    credential: AnoncredsObject,
    timestamp: Option<u64>,
    rev_state: Option<AnoncredsObject>,
}

#[no_mangle]
pub extern "C" fn anoncreds_create_presentation(
    pres_req: ObjectHandle,
    credentials: FfiList<FfiCredentialEntry>,
    credentials_prove: FfiList<FfiCredentialProve>,
    self_attest_names: FfiStrList,
    self_attest_values: FfiStrList,
    link_secret: FfiStr,
    schemas: FfiList<ObjectHandle>,
    schema_ids: FfiStrList,
    cred_defs: FfiList<ObjectHandle>,
    cred_def_ids: FfiStrList,
    presentation_p: *mut ObjectHandle,
) -> ErrorCode {
    catch_error(|| {
        check_useful_c_ptr!(presentation_p);

        let link_secret = link_secret
            .as_opt_str()
            .ok_or_else(|| err_msg!("Missing link secret"))?;
        let link_secret = LinkSecret::try_from(link_secret)?;

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

        let self_attested = if self_attest_names.is_empty() {
            None
        } else {
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
        };

        let mut present_creds = PresentCredentials::default();

        for (entry_idx, entry) in entries.iter().enumerate() {
            let mut add_cred = present_creds.add_credential(
                entry.credential.cast_ref()?,
                entry.timestamp,
                entry
                    .rev_state
                    .as_ref()
                    .map(AnoncredsObject::cast_ref)
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
        for schema_id in &schema_ids.to_string_vec()? {
            let s = SchemaId::new(schema_id.as_str())?;
            schema_identifiers.push(s);
        }

        let mut cred_def_identifiers: Vec<CredentialDefinitionId> = vec![];
        for cred_def_id in &cred_def_ids.to_string_vec()? {
            let cred_def_id = CredentialDefinitionId::new(cred_def_id.as_str())?;
            cred_def_identifiers.push(cred_def_id);
        }

        let schemas = AnoncredsObjectList::load(schemas.as_slice())?;
        let schemas = schemas
            .refs_map::<SchemaId, Schema>(&schema_identifiers)?
            .into_iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let cred_defs = AnoncredsObjectList::load(cred_defs.as_slice())?;
        let cred_defs = cred_defs
            .refs_map::<CredentialDefinitionId, CredentialDefinition>(&cred_def_identifiers)?
            .into_iter()
            .map(|(k, v)| v.try_clone().map(|v| (k.clone(), v)))
            .collect::<Result<_>>()?;

        let presentation = create_presentation(
            pres_req.load()?.cast_ref()?,
            present_creds,
            self_attested,
            &link_secret,
            &schemas,
            &cred_defs,
        )?;

        let presentation = ObjectHandle::create(presentation)?;
        unsafe { *presentation_p = presentation };
        Ok(())
    })
}

/// Optional value for overriding the non-revoked interval in the [`PresentationRequest`]
/// This only overrides the `from` value as a Revocation Status List is deemed valid until the next
/// entry.
///
/// E.g. if the ledger has Revocation Status List at timestamps [0, 100, 200],
/// let's call them List0, List100, List200. Then:  
///
/// ```txt
///
///       List0 is valid  List100 is valid
///        ______|_______ _______|_______
///       |              |               |
/// List  0 ----------- 100 ----------- 200
/// ```
///
/// A `nonrevoked_interval = {from: 50, to: 150}` should accept both List0 and
/// List100.  
///
#[derive(Debug)]
#[repr(C)]
pub struct FfiNonrevokedIntervalOverride<'a> {
    rev_reg_def_id: FfiStr<'a>,
    /// Timestamp in the `PresentationRequest`
    requested_from_ts: i32,
    /// Timestamp from which verifier accepts,
    /// should be less than `req_timestamp`
    override_rev_status_list_ts: i32,
}

impl<'a> FfiNonrevokedIntervalOverride<'a> {
    fn load(&self) -> Result<(RevocationRegistryDefinitionId, u64, u64)> {
        let id = RevocationRegistryDefinitionId::new(self.rev_reg_def_id.as_str().to_owned())?;
        let requested_from_ts = self
            .requested_from_ts
            .try_into()
            .map_err(|_| err_msg!("Invalid req timestamp "))?;
        let override_rev_status_list_ts = self
            .override_rev_status_list_ts
            .try_into()
            .map_err(|_| err_msg!("Invalid override timestamp "))?;
        Ok((id, requested_from_ts, override_rev_status_list_ts))
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
    rev_status_list: FfiList<ObjectHandle>,
    nonrevoked_interval_override: FfiList<FfiNonrevokedIntervalOverride>,
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

        let schemas = AnoncredsObjectList::load(schemas.as_slice())?;
        let schemas = schemas
            .refs_map::<SchemaId, Schema>(&schema_identifiers)?
            .into_iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let cred_defs = AnoncredsObjectList::load(cred_defs.as_slice())?;
        let cred_defs = cred_defs
            .refs_map::<CredentialDefinitionId, CredentialDefinition>(&cred_def_identifiers)?
            .into_iter()
            .map(|(k, v)| v.try_clone().map(|v| (k.clone(), v)))
            .collect::<Result<_>>()?;

        let rev_reg_defs = AnoncredsObjectList::load(rev_reg_defs.as_slice())?;
        let rev_reg_defs = rev_reg_defs
            .refs_map::<RevocationRegistryDefinitionId, RevocationRegistryDefinition>(
                &rev_reg_def_identifiers,
            )?
            .into_iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<HashMap<_, _>>();

        let rev_reg_defs = if rev_reg_defs.is_empty() {
            None
        } else {
            Some(&rev_reg_defs)
        };

        let rev_status_list: AnoncredsObjectList =
            AnoncredsObjectList::load(rev_status_list.as_slice())?;
        let rev_status_list: Result<Vec<&RevocationStatusList>> = rev_status_list.refs();
        let rev_status_list = rev_status_list.ok();

        let override_entries = {
            let override_ffi_entries = nonrevoked_interval_override.as_slice();
            override_ffi_entries.iter().try_fold(
                Vec::with_capacity(override_ffi_entries.len()),
                |mut v, entry| -> Result<Vec<(RevocationRegistryDefinitionId, u64, u64)>> {
                    v.push(entry.load()?);
                    Ok(v)
                },
            )?
        };
        let mut map_nonrevoked_interval_override = HashMap::new();
        for (id, req_timestamp, override_timestamp) in &override_entries {
            map_nonrevoked_interval_override
                .entry(id.clone())
                .or_insert_with(HashMap::new)
                .insert(*req_timestamp, *override_timestamp);
        }

        let rev_status_lists = rev_status_list
            .as_ref()
            .map(|v| v.iter().copied().cloned().collect());

        let verify = verify_presentation(
            presentation.load()?.cast_ref()?,
            pres_req.load()?.cast_ref()?,
            &schemas,
            &cred_defs,
            rev_reg_defs,
            rev_status_lists,
            Some(&map_nonrevoked_interval_override),
        )?;
        unsafe { *result_p = i8::from(verify) };
        Ok(())
    })
}
