use crate::cl::{
    bn::BigNumber, CredentialSchema, CredentialValues as CLCredentialValues, Issuer,
    NonCredentialSchema, SubProofRequest, Verifier,
};
use crate::data_types::presentation::RequestedProof;
use crate::data_types::rev_reg_def::RevocationRegistryDefinitionId;
use crate::data_types::schema::Schema;
use crate::data_types::{
    credential::CredentialValues,
    link_secret::LinkSecret,
    nonce::Nonce,
    pres_request::{NonRevokedInterval, PresentationRequestPayload},
};
use crate::error::Result;
use anoncreds_clsignatures::Predicate;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

pub fn attr_common_view(attr: &str) -> String {
    attr.replace(' ', "").to_lowercase()
}

pub fn build_credential_schema(schema: &Schema) -> Result<CredentialSchema> {
    trace!("build_credential_schema >>> schema: {:?}", schema);

    let mut credential_schema_builder = Issuer::new_credential_schema_builder()?;
    for attr in schema.attr_names.0.iter() {
        credential_schema_builder.add_attr(&attr_common_view(attr))?;
    }

    let res = credential_schema_builder.finalize()?;

    trace!("build_credential_schema <<< res: {:?}", res);

    Ok(res)
}

pub fn build_non_credential_schema() -> Result<NonCredentialSchema> {
    trace!("build_non_credential_schema");

    let mut non_credential_schema_builder = Issuer::new_non_credential_schema_builder()?;
    // value is master_secret as that's what's historically been used in published credential definitions
    non_credential_schema_builder.add_attr("master_secret")?;
    let res = non_credential_schema_builder.finalize()?;

    trace!("build_non_credential_schema <<< res: {:?}", res);
    Ok(res)
}

pub fn build_credential_values(
    credential_values: &CredentialValues,
    link_secret: Option<&LinkSecret>,
) -> Result<CLCredentialValues> {
    trace!(
        "build_credential_values >>> credential_values: {:?}",
        credential_values
    );

    let mut credential_values_builder = Issuer::new_credential_values_builder()?;
    for (attr, values) in credential_values.0.iter() {
        credential_values_builder.add_dec_known(&attr_common_view(attr), &values.encoded)?;
    }
    if let Some(ls) = link_secret {
        // value is master_secret as that's what's historically been used in published credential definitions
        credential_values_builder.add_value_hidden("master_secret", &ls.0)?;
    }

    let res = credential_values_builder.finalize()?;

    trace!("build_credential_values <<< res: {:?}", res);

    Ok(res)
}

pub fn encode_credential_attribute(raw_value: &str) -> Result<String> {
    if let Ok(val) = raw_value.parse::<i32>() {
        Ok(val.to_string())
    } else {
        let digest = Sha256::digest(raw_value.as_bytes());
        #[cfg(target_endian = "big")]
        let digest = {
            let mut d = digest;
            d.reverse();
            d
        };
        Ok(BigNumber::from_bytes(&digest)?.to_dec()?)
    }
}

pub fn build_sub_proof_request(
    attrs_for_credential: &Vec<String>,
    predicates_for_credential: &Vec<Predicate>,
) -> Result<SubProofRequest> {
    trace!(
        "build_sub_proof_request >>> attrs_for_credential: {:?}, predicates_for_credential: {:?}",
        attrs_for_credential,
        predicates_for_credential
    );

    let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder()?;

    for attr in attrs_for_credential {
        sub_proof_request_builder.add_revealed_attr(&attr_common_view(attr))?;
    }

    for predicate in predicates_for_credential {
        let p_type = format!("{:?}", predicate.p_type);

        sub_proof_request_builder.add_predicate(
            &attr_common_view(&predicate.attr_name),
            &p_type,
            predicate.value,
        )?;
    }

    let res = sub_proof_request_builder.finalize()?;

    trace!("build_sub_proof_request <<< res: {:?}", res);

    Ok(res)
}

pub fn new_nonce() -> Result<Nonce> {
    Nonce::new().map_err(err_map!(Unexpected))
}

pub fn get_non_revoked_interval(
    attrs_nonrevoked_interval: Option<NonRevokedInterval>,
    pred_nonrevoked_interval: Option<NonRevokedInterval>,
    pres_req: &PresentationRequestPayload,
    rev_reg_id: Option<&RevocationRegistryDefinitionId>,
    nonrevoke_interval_override: Option<
        &HashMap<RevocationRegistryDefinitionId, HashMap<u64, u64>>,
    >,
) -> Option<NonRevokedInterval> {
    let mut interval: Option<NonRevokedInterval> = None;

    if let Some(rev_reg_id) = rev_reg_id {
        // Collapse to the most stringent local interval for the attributes / predicates,
        // we can do this because there is only 1 revocation status list for this credential
        // if it satisfies the most stringent interval, it will satisfy all intervals
        interval = match (attrs_nonrevoked_interval, pred_nonrevoked_interval) {
            (Some(attr), None) => Some(attr),
            (None, Some(pred)) => Some(pred),
            (Some(mut attr), Some(pred)) => {
                attr.compare_and_set(&pred);
                Some(attr)
            }
            _ => None,
        };

        // Global interval is override by the local one,
        // we only need to update if local is None and Global is Some,
        // do not need to update if global is more stringent
        if let (Some(global), None) = (pres_req.non_revoked.clone(), interval.as_mut()) {
            interval = Some(global);
        };

        // Override Interval if an earlier `from` value is accepted by the verifier
        nonrevoke_interval_override.map(|maps| {
            maps.get(rev_reg_id)
                .map(|map| interval.as_mut().map(|int| int.update_with_override(map)))
        });
    }

    interval
}

pub fn get_requested_non_revoked_interval(
    rev_reg_id: Option<&RevocationRegistryDefinitionId>,
    local_nonrevoked_interval: Option<&NonRevokedInterval>,
    global_nonrevoked_interval: Option<&NonRevokedInterval>,
    nonrevoke_interval_override: Option<
        &HashMap<RevocationRegistryDefinitionId, HashMap<u64, u64>>,
    >,
) -> Option<NonRevokedInterval> {
    let mut interval: Option<NonRevokedInterval> = local_nonrevoked_interval.cloned();

    if let Some(rev_reg_id) = rev_reg_id {
        // Global interval is override by the local one,
        // we only need to update if local is None and Global is Some,
        // do not need to update if global is more stringent
        if let (Some(global), None) = (global_nonrevoked_interval, interval.as_mut()) {
            interval = Some(global.clone());
        };

        // Override Interval if an earlier `from` value is accepted by the verifier
        nonrevoke_interval_override.map(|maps| {
            maps.get(rev_reg_id)
                .map(|map| interval.as_mut().map(|int| int.update_with_override(map)))
        });
    }

    interval
}

impl PresentationRequestPayload {
    pub(crate) fn get_requested_attributes(
        &self,
        referents: &HashSet<String>,
    ) -> Result<(Vec<String>, Option<NonRevokedInterval>)> {
        trace!("get_requested_attributes >>> referents: {:?}", referents);
        let mut non_revoked_interval: Option<NonRevokedInterval> = None;
        let mut attributes: Vec<String> = Vec::new();

        for referent in referents {
            let requested = self
                .requested_attributes
                .get(referent)
                .cloned()
                .ok_or_else(|| err_msg!("Requested Attribute {} not found in request", referent))?;

            if let Some(int) = &requested.non_revoked {
                match non_revoked_interval.as_mut() {
                    Some(ni) => {
                        ni.compare_and_set(int);
                    }
                    None => non_revoked_interval = Some(int.clone()),
                }
            }
            if let Some(name) = requested.name {
                attributes.push(name);
            }
            if let Some(names) = requested.names {
                names
                    .iter()
                    .for_each(|name| attributes.push(name.to_string()))
            }
        }

        trace!(
            "get_requested_attributes <<< revealed_attrs_for_credential: {:?}",
            attributes
        );
        Ok((attributes, non_revoked_interval))
    }

    pub(crate) fn get_requested_predicates(
        &self,
        referents: &HashSet<String>,
    ) -> Result<(Vec<Predicate>, Option<NonRevokedInterval>)> {
        trace!("get_requested_predicates >>> referents: {:?}", referents);
        let mut non_revoked_interval: Option<NonRevokedInterval> = None;
        let mut predicates: Vec<Predicate> = Vec::with_capacity(self.requested_predicates.len());

        for referent in referents {
            let requested = self
                .requested_predicates
                .get(referent)
                .cloned()
                .ok_or_else(|| err_msg!("Requested Predicate {} not found in request", referent))?;

            if let Some(int) = &requested.non_revoked {
                match non_revoked_interval.as_mut() {
                    Some(ni) => {
                        ni.compare_and_set(int);
                    }
                    None => non_revoked_interval = Some(int.clone()),
                }
            }
            predicates.push(Predicate {
                attr_name: requested.name,
                p_type: requested.p_type.into(),
                value: requested.p_value,
            });
        }

        trace!(
            "get_requested_predicates <<< revealed_predicates_for_credential: {:?}",
            predicates
        );
        Ok((predicates, non_revoked_interval))
    }
}

impl RequestedProof {
    // get list of revealed attributes per credential
    pub(crate) fn get_attributes_for_credential(&self, index: u32) -> HashSet<String> {
        let mut referents = HashSet::new();
        for (referent, into) in self.revealed_attrs.iter() {
            if into.sub_proof_index == index {
                referents.insert(referent.to_string());
            }
        }
        for (referent, into) in self.revealed_attr_groups.iter() {
            if into.sub_proof_index == index {
                referents.insert(referent.to_string());
            }
        }
        referents
    }

    // get list of revealed predicates per credential
    pub(crate) fn get_predicates_for_credential(&self, index: u32) -> HashSet<String> {
        let mut referents = HashSet::new();
        for (referent, info) in self.predicates.iter() {
            if info.sub_proof_index == index {
                referents.insert(referent.to_string());
            }
        }
        referents
    }
}
