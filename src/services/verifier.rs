use super::helpers::attr_common_view;
use super::helpers::new_nonce;
use super::types::Presentation;
use super::types::PresentationRequest;
use super::types::RevocationRegistryDefinition;
use super::types::RevocationStatusList;
use crate::cl::{CredentialPublicKey, RevocationRegistry, Verifier};
use crate::data_types::cred_def::CredentialDefinition;
use crate::data_types::cred_def::CredentialDefinitionId;
use crate::data_types::issuer_id::IssuerId;
use crate::data_types::nonce::Nonce;
use crate::data_types::pres_request::PresentationRequestPayload;
use crate::data_types::pres_request::{AttributeInfo, NonRevokedInterval};
use crate::data_types::presentation::{Identifier, RequestedProof};
use crate::data_types::rev_reg_def::RevocationRegistryDefinitionId;
use crate::data_types::schema::Schema;
use crate::data_types::schema::SchemaId;
use crate::error::Result;
use crate::services::helpers::build_credential_schema;
use crate::services::helpers::build_sub_proof_request;
use crate::services::helpers::{build_non_credential_schema, get_requested_non_revoked_interval};
use crate::utils::query::Query;
use crate::utils::validation::LEGACY_DID_IDENTIFIER;

use anoncreds_clsignatures::{NonCredentialSchema, Proof, ProofVerifier, SubProof};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Filter {
    schema_id: SchemaId,
    schema_issuer_id: IssuerId,
    schema_name: String,
    schema_version: String,
    issuer_id: IssuerId,
    cred_def_id: CredentialDefinitionId,
}

static INTERNAL_TAG_MATCHER: Lazy<Regex> =
    Lazy::new(|| Regex::new("^attr::([^:]+)::(value|marker)$").unwrap());

/// Verify an incoming proof presentation
pub fn verify_presentation(
    presentation: &Presentation,
    pres_req: &PresentationRequest,
    schemas: &HashMap<SchemaId, Schema>,
    cred_defs: &HashMap<CredentialDefinitionId, CredentialDefinition>,
    rev_reg_defs: Option<&HashMap<RevocationRegistryDefinitionId, RevocationRegistryDefinition>>,
    rev_status_lists: Option<Vec<RevocationStatusList>>,
    nonrevoke_interval_override: Option<
        &HashMap<RevocationRegistryDefinitionId, HashMap<u64, u64>>,
    >,
) -> Result<bool> {
    trace!("verify >>> presentation: {:?}, pres_req: {:?}, schemas: {:?}, cred_defs: {:?}, rev_reg_defs: {:?} rev_status_lists: {:?}",
    presentation, pres_req, schemas, cred_defs, rev_reg_defs, rev_status_lists);

    // These values are from the prover and cannot be trusted
    let received_revealed_attrs: HashMap<String, Identifier> =
        received_revealed_attrs(presentation)?;
    let received_unrevealed_attrs: HashMap<String, Identifier> =
        received_unrevealed_attrs(presentation)?;
    let received_predicates: HashMap<String, Identifier> = received_predicates(presentation)?;
    let received_self_attested_attrs: HashSet<String> = received_self_attested_attrs(presentation);

    let pres_req = pres_req.value();

    // Ensures that all attributes in the request is also in the presentation
    compare_attr_from_proof_and_request(
        pres_req,
        &received_revealed_attrs,
        &received_unrevealed_attrs,
        &received_self_attested_attrs,
        &received_predicates,
    )?;

    // Ensures the encoded values are same as request
    verify_revealed_attribute_values(pres_req, presentation)?;

    // Ensures the restrictions set out in the request is met
    verify_requested_restrictions(
        pres_req,
        schemas,
        cred_defs,
        &presentation.requested_proof,
        &received_revealed_attrs,
        &received_unrevealed_attrs,
        &received_predicates,
        &received_self_attested_attrs,
    )?;

    let mut proof_verifier = CLProofVerifier::new(
        pres_req,
        schemas,
        cred_defs,
        rev_reg_defs,
        rev_status_lists.as_ref(),
    )?;

    for (sub_proof_index, identifier) in presentation.identifiers.iter().enumerate() {
        let attributes = presentation
            .requested_proof
            .get_attributes_for_credential(sub_proof_index as u32);
        let predicates = presentation
            .requested_proof
            .get_predicates_for_credential(sub_proof_index as u32);

        let (_, attrs_nonrevoked_interval) = pres_req.get_requested_attributes(&attributes)?;
        let (_, pred_nonrevoked_interval) = pres_req.get_requested_predicates(&predicates)?;

        {
            check_non_revoked_interval(
                proof_verifier.get_credential_definition(&identifier.cred_def_id)?,
                attrs_nonrevoked_interval,
                pred_nonrevoked_interval,
                pres_req,
                identifier.rev_reg_id.as_ref(),
                nonrevoke_interval_override,
                identifier.timestamp,
            )?;
        }

        proof_verifier.add_sub_proof(
            &presentation.proof.proofs[sub_proof_index],
            &identifier.schema_id,
            &identifier.cred_def_id,
            identifier.rev_reg_id.as_ref(),
            identifier.timestamp,
        )?;
    }

    let valid = proof_verifier.verify(&presentation.proof)?;

    trace!("verify <<< valid: {:?}", valid);

    Ok(valid)
}

/// Generates a cryptographically strong pseudo-random nonce with a length of 80 bits
pub fn generate_nonce() -> Result<Nonce> {
    new_nonce()
}

pub(crate) fn compare_attr_from_proof_and_request(
    pres_req: &PresentationRequestPayload,
    received_revealed_attrs: &HashMap<String, Identifier>,
    received_unrevealed_attrs: &HashMap<String, Identifier>,
    received_self_attested_attrs: &HashSet<String>,
    received_predicates: &HashMap<String, Identifier>,
) -> Result<()> {
    let requested_attrs: HashSet<String> = pres_req.requested_attributes.keys().cloned().collect();

    let received_attrs: HashSet<String> = received_revealed_attrs
        .iter()
        .chain(received_unrevealed_attrs)
        .map(|(r, _)| r.to_string())
        .collect::<HashSet<String>>()
        .union(received_self_attested_attrs)
        .cloned()
        .collect();

    if requested_attrs != received_attrs {
        return Err(err_msg!(
            "Requested attributes {:?} do not correspond to received {:?}",
            requested_attrs,
            received_attrs
        ));
    }

    let requested_predicates: HashSet<&String> = pres_req.requested_predicates.keys().collect();

    let received_predicates_: HashSet<&String> = received_predicates.keys().collect();

    if requested_predicates != received_predicates_ {
        return Err(err_msg!(
            "Requested predicates {:?} do not correspond to received {:?}",
            requested_predicates,
            received_predicates
        ));
    }

    Ok(())
}

fn received_revealed_attrs(proof: &Presentation) -> Result<HashMap<String, Identifier>> {
    let mut revealed_identifiers: HashMap<String, Identifier> = HashMap::new();
    for (referent, info) in &proof.requested_proof.revealed_attrs {
        revealed_identifiers.insert(
            referent.to_string(),
            get_proof_identifier(proof, info.sub_proof_index)?,
        );
    }
    for (referent, infos) in &proof.requested_proof.revealed_attr_groups {
        revealed_identifiers.insert(
            referent.to_string(),
            get_proof_identifier(proof, infos.sub_proof_index)?,
        );
    }
    Ok(revealed_identifiers)
}

fn received_unrevealed_attrs(proof: &Presentation) -> Result<HashMap<String, Identifier>> {
    let mut unrevealed_identifiers: HashMap<String, Identifier> = HashMap::new();
    for (referent, info) in &proof.requested_proof.unrevealed_attrs {
        unrevealed_identifiers.insert(
            referent.to_string(),
            get_proof_identifier(proof, info.sub_proof_index)?,
        );
    }
    Ok(unrevealed_identifiers)
}

fn received_predicates(proof: &Presentation) -> Result<HashMap<String, Identifier>> {
    let mut predicate_identifiers: HashMap<String, Identifier> = HashMap::new();
    for (referent, info) in &proof.requested_proof.predicates {
        predicate_identifiers.insert(
            referent.to_string(),
            get_proof_identifier(proof, info.sub_proof_index)?,
        );
    }
    Ok(predicate_identifiers)
}

fn received_self_attested_attrs(proof: &Presentation) -> HashSet<String> {
    proof
        .requested_proof
        .self_attested_attrs
        .keys()
        .cloned()
        .collect()
}

fn get_proof_identifier(proof: &Presentation, index: u32) -> Result<Identifier> {
    proof
        .identifiers
        .get(index as usize)
        .cloned()
        .ok_or_else(|| err_msg!("Identifier not found for index: {}", index))
}

fn verify_revealed_attribute_values(
    pres_req: &PresentationRequestPayload,
    proof: &Presentation,
) -> Result<()> {
    for (attr_referent, attr_info) in &proof.requested_proof.revealed_attrs {
        let attr_name = pres_req
            .requested_attributes
            .get(attr_referent)
            .as_ref()
            .ok_or_else(|| {
                err_msg!(
                    ProofRejected,
                    "Attribute with referent \"{}\" not found in ProofRequests",
                    attr_referent
                )
            })?
            .name
            .as_ref()
            .ok_or_else(|| {
                err_msg!(
                    ProofRejected,
                    "Attribute with referent \"{}\" not found in ProofRequests",
                    attr_referent,
                )
            })?;
        let sub_proof = proof
            .proof
            .proofs
            .get(attr_info.sub_proof_index as usize)
            .ok_or_else(|| {
                err_msg!(
                    ProofRejected,
                    "CryptoProof not found by index \"{}\"",
                    attr_info.sub_proof_index,
                )
            })?;
        verify_revealed_attribute_value(attr_name.as_str(), sub_proof, &attr_info.encoded)?;
    }

    for (attr_referent, attr_infos) in &proof.requested_proof.revealed_attr_groups {
        let sub_proof = proof
            .proof
            .proofs
            .get(attr_infos.sub_proof_index as usize)
            .ok_or_else(|| {
                err_msg!(
                    ProofRejected,
                    "CryptoProof not found by index \"{}\"",
                    attr_infos.sub_proof_index,
                )
            })?;
        let attr_names = pres_req
            .requested_attributes
            .get(attr_referent)
            .as_ref()
            .ok_or_else(|| {
                err_msg!(
                    ProofRejected,
                    "Attribute with referent \"{}\" not found in ProofRequests",
                    attr_referent,
                )
            })?
            .names
            .as_ref()
            .ok_or_else(|| {
                err_msg!(
                    ProofRejected,
                    "Attribute with referent \"{}\" not found in ProofRequests",
                    attr_referent,
                )
            })?;
        if attr_infos.values.len() != attr_names.len() {
            error!("Proof Revealed Attr Group does not match Proof Request Attribute Group, proof request attrs: {:?}, referent: {:?}, attr_infos: {:?}", pres_req.requested_attributes, attr_referent, attr_infos);
            return Err(err_msg!(
                "Proof Revealed Attr Group does not match Proof Request Attribute Group",
            ));
        }
        for attr_name in attr_names {
            let attr_info = &attr_infos.values.get(attr_name).ok_or_else(|| {
                err_msg!("Proof Revealed Attr Group does not match Proof Request Attribute Group",)
            })?;
            verify_revealed_attribute_value(attr_name, sub_proof, &attr_info.encoded)?;
        }
    }
    Ok(())
}

fn normalize_encoded_attr(attr: &str) -> String {
    attr.parse::<i32>()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| attr.to_owned())
}

pub(crate) fn verify_revealed_attribute_value(
    attr_name: &str,
    sub_proof: &SubProof,
    encoded: &str,
) -> Result<()> {
    let reveal_attr_encoded = normalize_encoded_attr(encoded);

    let crypto_proof_encoded = sub_proof
        .revealed_attrs()?
        .iter()
        .find(|(key, _)| attr_common_view(attr_name) == attr_common_view(key))
        .map(|(_, val)| val.to_string())
        .ok_or_else(|| {
            err_msg!(
                ProofRejected,
                "Attribute with name \"{}\" not found in CryptoProof",
                attr_name,
            )
        })?;

    if reveal_attr_encoded != crypto_proof_encoded {
        return Err(err_msg!(ProofRejected,
                "Encoded Values for \"{}\" are different in RequestedProof \"{}\" and CryptoProof \"{}\"", attr_name, reveal_attr_encoded, crypto_proof_encoded));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_requested_restrictions(
    pres_req: &PresentationRequestPayload,
    schemas: &HashMap<SchemaId, Schema>,
    cred_defs: &HashMap<CredentialDefinitionId, CredentialDefinition>,
    requested_proof: &RequestedProof,
    received_revealed_attrs: &HashMap<String, Identifier>,
    received_unrevealed_attrs: &HashMap<String, Identifier>,
    received_predicates: &HashMap<String, Identifier>,
    self_attested_attrs: &HashSet<String>,
) -> Result<()> {
    let proof_attr_identifiers: HashMap<String, Identifier> = received_revealed_attrs
        .iter()
        .chain(received_unrevealed_attrs)
        .map(|(r, id)| (r.to_string(), id.clone()))
        .collect();

    let requested_attrs: HashMap<String, AttributeInfo> = pres_req
        .requested_attributes
        .iter()
        .filter(|&(referent, info)| !is_self_attested(referent, info, self_attested_attrs))
        .map(|(referent, info)| (referent.to_string(), info.clone()))
        .collect();

    let requested_attributes_queries = pres_req
        .requested_attributes
        .iter()
        .filter_map(|(_, info)| info.restrictions.clone());

    let requested_predicates_queries = pres_req
        .requested_predicates
        .iter()
        .filter_map(|(_, info)| info.restrictions.clone());

    let filter_tags: Vec<String> = requested_attributes_queries
        .chain(requested_predicates_queries)
        .flat_map(|r| {
            r.get_name()
                .iter()
                .map(|n| n.to_owned().clone())
                .collect::<Vec<String>>()
        })
        .collect();

    // We check whether both the `issuer_id` and `issuer_did` are included. Since `issuer_did` will
    // only be used for legacy support and `issuer_id` will be the new restriction tag, we do not
    // allow mixing them.
    if filter_tags.contains(&"issuer_id".to_owned())
        && filter_tags.contains(&"issuer_did".to_owned())
    {
        return Err(err_msg!("Presentation request contains restriction for `issuer_id` (new) and `issuer_did` (legacy)"));
    }

    // We check whether both the `schema_issuer_id` and `schema_issuer_did` are included. Since
    // `schema_issuer_did` will only be used for legacy support and `schema_issuer_id` will be the
    // new restriction tag, we do not allow mixing them.
    if filter_tags.contains(&"schema_issuer_id".to_owned())
        && filter_tags.contains(&"schema_issuer_did".to_owned())
    {
        return Err(err_msg!("Presentation request contains both restrictions for `schema_issuer_id` (new) and `schema_issuer_did` (legacy)"));
    }

    for (referent, info) in &requested_attrs {
        if let Some(ref query) = info.restrictions {
            let identifier = proof_attr_identifiers.get(referent).ok_or_else(|| {
                err_msg!(
                    InvalidState,
                    "Identifier not found for referent: {}",
                    referent
                )
            })?;
            let filter = gather_filter_info(identifier, schemas, cred_defs)?;

            let attr_value_map: HashMap<String, Option<String>> = if let Some(name) =
                info.name.as_ref()
            {
                let mut map = HashMap::new();
                map.insert(
                    name.clone(),
                    requested_proof
                        .revealed_attrs
                        .get(referent)
                        .map(|attr| attr.raw.to_string()),
                );
                map
            } else if let Some(names) = info.names.as_ref() {
                let mut map: HashMap<String, Option<String>> = HashMap::new();
                let attrs = requested_proof
                    .revealed_attr_groups
                    .get(referent)
                    .ok_or_else(|| err_msg!("Proof does not have referent from proof request"))?;
                for name in names {
                    let val = attrs.values.get(name).map(|attr| attr.raw.clone());
                    map.insert(name.clone(), val);
                }
                map
            } else {
                error!(
                    r#"Proof Request attribute restriction should contain "name" or "names" param. Current proof request: {:?}"#,
                    pres_req
                );
                return Err(err_msg!(
                    r#"Proof Request attribute restriction should contain "name" or "names" param"#,
                ));
            };

            process_operator(&attr_value_map, query, &filter).map_err(err_map!(
                "Requested restriction validation failed for \"{:?}\" attributes",
                &attr_value_map
            ))?;
        }
    }

    for (referent, info) in &pres_req.requested_predicates {
        if let Some(ref query) = info.restrictions {
            let identifier = received_predicates.get(referent).ok_or_else(|| {
                err_msg!(
                    InvalidState,
                    "Identifier not found for referent: {}",
                    referent
                )
            })?;
            let filter = gather_filter_info(identifier, schemas, cred_defs)?;

            // start with the predicate requested attribute, which is un-revealed
            let mut attr_value_map: HashMap<String, Option<String>> = HashMap::new();
            attr_value_map.insert(info.name.to_string(), None);

            // include any revealed attributes for the same credential (based on sub_proof_index)
            let pred_sub_proof_index = requested_proof
                .predicates
                .get(referent)
                .unwrap()
                .sub_proof_index;
            for attr_referent in requested_proof.revealed_attrs.keys() {
                let attr_info = requested_proof.revealed_attrs.get(attr_referent).unwrap();
                let attr_sub_proof_index = attr_info.sub_proof_index;
                if pred_sub_proof_index == attr_sub_proof_index {
                    let attr_name = requested_attrs.get(attr_referent).unwrap().name.clone();
                    if let Some(name) = attr_name {
                        attr_value_map.insert(name, Some(attr_info.raw.clone()));
                    }
                }
            }
            for attr_referent in requested_proof.revealed_attr_groups.keys() {
                let attr_info = requested_proof
                    .revealed_attr_groups
                    .get(attr_referent)
                    .unwrap();
                let attr_sub_proof_index = attr_info.sub_proof_index;
                if pred_sub_proof_index == attr_sub_proof_index {
                    for name in attr_info.values.keys() {
                        let raw_val = attr_info.values.get(name).unwrap().raw.clone();
                        attr_value_map.insert(name.to_string(), Some(raw_val));
                    }
                }
            }

            process_operator(&attr_value_map, query, &filter).map_err(err_map!(
                "Requested restriction validation failed for \"{}\" predicate",
                &info.name
            ))?;
        }
    }

    Ok(())
}

fn is_self_attested(
    referent: &str,
    info: &AttributeInfo,
    self_attested_attrs: &HashSet<String>,
) -> bool {
    match info.restrictions.as_ref() {
        Some(&Query::And(ref array) | &Query::Or(ref array)) if array.is_empty() => {
            self_attested_attrs.contains(referent)
        }
        None => self_attested_attrs.contains(referent),
        Some(_) => false,
    }
}

pub(crate) fn gather_filter_info(
    identifier: &Identifier,
    schemas: &HashMap<SchemaId, Schema>,
    cred_defs: &HashMap<CredentialDefinitionId, CredentialDefinition>,
) -> Result<Filter> {
    let schema_id = &identifier.schema_id;
    let cred_def_id = &identifier.cred_def_id;

    let schema = schemas
        .get(schema_id)
        .ok_or_else(|| err_msg!("schema_id {schema_id} could not be found in the schemas"))?;

    let cred_def = cred_defs
        .get(cred_def_id)
        .ok_or_else(|| err_msg!("cred_def_id {cred_def_id} could not be found in the cred_defs"))?;

    Ok(Filter {
        schema_id: schema_id.clone(),
        schema_name: schema.name.clone(),
        schema_version: schema.version.clone(),
        schema_issuer_id: schema.issuer_id.clone(),
        issuer_id: cred_def.issuer_id.clone(),
        cred_def_id: cred_def_id.clone(),
    })
}

pub(crate) fn process_operator(
    attr_value_map: &HashMap<String, Option<String>>,
    restriction_op: &Query,
    filter: &Filter,
) -> Result<()> {
    match restriction_op {
        Query::Eq(ref tag_name, ref tag_value) => {
            process_filter(attr_value_map, tag_name, tag_value, filter).map_err(err_map!(
                "$eq operator validation failed for tag: \"{}\", value: \"{}\"",
                tag_name,
                tag_value
            ))
        }
        Query::Neq(ref tag_name, ref tag_value) => {
            if process_filter(attr_value_map, tag_name, tag_value, filter).is_err() {
                Ok(())
            } else {
                Err(err_msg!(ProofRejected,
                        "$neq operator validation failed for tag: \"{}\", value: \"{}\". Condition was passed.", tag_name, tag_value))
            }
        }
        Query::In(ref tag_name, ref tag_values) => {
            let res = tag_values
                .iter()
                .any(|val| process_filter(attr_value_map, tag_name, val, filter).is_ok());
            if res {
                Ok(())
            } else {
                Err(err_msg!(
                    ProofRejected,
                    "$in operator validation failed for tag: \"{}\", values \"{:?}\".",
                    tag_name,
                    tag_values,
                ))
            }
        }
        Query::And(ref operators) => operators
            .iter()
            .map(|op| process_operator(attr_value_map, op, filter))
            .collect::<Result<Vec<()>>>()
            .map(|_| ())
            .map_err(err_map!("$and operator validation failed.")),
        Query::Or(ref operators) => {
            let res = operators
                .iter()
                .any(|op| process_operator(attr_value_map, op, filter).is_ok());
            if res {
                Ok(())
            } else {
                Err(err_msg!(
                    ProofRejected,
                    "$or operator validation failed. All conditions were failed.",
                ))
            }
        }
        Query::Not(ref operator) => {
            if process_operator(attr_value_map, operator, filter).is_err() {
                Ok(())
            } else {
                Err(err_msg!(
                    ProofRejected,
                    "$not operator validation failed. All conditions were passed.",
                ))
            }
        }
        _ => Err(err_msg!(ProofRejected, "unsupported operator",)),
    }
}

fn process_filter(
    attr_value_map: &HashMap<String, Option<String>>,
    tag: &str,
    tag_value: &str,
    filter: &Filter,
) -> Result<()> {
    trace!(
        "_process_filter: attr_value_map: {:?}, tag: {}, tag_value: {}, filter: {:?}",
        attr_value_map,
        tag,
        tag_value,
        filter
    );
    match tag {
        tag_ @ "schema_id" => precess_filed(tag_, filter.schema_id.to_string(), tag_value),
        tag_ @ ("schema_issuer_did" | "schema_issuer_id") => {
            precess_filed(tag_, filter.schema_issuer_id.clone(), tag_value)
        }
        tag_ @ "schema_name" => precess_filed(tag_, &filter.schema_name, tag_value),
        tag_ @ "schema_version" => precess_filed(tag_, &filter.schema_version, tag_value),
        tag_ @ "cred_def_id" => precess_filed(tag_, filter.cred_def_id.to_string(), tag_value),
        tag_ @ ("issuer_did" | "issuer_id") => {
            precess_filed(tag_, filter.issuer_id.clone(), tag_value)
        }
        key if is_attr_internal_tag(key, attr_value_map) => {
            check_internal_tag_revealed_value(key, tag_value, attr_value_map)
        }
        key if is_attr_operator(key) => Ok(()),
        _ => Err(err_msg!("Unknown Filter Type")),
    }
}

fn precess_filed(filed: &str, filter_value: impl Into<String>, tag_value: &str) -> Result<()> {
    let filter_value = filter_value.into();
    // We explicitly check here with it is one of the two legacy identifier restrictions. This
    // means that we only allow legacy identifiers which can be detected with a simple regex. If
    // they are not in the legacy format, we do not support this.
    if (filed == "schema_issuer_did" || filed == "issuer_did")
        && (LEGACY_DID_IDENTIFIER.captures(&filter_value).is_none())
    {
        return Err(err_msg!(
            ProofRejected,
            "\"{}\" value is a legacy identifier tag and therefore only legacy identifiers can be used",
            filed,
        ));
    }
    if filter_value == tag_value {
        Ok(())
    } else {
        Err(err_msg!(
            ProofRejected,
            "\"{}\" values are different: expected: \"{}\", actual: \"{}\"",
            filed,
            tag_value,
            filter_value,
        ))
    }
}

fn is_attr_internal_tag(key: &str, attr_value_map: &HashMap<String, Option<String>>) -> bool {
    INTERNAL_TAG_MATCHER.captures(key).map_or(false, |caps| {
        caps.get(1).map_or(false, |s| {
            attr_value_map.contains_key(&s.as_str().to_string())
        })
    })
}

fn check_internal_tag_revealed_value(
    key: &str,
    tag_value: &str,
    attr_value_map: &HashMap<String, Option<String>>,
) -> Result<()> {
    let attr_name = INTERNAL_TAG_MATCHER
        .captures(key)
        .ok_or_else(|| err_msg!(InvalidState, "Attribute name became unparseable",))?
        .get(1)
        .ok_or_else(|| err_msg!(InvalidState, "No name has been parsed",))?
        .as_str();
    if let Some(Some(revealed_value)) = attr_value_map.get(attr_name) {
        if *revealed_value != tag_value {
            return Err(err_msg!(
                ProofRejected,
                "\"{}\" values are different: expected: \"{}\", actual: \"{}\"",
                key,
                tag_value,
                revealed_value
            ));
        }
    }
    Ok(())
}

fn is_attr_operator(key: &str) -> bool {
    key.starts_with("attr::") && key.ends_with("::marker")
}

fn build_revocation_registry_map(
    rev_status_lists: Option<&Vec<RevocationStatusList>>,
) -> Result<Option<HashMap<RevocationRegistryDefinitionId, HashMap<u64, RevocationRegistry>>>> {
    let rev_reg_map = if let Some(lists) = rev_status_lists {
        let mut map: HashMap<RevocationRegistryDefinitionId, HashMap<u64, RevocationRegistry>> =
            HashMap::new();

        for list in lists {
            let id = list
                .id()
                .ok_or_else(|| err_msg!(Unexpected, "RevStatusList missing Id"))?;

            let timestamp = list
                .timestamp()
                .ok_or_else(|| err_msg!(Unexpected, "RevStatusList missing timestamp"))?;

            let rev_reg: Option<RevocationRegistry> = (list).into();
            let rev_reg = rev_reg.ok_or_else(|| {
                err_msg!(Unexpected, "Revocation status list missing accumulator")
            })?;

            map.entry(id)
                .or_insert_with(HashMap::new)
                .insert(timestamp, rev_reg);
        }
        Some(map)
    } else {
        None
    };
    Ok(rev_reg_map)
}

fn check_non_revoked_interval(
    cred_def: &CredentialDefinition,
    attrs_nonrevoked_interval: Option<NonRevokedInterval>,
    pred_nonrevoked_interval: Option<NonRevokedInterval>,
    pres_req: &PresentationRequestPayload,
    rev_reg_id: Option<&RevocationRegistryDefinitionId>,
    nonrevoke_interval_override: Option<
        &HashMap<RevocationRegistryDefinitionId, HashMap<u64, u64>>,
    >,
    timestamp: Option<u64>,
) -> Result<()> {
    if cred_def.value.revocation.is_some() {
        // Collapse to the most stringent local interval for the attributes / predicates,
        // we can do this because there is only 1 revocation status list for this credential
        // if it satisfies the most stringent interval, it will satisfy all intervals
        let interval = match (attrs_nonrevoked_interval, pred_nonrevoked_interval) {
            (Some(attr), None) => Some(attr),
            (None, Some(pred)) => Some(pred),
            (Some(mut attr), Some(pred)) => {
                attr.compare_and_set(&pred);
                Some(attr)
            }
            _ => None,
        };

        let cred_nonrevoked_interval = get_requested_non_revoked_interval(
            rev_reg_id,
            interval.as_ref(),
            pres_req.non_revoked.as_ref(),
            nonrevoke_interval_override,
        );

        if let (Some(_), Some(cred_nonrevoked_interval)) = (
            cred_def.value.revocation.as_ref(),
            cred_nonrevoked_interval.as_ref(),
        ) {
            let timestamp = timestamp
                .ok_or_else(|| err_msg!("Identifier timestamp not found for revocation check"))?;

            cred_nonrevoked_interval.is_valid(timestamp)?;
        }
    }

    Ok(())
}

pub(crate) struct CLProofVerifier<'a> {
    proof_verifier: ProofVerifier,
    presentation_request: &'a PresentationRequestPayload,
    non_credential_schema: NonCredentialSchema,
    schemas: &'a HashMap<SchemaId, Schema>,
    cred_defs: &'a HashMap<CredentialDefinitionId, CredentialDefinition>,
    rev_reg_defs: Option<&'a HashMap<RevocationRegistryDefinitionId, RevocationRegistryDefinition>>,
    revocation_map:
        Option<HashMap<RevocationRegistryDefinitionId, HashMap<u64, RevocationRegistry>>>,
}

impl<'a> CLProofVerifier<'a> {
    pub(crate) fn new(
        presentation_request: &'a PresentationRequestPayload,
        schemas: &'a HashMap<SchemaId, Schema>,
        cred_defs: &'a HashMap<CredentialDefinitionId, CredentialDefinition>,
        rev_reg_defs: Option<
            &'a HashMap<RevocationRegistryDefinitionId, RevocationRegistryDefinition>,
        >,
        rev_status_lists: Option<&'a Vec<RevocationStatusList>>,
    ) -> Result<CLProofVerifier<'a>> {
        let proof_verifier = Verifier::new_proof_verifier()?;
        let non_credential_schema = build_non_credential_schema()?;
        let revocation_map = build_revocation_registry_map(rev_status_lists)?;
        Ok(CLProofVerifier {
            proof_verifier,
            presentation_request,
            non_credential_schema,
            schemas,
            cred_defs,
            rev_reg_defs,
            revocation_map,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_sub_proof(
        &mut self,
        sub_proof: &SubProof,
        schema_id: &SchemaId,
        cred_def_id: &CredentialDefinitionId,
        rev_reg_def_id: Option<&RevocationRegistryDefinitionId>,
        timestamp: Option<u64>,
    ) -> Result<()> {
        let schema = self.get_schema(schema_id)?;
        let cred_def = self.get_credential_definition(cred_def_id)?;
        let (rev_reg_def, rev_reg) = self.get_revocation_registry(rev_reg_def_id, timestamp)?;

        let credential_schema = build_credential_schema(schema)?;
        let credential_pub_key = CredentialPublicKey::build_from_parts(
            &cred_def.value.primary,
            cred_def.value.revocation.as_ref(),
        )?;

        let attributes: Vec<String> = sub_proof.revealed_attrs()?.keys().cloned().collect();
        let predicates = sub_proof.predicates();

        let sub_pres_request = build_sub_proof_request(&attributes, &predicates)?;
        let rev_key_pub = rev_reg_def.map(|d| &d.value.public_keys.accum_key);
        self.proof_verifier.add_sub_proof_request(
            &sub_pres_request,
            &credential_schema,
            &self.non_credential_schema,
            &credential_pub_key,
            rev_key_pub.cloned().as_ref(),
            rev_reg.cloned().as_ref(),
        )?;

        Ok(())
    }

    pub(crate) fn verify(&mut self, proof: &Proof) -> Result<bool> {
        let valid = self
            .proof_verifier
            .verify(proof, self.presentation_request.nonce.as_native())?;
        Ok(valid)
    }

    pub(crate) fn get_schema(&self, schema_id: &SchemaId) -> Result<&'a Schema> {
        self.schemas
            .get(schema_id)
            .ok_or_else(|| err_msg!("Schema not provided for ID: {:?}", schema_id))
    }

    pub(crate) fn get_credential_definition(
        &self,
        cred_def_id: &CredentialDefinitionId,
    ) -> Result<&'a CredentialDefinition> {
        self.cred_defs.get(cred_def_id).ok_or_else(|| {
            err_msg!(
                "Credential Definition not provided for ID: {:?}",
                cred_def_id
            )
        })
    }

    pub(crate) fn get_revocation_registry(
        &'a self,
        rev_reg_id: Option<&RevocationRegistryDefinitionId>,
        timestamp: Option<u64>,
    ) -> Result<(
        Option<&'a RevocationRegistryDefinition>,
        Option<&'a RevocationRegistry>,
    )> {
        let (rev_reg_def, rev_reg) =
            if let (Some(rev_reg_id), Some(timestamp)) = (rev_reg_id, timestamp) {
                let rev_reg_defs = self.rev_reg_defs.ok_or_else(|| {
                    err_msg!("Could not load the Revocation Registry Definitions mapping")
                })?;

                let rev_reg_map = self
                    .revocation_map
                    .as_ref()
                    .ok_or_else(|| err_msg!("Could not load the Revocation Registry mapping"))?;

                let rev_reg_def = Some(rev_reg_defs.get(rev_reg_id).ok_or_else(|| {
                    err_msg!(
                        "Revocation Registry Definition not provided for ID: {:?}",
                        rev_reg_id
                    )
                })?);

                let rev_reg = Some(
                    rev_reg_map
                        .get(rev_reg_id)
                        .and_then(|regs| regs.get(&timestamp))
                        .ok_or_else(|| {
                            err_msg!(
                                "Revocation Registry not provided for ID and timestamp: {:?}, {:?}",
                                rev_reg_id,
                                timestamp
                            )
                        })?,
                );

                (rev_reg_def, rev_reg)
            } else {
                (None, None)
            };

        Ok((rev_reg_def, rev_reg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const SCHEMA_ID: &str = "123";
    pub const SCHEMA_NAME: &str = "Schema Name";
    pub const SCHEMA_ISSUER_ID: &str = "1111111111111111111111";
    pub const SCHEMA_VERSION: &str = "1.2.3";
    pub const CRED_DEF_ID: &str = "345";
    pub const ISSUER_ID: &str = "1111111111111111111111";

    fn schema_id_tag() -> String {
        "schema_id".to_string()
    }

    fn schema_name_tag() -> String {
        "schema_name".to_string()
    }

    fn schema_issuer_did_tag() -> String {
        "schema_issuer_did".to_string()
    }

    fn schema_version_tag() -> String {
        "schema_version".to_string()
    }

    fn cred_def_id_tag() -> String {
        "cred_def_id".to_string()
    }

    fn issuer_did_tag() -> String {
        "issuer_did".to_string()
    }

    fn attr_tag() -> String {
        "attr::zip::marker".to_string()
    }

    fn attr_tag_value() -> String {
        "attr::zip::value".to_string()
    }

    fn bad_attr_tag() -> String {
        "bad::zip::marker".to_string()
    }

    fn filter() -> Filter {
        Filter {
            schema_id: SchemaId::new_unchecked(SCHEMA_ID),
            schema_name: SCHEMA_NAME.to_string(),
            schema_issuer_id: IssuerId::new_unchecked(SCHEMA_ISSUER_ID),
            schema_version: SCHEMA_VERSION.to_string(),
            cred_def_id: CredentialDefinitionId::new_unchecked(CRED_DEF_ID),
            issuer_id: IssuerId::new_unchecked(ISSUER_ID),
        }
    }

    fn _process_operator(
        attr: &str,
        restriction_op: &Query,
        filter: &Filter,
        revealed_value: Option<&str>,
    ) -> Result<()> {
        let mut attr_value_map = HashMap::new();
        attr_value_map.insert(attr.to_string(), revealed_value.map(String::from));
        process_operator(&attr_value_map, restriction_op, filter)
    }

    #[test]
    fn test_process_op_eq() {
        let filter = filter();

        let mut op = Query::Eq(schema_id_tag(), SCHEMA_ID.to_string());
        _process_operator("zip", &op, &filter, None).unwrap();

        op = Query::And(vec![
            Query::Eq(attr_tag(), "1".to_string()),
            Query::Eq(schema_id_tag(), SCHEMA_ID.to_string()),
        ]);
        _process_operator("zip", &op, &filter, None).unwrap();

        op = Query::And(vec![
            Query::Eq(bad_attr_tag(), "1".to_string()),
            Query::Eq(schema_id_tag(), SCHEMA_ID.to_string()),
        ]);
        assert!(_process_operator("zip", &op, &filter, None).is_err());

        op = Query::Eq(schema_id_tag(), "NOT HERE".to_string());
        assert!(_process_operator("zip", &op, &filter, None).is_err());
    }

    #[test]
    fn test_process_op_ne() {
        let filter = filter();
        let mut op = Query::Neq(schema_id_tag(), SCHEMA_ID.to_string());
        assert!(_process_operator("zip", &op, &filter, None).is_err());

        op = Query::Neq(schema_id_tag(), "NOT HERE".to_string());
        _process_operator("zip", &op, &filter, None).unwrap()
    }

    #[test]
    fn test_process_op_in() {
        let filter = filter();
        let mut cred_def_ids = vec!["Not Here".to_string()];

        let mut op = Query::In(cred_def_id_tag(), cred_def_ids.clone());
        assert!(_process_operator("zip", &op, &filter, None).is_err());

        cred_def_ids.push(CRED_DEF_ID.to_string());
        op = Query::In(cred_def_id_tag(), cred_def_ids.clone());
        _process_operator("zip", &op, &filter, None).unwrap()
    }

    #[test]
    fn test_process_op_or() {
        let filter = filter();
        let mut op = Query::Or(vec![
            Query::Eq(schema_id_tag(), "Not Here".to_string()),
            Query::Eq(cred_def_id_tag(), "Not Here".to_string()),
        ]);
        assert!(_process_operator("zip", &op, &filter, None).is_err());

        op = Query::Or(vec![
            Query::Eq(schema_id_tag(), SCHEMA_ID.to_string()),
            Query::Eq(cred_def_id_tag(), "Not Here".to_string()),
        ]);
        _process_operator("zip", &op, &filter, None).unwrap()
    }

    #[test]
    fn test_process_op_and() {
        let filter = filter();
        let mut op = Query::And(vec![
            Query::Eq(schema_id_tag(), "Not Here".to_string()),
            Query::Eq(cred_def_id_tag(), "Not Here".to_string()),
        ]);
        assert!(_process_operator("zip", &op, &filter, None).is_err());

        op = Query::And(vec![
            Query::Eq(schema_id_tag(), SCHEMA_ID.to_string()),
            Query::Eq(cred_def_id_tag(), "Not Here".to_string()),
        ]);
        assert!(_process_operator("zip", &op, &filter, None).is_err());

        op = Query::And(vec![
            Query::Eq(schema_id_tag(), SCHEMA_ID.to_string()),
            Query::Eq(cred_def_id_tag(), CRED_DEF_ID.to_string()),
        ]);
        _process_operator("zip", &op, &filter, None).unwrap()
    }

    #[test]
    fn test_process_op_not() {
        let filter = filter();
        let mut op = Query::Not(Box::new(Query::And(vec![
            Query::Eq(schema_id_tag(), SCHEMA_ID.to_string()),
            Query::Eq(cred_def_id_tag(), CRED_DEF_ID.to_string()),
        ])));
        assert!(_process_operator("zip", &op, &filter, None).is_err());

        op = Query::Not(Box::new(Query::And(vec![
            Query::Eq(schema_id_tag(), "Not Here".to_string()),
            Query::Eq(cred_def_id_tag(), "Not Here".to_string()),
        ])));
        _process_operator("zip", &op, &filter, None).unwrap()
    }

    #[test]
    fn test_proccess_op_or_with_nested_and() {
        let filter = filter();
        let mut op = Query::Or(vec![
            Query::And(vec![
                Query::Eq(schema_id_tag(), "Not Here".to_string()),
                Query::Eq(cred_def_id_tag(), "Not Here".to_string()),
            ]),
            Query::And(vec![
                Query::Eq(schema_issuer_did_tag(), "Not Here".to_string()),
                Query::Eq(schema_name_tag(), "Not Here".to_string()),
            ]),
            Query::And(vec![
                Query::Eq(schema_name_tag(), "Not Here".to_string()),
                Query::Eq(issuer_did_tag(), "Not Here".to_string()),
            ]),
        ]);
        assert!(_process_operator("zip", &op, &filter, None).is_err());

        op = Query::Or(vec![
            Query::And(vec![
                Query::Eq(schema_id_tag(), SCHEMA_ID.to_string()),
                Query::Eq(cred_def_id_tag(), "Not Here".to_string()),
            ]),
            Query::And(vec![
                Query::Eq(schema_issuer_did_tag(), "Not Here".to_string()),
                Query::Eq(schema_name_tag(), "Not Here".to_string()),
            ]),
            Query::And(vec![
                Query::Eq(schema_name_tag(), "Not Here".to_string()),
                Query::Eq(issuer_did_tag(), "Not Here".to_string()),
            ]),
        ]);
        assert!(_process_operator("zip", &op, &filter, None).is_err());

        op = Query::Or(vec![
            Query::And(vec![
                Query::Eq(schema_id_tag(), SCHEMA_ID.to_string()),
                Query::Eq(cred_def_id_tag(), CRED_DEF_ID.to_string()),
            ]),
            Query::And(vec![
                Query::Eq(schema_issuer_did_tag(), "Not Here".to_string()),
                Query::Eq(schema_name_tag(), "Not Here".to_string()),
            ]),
            Query::And(vec![
                Query::Eq(schema_name_tag(), "Not Here".to_string()),
                Query::Eq(issuer_did_tag(), "Not Here".to_string()),
            ]),
        ]);
        _process_operator("zip", &op, &filter, None).unwrap()
    }

    #[test]
    fn test_verify_op_complex_nested() {
        let filter = filter();
        let mut op = Query::And(vec![
            Query::And(vec![
                Query::Or(vec![
                    Query::Eq(schema_name_tag(), "Not Here".to_string()),
                    Query::Eq(issuer_did_tag(), "Not Here".to_string()),
                ]),
                Query::Eq(schema_id_tag(), SCHEMA_ID.to_string()),
                Query::Eq(cred_def_id_tag(), CRED_DEF_ID.to_string()),
            ]),
            Query::And(vec![
                Query::Eq(schema_issuer_did_tag(), SCHEMA_ISSUER_ID.to_string()),
                Query::Eq(schema_name_tag(), SCHEMA_NAME.to_string()),
            ]),
            Query::And(vec![
                Query::Eq(schema_version_tag(), SCHEMA_VERSION.to_string()),
                Query::Eq(issuer_did_tag(), ISSUER_ID.to_string()),
            ]),
        ]);
        assert!(_process_operator("zip", &op, &filter, None).is_err());

        op = Query::And(vec![
            Query::And(vec![
                Query::Or(vec![
                    Query::Eq(schema_name_tag(), SCHEMA_NAME.to_string()),
                    Query::Eq(issuer_did_tag(), "Not Here".to_string()),
                ]),
                Query::Eq(schema_id_tag(), SCHEMA_ID.to_string()),
                Query::Eq(cred_def_id_tag(), CRED_DEF_ID.to_string()),
            ]),
            Query::And(vec![
                Query::Eq(schema_issuer_did_tag(), SCHEMA_ISSUER_ID.to_string()),
                Query::Eq(schema_name_tag(), SCHEMA_NAME.to_string()),
            ]),
            Query::And(vec![
                Query::Eq(schema_version_tag(), SCHEMA_VERSION.to_string()),
                Query::Eq(issuer_did_tag(), ISSUER_ID.to_string()),
            ]),
            Query::Not(Box::new(Query::Eq(
                schema_version_tag(),
                "NOT HERE".to_string(),
            ))),
        ]);
        _process_operator("zip", &op, &filter, None).unwrap();

        op = Query::And(vec![
            Query::And(vec![
                Query::Or(vec![
                    Query::Eq(schema_name_tag(), SCHEMA_NAME.to_string()),
                    Query::Eq(issuer_did_tag(), "Not Here".to_string()),
                ]),
                Query::Eq(schema_id_tag(), SCHEMA_ID.to_string()),
                Query::Eq(cred_def_id_tag(), CRED_DEF_ID.to_string()),
            ]),
            Query::And(vec![
                Query::Eq(schema_issuer_did_tag(), SCHEMA_ISSUER_ID.to_string()),
                Query::Eq(schema_name_tag(), SCHEMA_NAME.to_string()),
            ]),
            Query::And(vec![
                Query::Eq(schema_version_tag(), SCHEMA_VERSION.to_string()),
                Query::Eq(issuer_did_tag(), ISSUER_ID.to_string()),
            ]),
            Query::Not(Box::new(Query::Eq(
                schema_version_tag(),
                SCHEMA_VERSION.to_string(),
            ))),
        ]);
        assert!(_process_operator("zip", &op, &filter, None).is_err());
    }

    #[test]
    fn test_process_op_eq_revealed_value() {
        let filter = filter();
        let value = "value";

        let mut op = Query::Eq(attr_tag_value(), value.to_string());
        _process_operator("zip", &op, &filter, Some(value)).unwrap();

        op = Query::And(vec![
            Query::Eq(attr_tag_value(), value.to_string()),
            Query::Eq(schema_issuer_did_tag(), SCHEMA_ISSUER_ID.to_string()),
        ]);
        _process_operator("zip", &op, &filter, Some(value)).unwrap();

        op = Query::Eq(attr_tag_value(), value.to_string());
        assert!(_process_operator("zip", &op, &filter, Some("NOT HERE")).is_err());
    }

    fn _received() -> HashMap<String, Identifier> {
        let mut res: HashMap<String, Identifier> = HashMap::new();
        res.insert(
            "referent_1".to_string(),
            Identifier {
                timestamp: Some(1234),
                schema_id: SchemaId::default(),
                cred_def_id: CredentialDefinitionId::default(),
                rev_reg_id: Some(RevocationRegistryDefinitionId::default()),
            },
        );
        res.insert(
            "referent_2".to_string(),
            Identifier {
                timestamp: None,
                schema_id: SchemaId::default(),
                cred_def_id: CredentialDefinitionId::default(),
                rev_reg_id: Some(RevocationRegistryDefinitionId::default()),
            },
        );
        res
    }

    #[test]
    fn format_attribute() {
        assert_eq!(normalize_encoded_attr(""), "");
        assert_eq!(normalize_encoded_attr("abc"), "abc");
        assert_eq!(normalize_encoded_attr("0"), "0");
        assert_eq!(normalize_encoded_attr("01"), "1");
        assert_eq!(normalize_encoded_attr("01.0"), "01.0");
        assert_eq!(normalize_encoded_attr("0abc"), "0abc");
        assert_eq!(normalize_encoded_attr("-100"), "-100");
        assert_eq!(normalize_encoded_attr("-0100"), "-100");
    }
}
