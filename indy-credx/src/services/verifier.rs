use std::collections::{HashMap, HashSet};

use once_cell::sync::Lazy;
use regex::Regex;

use super::helpers::*;
use super::types::*;
use crate::error::Result;
use crate::ursa::cl::{verifier::Verifier as CryptoVerifier, CredentialPublicKey};
use indy_data_types::anoncreds::{
    nonce::Nonce,
    pres_request::{AttributeInfo, NonRevocedInterval, PredicateInfo, PresentationRequestPayload},
    presentation::{Identifier, RequestedProof, RevealedAttributeInfo},
};
use indy_utils::wql::Query;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Filter {
    schema_id: String,
    schema_issuer_did: String,
    schema_name: String,
    schema_version: String,
    issuer_did: String,
    cred_def_id: String,
}

static INTERNAL_TAG_MATCHER: Lazy<Regex> =
    Lazy::new(|| Regex::new("^attr::([^:]+)::(value|marker)$").unwrap());

pub fn verify_presentation(
    presentation: &Presentation,
    pres_req: &PresentationRequest,
    schemas: &HashMap<SchemaId, &Schema>,
    cred_defs: &HashMap<CredentialDefinitionId, &CredentialDefinition>,
    rev_reg_defs: Option<&HashMap<RevocationRegistryId, &RevocationRegistryDefinition>>,
    rev_regs: Option<&HashMap<RevocationRegistryId, HashMap<u64, &RevocationRegistry>>>,
) -> Result<bool> {
    trace!("verify >>> presentation: {:?}, pres_req: {:?}, schemas: {:?}, cred_defs: {:?}, rev_reg_defs: {:?} rev_regs: {:?}",
    presentation, pres_req, schemas, cred_defs, rev_reg_defs, rev_regs);

    let pres_req = pres_req.value();
    let received_revealed_attrs: HashMap<String, Identifier> =
        received_revealed_attrs(&presentation)?;
    let received_unrevealed_attrs: HashMap<String, Identifier> =
        received_unrevealed_attrs(&presentation)?;
    let received_predicates: HashMap<String, Identifier> = received_predicates(&presentation)?;
    let received_self_attested_attrs: HashSet<String> = received_self_attested_attrs(&presentation);

    compare_attr_from_proof_and_request(
        pres_req,
        &received_revealed_attrs,
        &received_unrevealed_attrs,
        &received_self_attested_attrs,
        &received_predicates,
    )?;

    verify_revealed_attribute_values(&pres_req, &presentation)?;

    verify_requested_restrictions(
        &pres_req,
        &presentation.requested_proof,
        &received_revealed_attrs,
        &received_unrevealed_attrs,
        &received_predicates,
        &received_self_attested_attrs,
    )?;

    compare_timestamps_from_proof_and_request(
        pres_req,
        &received_revealed_attrs,
        &received_unrevealed_attrs,
        &received_self_attested_attrs,
        &received_predicates,
    )?;

    let mut proof_verifier = CryptoVerifier::new_proof_verifier()?;
    let non_credential_schema = build_non_credential_schema()?;

    for sub_proof_index in 0..presentation.identifiers.len() {
        let identifier = presentation.identifiers[sub_proof_index].clone();

        let schema = match schemas
            .get(&identifier.schema_id)
            .ok_or_else(|| err_msg!("Schema not provided for ID: {:?}", identifier.schema_id))?
        {
            Schema::SchemaV1(schema) => schema,
        };

        let cred_def = match cred_defs.get(&identifier.cred_def_id).ok_or_else(|| {
            err_msg!(
                "Credential Definition not provided for ID: {:?}",
                identifier.cred_def_id
            )
        })? {
            CredentialDefinition::CredentialDefinitionV1(cred_def) => cred_def,
        };

        let (rev_reg_def, rev_reg) = if let Some(timestamp) = identifier.timestamp {
            let rev_reg_id = identifier.rev_reg_id.clone().ok_or_else(|| {
                err_msg!("Timestamp provided but Revocation Registry Id not found")
            })?;
            if rev_reg_defs.is_none() {
                return Err(err_msg!(
                    "Timestamp provided but no Revocation Registry Definitions found"
                ));
            }
            if rev_regs.is_none() {
                return Err(err_msg!(
                    "Timestamp provided but no Revocation Registries found"
                ));
            }

            let rev_reg_def = Some(rev_reg_defs.as_ref().unwrap().get(&rev_reg_id).ok_or_else(
                || {
                    err_msg!(
                        "Revocation Registry Definition not provided for ID: {:?}",
                        rev_reg_id
                    )
                },
            )?);

            let rev_reg = Some(
                rev_regs
                    .as_ref()
                    .unwrap()
                    .get(&rev_reg_id)
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

        let attrs_for_credential = get_revealed_attributes_for_credential(
            sub_proof_index,
            &presentation.requested_proof,
            pres_req,
        )?;
        let predicates_for_credential = get_predicates_for_credential(
            sub_proof_index,
            &presentation.requested_proof,
            pres_req,
        )?;

        let credential_schema = build_credential_schema(&schema.attr_names.0)?;
        let sub_pres_request =
            build_sub_proof_request(&attrs_for_credential, &predicates_for_credential)?;

        let credential_pub_key = CredentialPublicKey::build_from_parts(
            &cred_def.value.primary,
            cred_def.value.revocation.as_ref(),
        )?;

        let rev_key_pub = rev_reg_def.as_ref().map(|r_reg_def| match r_reg_def {
            RevocationRegistryDefinition::RevocationRegistryDefinitionV1(reg_def) => {
                &reg_def.value.public_keys.accum_key
            }
        });
        let rev_reg = rev_reg.as_ref().map(|r_reg| match r_reg {
            RevocationRegistry::RevocationRegistryV1(reg_def) => &reg_def.value,
        });

        proof_verifier.add_sub_proof_request(
            &sub_pres_request,
            &credential_schema,
            &non_credential_schema,
            &credential_pub_key,
            rev_key_pub,
            rev_reg,
        )?;
    }

    let valid = proof_verifier.verify(&presentation.proof, pres_req.nonce.as_native())?;

    trace!("verify <<< valid: {:?}", valid);

    Ok(valid)
}

pub fn generate_nonce() -> Result<Nonce> {
    new_nonce()
}

fn get_revealed_attributes_for_credential(
    sub_proof_index: usize,
    requested_proof: &RequestedProof,
    pres_req: &PresentationRequestPayload,
) -> Result<Vec<AttributeInfo>> {
    trace!("_get_revealed_attributes_for_credential >>> sub_proof_index: {:?}, requested_credentials: {:?}, pres_req: {:?}",
           sub_proof_index, requested_proof, pres_req);

    let mut revealed_attrs_for_credential = requested_proof
        .revealed_attrs
        .iter()
        .filter(|&(attr_referent, ref revealed_attr_info)| {
            sub_proof_index == revealed_attr_info.sub_proof_index as usize
                && pres_req.requested_attributes.contains_key(attr_referent)
        })
        .map(|(attr_referent, _)| pres_req.requested_attributes[attr_referent].clone())
        .collect::<Vec<AttributeInfo>>();

    revealed_attrs_for_credential.append(
        &mut requested_proof
            .revealed_attr_groups
            .iter()
            .filter(|&(attr_referent, ref revealed_attr_info)| {
                sub_proof_index == revealed_attr_info.sub_proof_index as usize
                    && pres_req.requested_attributes.contains_key(attr_referent)
            })
            .map(|(attr_referent, _)| pres_req.requested_attributes[attr_referent].clone())
            .collect::<Vec<AttributeInfo>>(),
    );

    trace!(
        "_get_revealed_attributes_for_credential <<< revealed_attrs_for_credential: {:?}",
        revealed_attrs_for_credential
    );

    Ok(revealed_attrs_for_credential)
}

fn get_predicates_for_credential(
    sub_proof_index: usize,
    requested_proof: &RequestedProof,
    pres_req: &PresentationRequestPayload,
) -> Result<Vec<PredicateInfo>> {
    trace!("_get_predicates_for_credential >>> sub_proof_index: {:?}, requested_credentials: {:?}, pres_req: {:?}",
           sub_proof_index, requested_proof, pres_req);

    let predicates_for_credential = requested_proof
        .predicates
        .iter()
        .filter(|&(predicate_referent, requested_referent)| {
            sub_proof_index == requested_referent.sub_proof_index as usize
                && pres_req
                    .requested_predicates
                    .contains_key(predicate_referent)
        })
        .map(|(predicate_referent, _)| pres_req.requested_predicates[predicate_referent].clone())
        .collect::<Vec<PredicateInfo>>();

    trace!(
        "_get_predicates_for_credential <<< predicates_for_credential: {:?}",
        predicates_for_credential
    );

    Ok(predicates_for_credential)
}

fn compare_attr_from_proof_and_request(
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
        .union(&received_self_attested_attrs)
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

fn compare_timestamps_from_proof_and_request(
    pres_req: &PresentationRequestPayload,
    received_revealed_attrs: &HashMap<String, Identifier>,
    received_unrevealed_attrs: &HashMap<String, Identifier>,
    received_self_attested_attrs: &HashSet<String>,
    received_predicates: &HashMap<String, Identifier>,
) -> Result<()> {
    pres_req
        .requested_attributes
        .iter()
        .map(|(referent, info)| {
            validate_timestamp(
                &received_revealed_attrs,
                referent,
                &pres_req.non_revoked,
                &info.non_revoked,
            )
            .or_else(|_| {
                validate_timestamp(
                    &received_unrevealed_attrs,
                    referent,
                    &pres_req.non_revoked,
                    &info.non_revoked,
                )
            })
            .or_else(|_| {
                received_self_attested_attrs
                    .get(referent)
                    .map(|_| ())
                    .ok_or_else(|| err_msg!("Missing referent"))
            })
        })
        .collect::<Result<Vec<()>>>()?;

    pres_req
        .requested_predicates
        .iter()
        .map(|(referent, info)| {
            validate_timestamp(
                received_predicates,
                referent,
                &pres_req.non_revoked,
                &info.non_revoked,
            )
        })
        .collect::<Result<Vec<()>>>()?;

    Ok(())
}

fn validate_timestamp(
    received_: &HashMap<String, Identifier>,
    referent: &str,
    global_interval: &Option<NonRevocedInterval>,
    local_interval: &Option<NonRevocedInterval>,
) -> Result<()> {
    if get_non_revoc_interval(global_interval, local_interval).is_none() {
        return Ok(());
    }

    if !received_
        .get(referent)
        .map(|attr| attr.timestamp.is_some())
        .unwrap_or(false)
    {
        return Err(err_msg!("Missing timestamp"));
    }

    Ok(())
}

fn received_revealed_attrs(proof: &Presentation) -> Result<HashMap<String, Identifier>> {
    let mut revealed_identifiers: HashMap<String, Identifier> = HashMap::new();
    for (referent, info) in proof.requested_proof.revealed_attrs.iter() {
        revealed_identifiers.insert(
            referent.to_string(),
            get_proof_identifier(proof, info.sub_proof_index)?,
        );
    }
    for (referent, infos) in proof.requested_proof.revealed_attr_groups.iter() {
        revealed_identifiers.insert(
            referent.to_string(),
            get_proof_identifier(proof, infos.sub_proof_index)?,
        );
    }
    Ok(revealed_identifiers)
}

fn received_unrevealed_attrs(proof: &Presentation) -> Result<HashMap<String, Identifier>> {
    let mut unrevealed_identifiers: HashMap<String, Identifier> = HashMap::new();
    for (referent, info) in proof.requested_proof.unrevealed_attrs.iter() {
        unrevealed_identifiers.insert(
            referent.to_string(),
            get_proof_identifier(proof, info.sub_proof_index)?,
        );
    }
    Ok(unrevealed_identifiers)
}

fn received_predicates(proof: &Presentation) -> Result<HashMap<String, Identifier>> {
    let mut predicate_identifiers: HashMap<String, Identifier> = HashMap::new();
    for (referent, info) in proof.requested_proof.predicates.iter() {
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
    for (attr_referent, attr_info) in proof.requested_proof.revealed_attrs.iter() {
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
        verify_revealed_attribute_value(attr_name.as_str(), proof, &attr_info)?;
    }

    for (attr_referent, attr_infos) in proof.requested_proof.revealed_attr_groups.iter() {
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
            verify_revealed_attribute_value(
                attr_name,
                proof,
                &RevealedAttributeInfo {
                    sub_proof_index: attr_infos.sub_proof_index,
                    raw: attr_info.raw.clone(),
                    encoded: attr_info.encoded.clone(),
                },
            )?;
        }
    }
    Ok(())
}

fn verify_revealed_attribute_value(
    attr_name: &str,
    proof: &Presentation,
    attr_info: &RevealedAttributeInfo,
) -> Result<()> {
    let reveal_attr_encoded = attr_info.encoded.to_string();
    let reveal_attr_encoded = Regex::new("^0*")
        .unwrap()
        .replace_all(&reveal_attr_encoded, "")
        .to_owned();
    let sub_proof_index = attr_info.sub_proof_index as usize;

    let crypto_proof_encoded = proof
        .proof
        .proofs
        .get(sub_proof_index)
        .ok_or_else(|| {
            err_msg!(
                ProofRejected,
                "CryptoProof not found by index \"{}\"",
                sub_proof_index,
            )
        })?
        .revealed_attrs()?
        .iter()
        .find(|(key, _)| attr_common_view(attr_name) == attr_common_view(&key))
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

fn verify_requested_restrictions(
    pres_req: &PresentationRequestPayload,
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
        .filter(|&(referent, info)| !is_self_attested(&referent, &info, self_attested_attrs))
        .map(|(referent, info)| (referent.to_string(), info.clone()))
        .collect();

    for (referent, info) in requested_attrs {
        if let Some(ref query) = info.restrictions {
            let filter = gather_filter_info(&referent, &proof_attr_identifiers)?;

            let name_value_map: HashMap<String, Option<&str>> = if let Some(name) = info.name {
                let mut map = HashMap::new();
                map.insert(
                    name.clone(),
                    requested_proof
                        .revealed_attrs
                        .get(&referent)
                        .map(|attr| attr.raw.as_str()),
                );
                map
            } else if let Some(names) = info.names {
                let mut map = HashMap::new();
                let attrs = requested_proof
                    .revealed_attr_groups
                    .get(&referent)
                    .ok_or_else(|| err_msg!("Proof does not have referent from proof request"))?;
                for name in names {
                    let val = attrs.values.get(&name).map(|attr| attr.raw.as_str());
                    map.insert(name, val);
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

            do_process_operator(&name_value_map, &query, &filter).map_err(err_map!(
                "Requested restriction validation failed for \"{:?}\" attributes",
                &name_value_map
            ))?;
        }
    }

    for (referent, info) in pres_req.requested_predicates.iter() {
        if let Some(ref query) = info.restrictions {
            let filter = gather_filter_info(&referent, received_predicates)?;

            process_operator(&info.name, &query, &filter, None).map_err(err_map!(
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
        Some(&Query::And(ref array)) | Some(&Query::Or(ref array)) if array.is_empty() => {
            self_attested_attrs.contains(referent)
        }
        None => self_attested_attrs.contains(referent),
        Some(_) => false,
    }
}

fn gather_filter_info(referent: &str, identifiers: &HashMap<String, Identifier>) -> Result<Filter> {
    let identifier = identifiers.get(referent).ok_or_else(|| {
        err_msg!(
            InvalidState,
            "Identifier not found for referent: {}",
            referent
        )
    })?;

    let (_, schema_issuer_did, schema_name, schema_version) =
        identifier.schema_id.parts().ok_or_else(|| {
            err_msg!(
                "Invalid Schema ID `{}`: wrong number of parts",
                identifier.schema_id.0
            )
        })?;

    let issuer_did = identifier.cred_def_id.issuer_did().ok_or_else(|| {
        err_msg!(
            "Invalid Credential Definition ID `{}`: wrong number of parts",
            identifier.cred_def_id.0
        )
    })?;

    Ok(Filter {
        schema_id: identifier.schema_id.0.to_string(),
        schema_name,
        schema_issuer_did: schema_issuer_did.0,
        schema_version,
        cred_def_id: identifier.cred_def_id.0.to_string(),
        issuer_did: issuer_did.0,
    })
}

fn process_operator(
    attr: &str,
    restriction_op: &Query,
    filter: &Filter,
    revealed_value: Option<&str>,
) -> Result<()> {
    let mut attr_value_map = HashMap::new();
    attr_value_map.insert(attr.to_string(), revealed_value);
    do_process_operator(&attr_value_map, restriction_op, filter)
}

fn do_process_operator(
    attr_value_map: &HashMap<String, Option<&str>>,
    restriction_op: &Query,
    filter: &Filter,
) -> Result<()> {
    match restriction_op {
        Query::Eq(ref tag_name, ref tag_value) => {
            process_filter(attr_value_map, &tag_name, &tag_value, filter).map_err(err_map!(
                "$eq operator validation failed for tag: \"{}\", value: \"{}\"",
                tag_name,
                tag_value
            ))
        }
        Query::Neq(ref tag_name, ref tag_value) => {
            if process_filter(attr_value_map, &tag_name, &tag_value, filter).is_err() {
                Ok(())
            } else {
                Err(err_msg!(ProofRejected,
                        "$neq operator validation failed for tag: \"{}\", value: \"{}\". Condition was passed.", tag_name, tag_value))
            }
        }
        Query::In(ref tag_name, ref tag_values) => {
            let res = tag_values
                .iter()
                .any(|val| process_filter(attr_value_map, &tag_name, &val, filter).is_ok());
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
            .map(|op| do_process_operator(attr_value_map, op, filter))
            .collect::<Result<Vec<()>>>()
            .map(|_| ())
            .map_err(err_map!("$and operator validation failed.")),
        Query::Or(ref operators) => {
            let res = operators
                .iter()
                .any(|op| do_process_operator(attr_value_map, op, filter).is_ok());
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
            if do_process_operator(attr_value_map, &*operator, filter).is_err() {
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
    attr_value_map: &HashMap<String, Option<&str>>,
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
        tag_ @ "schema_id" => precess_filed(tag_, &filter.schema_id, tag_value),
        tag_ @ "schema_issuer_did" => precess_filed(tag_, &filter.schema_issuer_did, tag_value),
        tag_ @ "schema_name" => precess_filed(tag_, &filter.schema_name, tag_value),
        tag_ @ "schema_version" => precess_filed(tag_, &filter.schema_version, tag_value),
        tag_ @ "cred_def_id" => precess_filed(tag_, &filter.cred_def_id, tag_value),
        tag_ @ "issuer_did" => precess_filed(tag_, &filter.issuer_did, tag_value),
        x if is_attr_internal_tag(x, attr_value_map) => {
            check_internal_tag_revealed_value(x, tag_value, attr_value_map)
        }
        x if is_attr_operator(x) => Ok(()),
        _ => Err(err_msg!("Unknown Filter Type")),
    }
}

fn precess_filed(filed: &str, filter_value: &str, tag_value: &str) -> Result<()> {
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

fn is_attr_internal_tag(key: &str, attr_value_map: &HashMap<String, Option<&str>>) -> bool {
    INTERNAL_TAG_MATCHER
        .captures(key)
        .map(|caps| {
            caps.get(1)
                .map(|s| attr_value_map.contains_key(&s.as_str().to_string()))
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

fn check_internal_tag_revealed_value(
    key: &str,
    tag_value: &str,
    attr_value_map: &HashMap<String, Option<&str>>,
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

#[cfg(test)]
mod tests {
    use super::*;

    pub const SCHEMA_ID: &str = "123";
    pub const SCHEMA_NAME: &str = "Schema Name";
    pub const SCHEMA_ISSUER_DID: &str = "234";
    pub const SCHEMA_VERSION: &str = "1.2.3";
    pub const CRED_DEF_ID: &str = "345";
    pub const ISSUER_DID: &str = "456";

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
            schema_id: SCHEMA_ID.to_string(),
            schema_name: SCHEMA_NAME.to_string(),
            schema_issuer_did: SCHEMA_ISSUER_DID.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            cred_def_id: CRED_DEF_ID.to_string(),
            issuer_did: ISSUER_DID.to_string(),
        }
    }

    #[test]
    fn test_process_op_eq() {
        let filter = filter();

        let mut op = Query::Eq(schema_id_tag(), SCHEMA_ID.to_string());
        process_operator("zip", &op, &filter, None).unwrap();

        op = Query::And(vec![
            Query::Eq(attr_tag(), "1".to_string()),
            Query::Eq(schema_id_tag(), SCHEMA_ID.to_string()),
        ]);
        process_operator("zip", &op, &filter, None).unwrap();

        op = Query::And(vec![
            Query::Eq(bad_attr_tag(), "1".to_string()),
            Query::Eq(schema_id_tag(), SCHEMA_ID.to_string()),
        ]);
        assert!(process_operator("zip", &op, &filter, None).is_err());

        op = Query::Eq(schema_id_tag(), "NOT HERE".to_string());
        assert!(process_operator("zip", &op, &filter, None).is_err());
    }

    #[test]
    fn test_process_op_ne() {
        let filter = filter();
        let mut op = Query::Neq(schema_id_tag(), SCHEMA_ID.to_string());
        assert!(process_operator("zip", &op, &filter, None).is_err());

        op = Query::Neq(schema_id_tag(), "NOT HERE".to_string());
        process_operator("zip", &op, &filter, None).unwrap()
    }

    #[test]
    fn test_process_op_in() {
        let filter = filter();
        let mut cred_def_ids = vec!["Not Here".to_string()];

        let mut op = Query::In(cred_def_id_tag(), cred_def_ids.clone());
        assert!(process_operator("zip", &op, &filter, None).is_err());

        cred_def_ids.push(CRED_DEF_ID.to_string());
        op = Query::In(cred_def_id_tag(), cred_def_ids.clone());
        process_operator("zip", &op, &filter, None).unwrap()
    }

    #[test]
    fn test_process_op_or() {
        let filter = filter();
        let mut op = Query::Or(vec![
            Query::Eq(schema_id_tag(), "Not Here".to_string()),
            Query::Eq(cred_def_id_tag(), "Not Here".to_string()),
        ]);
        assert!(process_operator("zip", &op, &filter, None).is_err());

        op = Query::Or(vec![
            Query::Eq(schema_id_tag(), SCHEMA_ID.to_string()),
            Query::Eq(cred_def_id_tag(), "Not Here".to_string()),
        ]);
        process_operator("zip", &op, &filter, None).unwrap()
    }

    #[test]
    fn test_process_op_and() {
        let filter = filter();
        let mut op = Query::And(vec![
            Query::Eq(schema_id_tag(), "Not Here".to_string()),
            Query::Eq(cred_def_id_tag(), "Not Here".to_string()),
        ]);
        assert!(process_operator("zip", &op, &filter, None).is_err());

        op = Query::And(vec![
            Query::Eq(schema_id_tag(), SCHEMA_ID.to_string()),
            Query::Eq(cred_def_id_tag(), "Not Here".to_string()),
        ]);
        assert!(process_operator("zip", &op, &filter, None).is_err());

        op = Query::And(vec![
            Query::Eq(schema_id_tag(), SCHEMA_ID.to_string()),
            Query::Eq(cred_def_id_tag(), CRED_DEF_ID.to_string()),
        ]);
        process_operator("zip", &op, &filter, None).unwrap()
    }

    #[test]
    fn test_process_op_not() {
        let filter = filter();
        let mut op = Query::Not(Box::new(Query::And(vec![
            Query::Eq(schema_id_tag(), SCHEMA_ID.to_string()),
            Query::Eq(cred_def_id_tag(), CRED_DEF_ID.to_string()),
        ])));
        assert!(process_operator("zip", &op, &filter, None).is_err());

        op = Query::Not(Box::new(Query::And(vec![
            Query::Eq(schema_id_tag(), "Not Here".to_string()),
            Query::Eq(cred_def_id_tag(), "Not Here".to_string()),
        ])));
        process_operator("zip", &op, &filter, None).unwrap()
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
        assert!(process_operator("zip", &op, &filter, None).is_err());

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
        assert!(process_operator("zip", &op, &filter, None).is_err());

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
        process_operator("zip", &op, &filter, None).unwrap()
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
                Query::Eq(schema_issuer_did_tag(), SCHEMA_ISSUER_DID.to_string()),
                Query::Eq(schema_name_tag(), SCHEMA_NAME.to_string()),
            ]),
            Query::And(vec![
                Query::Eq(schema_version_tag(), SCHEMA_VERSION.to_string()),
                Query::Eq(issuer_did_tag(), ISSUER_DID.to_string()),
            ]),
        ]);
        assert!(process_operator("zip", &op, &filter, None).is_err());

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
                Query::Eq(schema_issuer_did_tag(), SCHEMA_ISSUER_DID.to_string()),
                Query::Eq(schema_name_tag(), SCHEMA_NAME.to_string()),
            ]),
            Query::And(vec![
                Query::Eq(schema_version_tag(), SCHEMA_VERSION.to_string()),
                Query::Eq(issuer_did_tag(), ISSUER_DID.to_string()),
            ]),
            Query::Not(Box::new(Query::Eq(
                schema_version_tag(),
                "NOT HERE".to_string(),
            ))),
        ]);
        process_operator("zip", &op, &filter, None).unwrap();

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
                Query::Eq(schema_issuer_did_tag(), SCHEMA_ISSUER_DID.to_string()),
                Query::Eq(schema_name_tag(), SCHEMA_NAME.to_string()),
            ]),
            Query::And(vec![
                Query::Eq(schema_version_tag(), SCHEMA_VERSION.to_string()),
                Query::Eq(issuer_did_tag(), ISSUER_DID.to_string()),
            ]),
            Query::Not(Box::new(Query::Eq(
                schema_version_tag(),
                SCHEMA_VERSION.to_string(),
            ))),
        ]);
        assert!(process_operator("zip", &op, &filter, None).is_err());
    }

    #[test]
    fn test_process_op_eq_revealed_value() {
        let filter = filter();
        let value = "value";

        let mut op = Query::Eq(attr_tag_value(), value.to_string());
        process_operator("zip", &op, &filter, Some(value)).unwrap();

        op = Query::And(vec![
            Query::Eq(attr_tag_value(), value.to_string()),
            Query::Eq(schema_issuer_did_tag(), SCHEMA_ISSUER_DID.to_string()),
        ]);
        process_operator("zip", &op, &filter, Some(value)).unwrap();

        op = Query::Eq(attr_tag_value(), value.to_string());
        assert!(process_operator("zip", &op, &filter, Some("NOT HERE")).is_err());
    }

    fn _received() -> HashMap<String, Identifier> {
        let mut res: HashMap<String, Identifier> = HashMap::new();
        res.insert(
            "referent_1".to_string(),
            Identifier {
                timestamp: Some(1234),
                schema_id: SchemaId(String::new()),
                cred_def_id: CredentialDefinitionId(String::new()),
                rev_reg_id: Some(RevocationRegistryId(String::new())),
            },
        );
        res.insert(
            "referent_2".to_string(),
            Identifier {
                timestamp: None,
                schema_id: SchemaId(String::new()),
                cred_def_id: CredentialDefinitionId(String::new()),
                rev_reg_id: Some(RevocationRegistryId(String::new())),
            },
        );
        res
    }

    fn _interval() -> NonRevocedInterval {
        NonRevocedInterval {
            from: None,
            to: Some(1234),
        }
    }

    #[test]
    fn validate_timestamp_works() {
        validate_timestamp(&_received(), "referent_1", &None, &None).unwrap();
        validate_timestamp(&_received(), "referent_1", &Some(_interval()), &None).unwrap();
        validate_timestamp(&_received(), "referent_1", &None, &Some(_interval())).unwrap();
    }

    #[test]
    fn validate_timestamp_not_work() {
        validate_timestamp(&_received(), "referent_2", &Some(_interval()), &None).unwrap_err();
        validate_timestamp(&_received(), "referent_2", &None, &Some(_interval())).unwrap_err();
        validate_timestamp(&_received(), "referent_3", &None, &Some(_interval())).unwrap_err();
    }
}
