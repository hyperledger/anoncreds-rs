use crate::data_types::cred_def::CredentialDefinition;
use crate::data_types::cred_def::CredentialDefinitionId;
use crate::data_types::pres_request::PresentationRequestPayload;
use crate::data_types::pres_request::{AttributeInfo, NonRevokedInterval, PredicateInfo};
use crate::data_types::presentation::Identifier;
use crate::data_types::rev_reg_def::RevocationRegistryDefinitionId;
use crate::data_types::schema::Schema;
use crate::data_types::schema::SchemaId;
use crate::data_types::w3c::credential::CredentialAttributeValue;
use crate::data_types::w3c::credential::W3CCredential;
use crate::data_types::w3c::presentation::W3CPresentation;
use crate::data_types::w3c::presentation_proof::CredentialPresentationProof;
use crate::error::Result;
use crate::services::helpers::get_requested_non_revoked_interval;
use crate::types::{PresentationRequest, RevocationRegistryDefinition, RevocationStatusList};
use crate::utils::query::Query;
use crate::verifier::CLProofVerifier;
use crate::verifier::{gather_filter_info, process_operator};
use anoncreds_clsignatures::Proof;
use std::collections::HashMap;

/// Verify an incoming presentation in W3C form
pub fn verify_presentation(
    presentation: &W3CPresentation,
    pres_req: &PresentationRequest,
    schemas: &HashMap<SchemaId, Schema>,
    cred_defs: &HashMap<CredentialDefinitionId, CredentialDefinition>,
    rev_reg_defs: Option<&HashMap<RevocationRegistryDefinitionId, RevocationRegistryDefinition>>,
    rev_status_lists: Option<Vec<RevocationStatusList>>,
    nonrevoke_interval_override: Option<
        &HashMap<RevocationRegistryDefinitionId, HashMap<u64, u64>>,
    >,
) -> Result<bool> {
    trace!("verify_w3c_presentation >>> presentation: {:?}, pres_req: {:?}, schemas: {:?}, cred_defs: {:?}, rev_reg_defs: {:?} rev_status_lists: {:?}",
    presentation, pres_req, schemas, cred_defs, rev_reg_defs, rev_status_lists);

    let presentation_request = pres_req.value();

    // we need to decode proofs in advance as their data needed for restrictions check
    let credential_proofs = presentation
        .verifiable_credential
        .iter()
        .map(|verifiable_credential| verifiable_credential.get_presentation_proof())
        .collect::<Result<Vec<&CredentialPresentationProof>>>()?;

    // These values are from the prover and cannot be trusted
    // Check that all requested attributes and predicates included into the presentation
    // Also check that all requested credential restriction are valid
    check_request_data(
        presentation_request,
        presentation,
        schemas,
        cred_defs,
        nonrevoke_interval_override,
        &credential_proofs,
    )?;

    let proof_data = presentation.proof.get_proof_value()?;
    let mut proof = Proof {
        proofs: Vec::new(),
        aggregated_proof: proof_data.aggregated,
    };

    let mut proof_verifier = CLProofVerifier::init(
        presentation_request,
        schemas,
        cred_defs,
        rev_reg_defs,
        rev_status_lists.as_ref(),
    )?;

    for (index, verifiable_credential) in presentation.verifiable_credential.iter().enumerate() {
        let credential_proof = credential_proofs
            .get(index)
            .ok_or_else(|| err_msg!("Unable to get credential proof for index {}", index))?;
        let proof_data = credential_proof.get_proof_value()?;
        let schema_id = &verifiable_credential.get_schema_id();
        let cred_def_id = &verifiable_credential.get_cred_def_id();
        let rev_reg_id = verifiable_credential.get_rev_reg_id();

        _check_encoded_attributes(verifiable_credential, &proof_data)?;

        let attributes: Vec<AttributeInfo> = verifiable_credential.attributes();
        let predicates: Vec<PredicateInfo> = verifiable_credential.predicates();

        proof_verifier.add_sub_proof(
            &attributes,
            &predicates,
            schema_id,
            cred_def_id,
            rev_reg_id,
            credential_proof.timestamp,
        )?;

        proof.proofs.push(proof_data.sub_proof);
    }

    let valid = proof_verifier.verify(&proof)?;

    trace!("verify_w3c_presentation <<< valid: {:?}", valid);

    Ok(valid)
}

fn check_credential_restrictions(
    credential: &W3CCredential,
    restrictions: Option<&Query>,
    schemas: &HashMap<SchemaId, Schema>,
    cred_defs: &HashMap<CredentialDefinitionId, CredentialDefinition>,
) -> Result<()> {
    if let Some(restrictions) = restrictions {
        let identifier: Identifier = Identifier {
            schema_id: credential.get_schema_id().to_owned(),
            cred_def_id: credential.get_cred_def_id().to_owned(),
            rev_reg_id: credential.get_rev_reg_id().cloned(),
            timestamp: None,
        };
        let filter = gather_filter_info(&identifier, schemas, cred_defs)?;
        let mut attr_value_map: HashMap<String, Option<&str>> = HashMap::new();
        for (attribute, value) in credential.credential_subject.attributes.0.iter() {
            if let CredentialAttributeValue::Attribute(value) = value {
                attr_value_map.insert(attribute.to_owned(), Some(value));
            }
        }
        process_operator(&attr_value_map, restrictions, &filter).map_err(err_map!(
            "Requested restriction validation failed for \"{:?}\" attributes",
            &attr_value_map
        ))?;
    }
    Ok(())
}

fn check_credential_non_revoked_interval(
    credential: &W3CCredential,
    presentation_request: &PresentationRequestPayload,
    nonrevoke_interval: Option<&NonRevokedInterval>,
    nonrevoke_interval_override: Option<
        &HashMap<RevocationRegistryDefinitionId, HashMap<u64, u64>>,
    >,
    proof: &CredentialPresentationProof,
) -> Result<()> {
    if credential.rev_reg_id().is_none() {
        return Ok(());
    }

    let non_revoked_interval = get_requested_non_revoked_interval(
        credential.rev_reg_id(),
        nonrevoke_interval,
        presentation_request.non_revoked.as_ref(),
        nonrevoke_interval_override,
    );

    if let Some(non_revoked_interval) = non_revoked_interval {
        let timestamp = proof
            .timestamp
            .ok_or_else(|| err_msg!("Credential timestamp not found for revocation check"))?;
        non_revoked_interval.is_valid(timestamp)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn check_credential_conditions(
    credential: &W3CCredential,
    presentation_request: &PresentationRequestPayload,
    restrictions: Option<&Query>,
    schemas: &HashMap<SchemaId, Schema>,
    cred_defs: &HashMap<CredentialDefinitionId, CredentialDefinition>,
    nonrevoke_interval: Option<&NonRevokedInterval>,
    nonrevoke_interval_override: Option<
        &HashMap<RevocationRegistryDefinitionId, HashMap<u64, u64>>,
    >,
    proof: &CredentialPresentationProof,
) -> Result<()> {
    check_credential_restrictions(credential, restrictions, schemas, cred_defs)?;
    check_credential_non_revoked_interval(
        credential,
        presentation_request,
        nonrevoke_interval,
        nonrevoke_interval_override,
        proof,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn check_requested_attribute<'a>(
    presentation_request: &PresentationRequestPayload,
    presentation: &'a W3CPresentation,
    attribute: &str,
    restrictions: Option<&Query>,
    nonrevoke_interval: Option<&NonRevokedInterval>,
    schemas: &HashMap<SchemaId, Schema>,
    cred_defs: &HashMap<CredentialDefinitionId, CredentialDefinition>,
    nonrevoke_interval_override: Option<
        &HashMap<RevocationRegistryDefinitionId, HashMap<u64, u64>>,
    >,
    credential_proofs: &[&CredentialPresentationProof],
) -> Result<&'a W3CCredential> {
    let mut found_credential: Option<&'a W3CCredential> = None;
    for (index, credential) in presentation.verifiable_credential.iter().enumerate() {
        let proof = credential_proofs
            .get(index)
            .ok_or_else(|| err_msg!("Unable to get credential proof for index {}", index))?;
        let valid_credential = credential.has_attribute(attribute)
            && check_credential_conditions(
                credential,
                presentation_request,
                restrictions,
                schemas,
                cred_defs,
                nonrevoke_interval,
                nonrevoke_interval_override,
                proof,
            )
            .is_ok();

        if valid_credential {
            found_credential = Some(credential);
            break;
        }
    }

    if let Some(found_credential) = found_credential {
        // credential for attribute is found in revealed data
        return Ok(found_credential);
    }

    // else consider attribute as unrevealed and try to find credential which schema includes requested attribute
    for (index, credential) in presentation.verifiable_credential.iter().enumerate() {
        let proof = credential_proofs
            .get(index)
            .ok_or_else(|| err_msg!("Unable to get credential proof for index {}", index))?;
        let schema = schemas
            .get(&credential.credential_schema.schema)
            .ok_or_else(|| {
                err_msg!(
                    "Credential schema not found {}",
                    credential.credential_schema.schema
                )
            })?;

        let valid_credential = schema.has_attribute(attribute)
            && check_credential_conditions(
                credential,
                presentation_request,
                restrictions,
                schemas,
                cred_defs,
                nonrevoke_interval,
                nonrevoke_interval_override,
                proof,
            )
            .is_ok();

        if valid_credential {
            found_credential = Some(credential);
            break;
        }
    }

    if let Some(found_credential) = found_credential {
        // credential for attribute is found in revealed data
        return Ok(found_credential);
    }

    Err(err_msg!(
        "Presentation does not contain attribute {}",
        attribute
    ))
}

#[allow(clippy::too_many_arguments)]
fn check_requested_predicate<'a>(
    presentation_request: &PresentationRequestPayload,
    presentation: &'a W3CPresentation,
    predicate: &PredicateInfo,
    schemas: &HashMap<SchemaId, Schema>,
    cred_defs: &HashMap<CredentialDefinitionId, CredentialDefinition>,
    nonrevoke_interval_override: Option<
        &HashMap<RevocationRegistryDefinitionId, HashMap<u64, u64>>,
    >,
    credential_proofs: &[&CredentialPresentationProof],
) -> Result<&'a W3CCredential> {
    for (index, credential) in presentation.verifiable_credential.iter().enumerate() {
        let proof = credential_proofs
            .get(index)
            .ok_or_else(|| err_msg!("Unable to get credential proof for index {}", index))?;
        let valid_credential = credential.has_predicate(predicate)
            && check_credential_conditions(
                credential,
                presentation_request,
                predicate.restrictions.as_ref(),
                schemas,
                cred_defs,
                predicate.non_revoked.as_ref(),
                nonrevoke_interval_override,
                proof,
            )
            .is_ok();

        if valid_credential {
            return Ok(credential);
        }
    }

    Err(err_msg!(
        "Presentation does not contain attribute {}",
        predicate.name
    ))
}

fn check_request_data(
    presentation_request: &PresentationRequestPayload,
    presentation: &W3CPresentation,
    schemas: &HashMap<SchemaId, Schema>,
    cred_defs: &HashMap<CredentialDefinitionId, CredentialDefinition>,
    nonrevoke_interval_override: Option<
        &HashMap<RevocationRegistryDefinitionId, HashMap<u64, u64>>,
    >,
    credential_proofs: &[&CredentialPresentationProof],
) -> Result<()> {
    for (_, attribute) in presentation_request.requested_attributes.iter() {
        if let Some(ref name) = attribute.name {
            check_requested_attribute(
                presentation_request,
                presentation,
                name,
                attribute.restrictions.as_ref(),
                attribute.non_revoked.as_ref(),
                schemas,
                cred_defs,
                nonrevoke_interval_override,
                credential_proofs,
            )?;
        }
        if let Some(ref names) = attribute.names {
            for name in names {
                check_requested_attribute(
                    presentation_request,
                    presentation,
                    name,
                    attribute.restrictions.as_ref(),
                    attribute.non_revoked.as_ref(),
                    schemas,
                    cred_defs,
                    nonrevoke_interval_override,
                    credential_proofs,
                )?;
            }
        }
    }
    for (_, predicate) in presentation_request.requested_predicates.iter() {
        check_requested_predicate(
            presentation_request,
            presentation,
            predicate,
            schemas,
            cred_defs,
            nonrevoke_interval_override,
            credential_proofs,
        )?;
    }
    Ok(())
}

fn _check_encoded_attributes(
    credential: &W3CCredential,
    credential_proof: &CredentialPresentationProofValue,
) -> Result<()> {
    credential
        .get_attributes()
        .iter()
        .map(|(name, value)| {
            encode_credential_attribute(value).and_then(|encoded| {
                verify_revealed_attribute_value(name, &credential_proof.sub_proof, &encoded)
            })
        })
        .collect::<Result<Vec<()>>>()?;
    Ok(())
}
