use crate::data_types::cred_def::CredentialDefinition;
use crate::data_types::cred_def::CredentialDefinitionId;
use crate::data_types::pres_request::PresentationRequestPayload;
use crate::data_types::pres_request::{NonRevokedInterval, PredicateInfo};
use crate::data_types::presentation::Identifier;
use crate::data_types::rev_reg_def::RevocationRegistryDefinitionId;
use crate::data_types::schema::Schema;
use crate::data_types::schema::SchemaId;
use crate::data_types::w3c::credential::W3CCredential;
use crate::data_types::w3c::credential_attributes::CredentialAttributeValue;
use crate::data_types::w3c::presentation::W3CPresentation;
use crate::data_types::w3c::proof::CredentialPresentationProofValue;
use crate::error::Result;
use crate::services::helpers::{encode_credential_attribute, get_requested_non_revoked_interval};
use crate::types::{PresentationRequest, RevocationRegistryDefinition, RevocationStatusList};
use crate::utils::query::Query;
use crate::verifier::{gather_filter_info, process_operator};
use crate::verifier::{verify_revealed_attribute_value, CLProofVerifier};
use anoncreds_clsignatures::{Proof, SubProof};
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
    trace!("verify >>> verify_w3c_presentation: {:?}, pres_req: {:?}, schemas: {:?}, cred_defs: {:?}, rev_reg_defs: {:?} rev_status_lists: {:?}",
    presentation, pres_req, schemas, cred_defs, rev_reg_defs, rev_status_lists);

    presentation.validate()?;

    let presentation_request = pres_req.value();

    // we need to decode proofs in advance as their data needed in two places: checking
    // against the request and proof verification itself
    let credential_proofs = presentation
        .verifiable_credential
        .iter()
        .map(|vc| vc.get_credential_presentation_proof().cloned())
        .collect::<Result<Vec<CredentialPresentationProofValue>>>()?;

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

    let presentation_proof = presentation.get_presentation_proof()?;

    let mut proof_verifier = CLProofVerifier::new(
        presentation_request,
        schemas,
        cred_defs,
        rev_reg_defs,
        rev_status_lists.as_ref(),
    )?;

    let mut sub_proofs: Vec<SubProof> = Vec::with_capacity(credential_proofs.len());

    for credential_proof in credential_proofs {
        proof_verifier.add_sub_proof(
            &credential_proof.sub_proof,
            &credential_proof.schema_id,
            &credential_proof.cred_def_id,
            credential_proof.rev_reg_id.as_ref(),
            credential_proof.timestamp,
        )?;

        sub_proofs.push(credential_proof.sub_proof);
    }

    let cl_proof = Proof {
        proofs: sub_proofs,
        aggregated_proof: presentation_proof.aggregated.clone(),
    };
    let valid = proof_verifier.verify(&cl_proof)?;

    trace!("verify_w3c_presentation <<< valid: {:?}", valid);

    Ok(valid)
}

fn check_credential_restrictions(
    credential: &W3CCredential,
    restrictions: Option<&Query>,
    schemas: &HashMap<SchemaId, Schema>,
    cred_defs: &HashMap<CredentialDefinitionId, CredentialDefinition>,
    proof: &CredentialPresentationProofValue,
) -> Result<()> {
    if let Some(restrictions) = restrictions {
        let identifier: Identifier = Identifier {
            schema_id: proof.schema_id.to_owned(),
            cred_def_id: proof.cred_def_id.to_owned(),
            rev_reg_id: proof.rev_reg_id.to_owned(),
            timestamp: None,
        };
        let filter = gather_filter_info(&identifier, schemas, cred_defs)?;
        let mut attr_value_map: HashMap<String, Option<String>> = HashMap::new();
        for (attribute, value) in credential.credential_subject.0.iter() {
            if let CredentialAttributeValue::String(value) = value {
                attr_value_map.insert(attribute.to_owned(), Some(value.to_string()));
            }
            if let CredentialAttributeValue::Number(value) = value {
                attr_value_map.insert(attribute.to_owned(), Some(value.to_string()));
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
    presentation_request: &PresentationRequestPayload,
    nonrevoke_interval: Option<&NonRevokedInterval>,
    nonrevoke_interval_override: Option<
        &HashMap<RevocationRegistryDefinitionId, HashMap<u64, u64>>,
    >,
    proof: &CredentialPresentationProofValue,
) -> Result<()> {
    if let Some(ref rev_reg_id) = proof.rev_reg_id {
        let non_revoked_interval = get_requested_non_revoked_interval(
            Some(rev_reg_id),
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
    proof: &CredentialPresentationProofValue,
) -> Result<()> {
    check_credential_restrictions(credential, restrictions, schemas, cred_defs, proof)?;
    check_credential_non_revoked_interval(
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
    credential_proofs: &[CredentialPresentationProofValue],
) -> Result<&'a W3CCredential> {
    // find a credential matching to requested attribute
    for (index, credential) in presentation.verifiable_credential.iter().enumerate() {
        // credential must contain requested attribute in subject
        if let Ok((attribute, value)) = credential.get_attribute(attribute) {
            // attribute value must match to encoded value in cl proof
            let proof = credential_proofs
                .get(index)
                .ok_or_else(|| err_msg!("Unable to get credential proof for index {}", index))?;

            let encoded = encode_credential_attribute(&value.to_string())?;
            if verify_revealed_attribute_value(&attribute, &proof.sub_proof, &encoded).is_err() {
                continue;
            }

            // check credential restrictions
            if check_credential_conditions(
                credential,
                presentation_request,
                restrictions,
                schemas,
                cred_defs,
                nonrevoke_interval,
                nonrevoke_interval_override,
                proof,
            )
            .is_err()
            {
                continue;
            }

            return Ok(credential);
        }
    }

    // else consider attribute as unrevealed and try to find credential which schema includes requested attribute
    for (index, credential) in presentation.verifiable_credential.iter().enumerate() {
        let proof = credential_proofs
            .get(index)
            .ok_or_else(|| err_msg!("Unable to get credential proof for index {}", index))?;
        let schema = schemas
            .get(&proof.schema_id)
            .ok_or_else(|| err_msg!("Credential schema not found {}", proof.schema_id))?;

        // credential schema must contain requested attribute
        if !schema.has_case_insensitive_attribute(attribute) {
            continue;
        }

        // check credential restrictions
        if check_credential_conditions(
            credential,
            presentation_request,
            restrictions,
            schemas,
            cred_defs,
            nonrevoke_interval,
            nonrevoke_interval_override,
            proof,
        )
        .is_err()
        {
            continue;
        }

        return Ok(credential);
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
    credential_proofs: &[CredentialPresentationProofValue],
    predicate: &PredicateInfo,
    schemas: &HashMap<SchemaId, Schema>,
    cred_defs: &HashMap<CredentialDefinitionId, CredentialDefinition>,
    nonrevoke_interval_override: Option<
        &HashMap<RevocationRegistryDefinitionId, HashMap<u64, u64>>,
    >,
) -> Result<&'a W3CCredential> {
    // find a credential matching to requested predicate
    for (index, credential) in presentation.verifiable_credential.iter().enumerate() {
        // credential must contain requested predicate in subject
        if let Ok((name, _)) = credential.get_predicate(&predicate.name) {
            // predicate value must match to predicate in cl proof
            let proof = credential_proofs
                .get(index)
                .ok_or_else(|| err_msg!("Unable to get credential proof for index {}", index))?;

            let matches_cl_proof_predicate = proof.sub_proof.predicates().into_iter().find(|p| {
                p.attr_name == name
                    && p.p_type == predicate.clone().p_type.into()
                    && p.value == predicate.p_value
            });

            if matches_cl_proof_predicate.is_none() {
                continue;
            }

            // check credential restrictions
            if check_credential_conditions(
                credential,
                presentation_request,
                predicate.restrictions.as_ref(),
                schemas,
                cred_defs,
                predicate.non_revoked.as_ref(),
                nonrevoke_interval_override,
                proof,
            )
            .is_err()
            {
                continue;
            }

            return Ok(credential);
        }
    }

    Err(err_msg!(
        "Presentation does not contain predicate {}",
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
    credential_proofs: &[CredentialPresentationProofValue],
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
            credential_proofs,
            predicate,
            schemas,
            cred_defs,
            nonrevoke_interval_override,
        )?;
    }

    for (cred, proof) in presentation
        .verifiable_credential
        .as_slice()
        .iter()
        .zip(credential_proofs)
    {
        let Some(cred_def_issuer) = cred_defs.get(&proof.cred_def_id).map(|cd| &cd.issuer_id) else {
            return Err(err_msg!("Missing credential definition"));
        };
        if cred_def_issuer != &cred.issuer {
            return Err(err_msg!("Inconsistent issuer ID"));
        }
        let di_proof = cred.get_data_integrity_proof()?;
        if di_proof.verification_method != proof.cred_def_id.0 {
            return Err(err_msg!("Inconsistent credential definition ID"));
        }
    }

    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::data_types::nonce::Nonce;
    use crate::data_types::pres_request::{AttributeInfo, PredicateTypes};
    use crate::data_types::w3c::credential_attributes::CredentialSubject;
    use crate::data_types::w3c::proof::tests::{
        credential_pres_proof_value, presentation_proof_value,
    };
    use crate::data_types::w3c::proof::DataIntegrityProof;
    use crate::w3c::credential_conversion::tests::{
        cred_def_id, credential_definition, issuer_id, schema, schema_id,
    };
    use crate::ErrorKind;
    use rstest::*;

    const PROOF_TIMESTAMP_FROM: u64 = 40;
    const PROOF_TIMESTAMP_TO: u64 = 50;
    const PROOF_TIMESTAMP: u64 = 50;

    fn credential_attributes() -> CredentialSubject {
        CredentialSubject(HashMap::from([
            (
                "name".to_string(),
                CredentialAttributeValue::String("Alice".to_string()),
            ),
            (
                "height".to_string(),
                CredentialAttributeValue::String("178".to_string()),
            ),
            ("age".to_string(), CredentialAttributeValue::Bool(true)),
        ]))
    }

    pub(crate) fn revocation_id() -> RevocationRegistryDefinitionId {
        RevocationRegistryDefinitionId::new_unchecked("mock:uri")
    }

    fn _non_revoke_override_interval(
        timestamp: u64,
        change: u64,
    ) -> HashMap<RevocationRegistryDefinitionId, HashMap<u64, u64>> {
        let non_revoke_override =
            HashMap::from([(revocation_id(), HashMap::from([(timestamp, change)]))]);

        non_revoke_override
    }

    fn _credential() -> W3CCredential {
        let proof =
            DataIntegrityProof::new_credential_presentation_proof(&credential_pres_proof_value())
                .unwrap();
        W3CCredential::new(issuer_id(), credential_attributes(), proof, None)
    }

    fn _w3_presentation() -> W3CPresentation {
        let proof = DataIntegrityProof::new_presentation_proof(
            &presentation_proof_value(),
            "1".to_string(),
            cred_def_id().to_string(),
        )
        .unwrap();
        W3CPresentation::new(vec![_credential()], proof, None)
    }

    fn _base_presentation_request() -> PresentationRequestPayload {
        PresentationRequestPayload {
            nonce: Nonce::new().unwrap(),
            name: "Presentation request".to_string(),
            version: "1.0".to_string(),
            requested_attributes: HashMap::new(),
            requested_predicates: HashMap::new(),
            non_revoked: None,
        }
    }

    fn _attribute() -> AttributeInfo {
        AttributeInfo {
            name: Some("name".to_string()),
            names: None,
            restrictions: None,
            non_revoked: None,
        }
    }

    fn _attributes_group() -> AttributeInfo {
        AttributeInfo {
            name: None,
            names: Some(vec!["name".to_string(), "height".to_string()]),
            restrictions: None,
            non_revoked: None,
        }
    }

    fn _predicate() -> PredicateInfo {
        PredicateInfo {
            name: "age".to_string(),
            p_type: PredicateTypes::GE,
            p_value: 18,
            restrictions: None,
            non_revoked: None,
        }
    }

    #[fixture]
    fn _presentation_request_with_attribute_and_predicate() -> PresentationRequestPayload {
        PresentationRequestPayload {
            requested_attributes: HashMap::from([("attr1_referent".to_string(), _attribute())]),
            requested_predicates: HashMap::from([(
                "predicate1_referent".to_string(),
                _predicate(),
            )]),
            .._base_presentation_request()
        }
    }

    #[fixture]
    fn _presentation_request_with_single_attribute() -> PresentationRequestPayload {
        PresentationRequestPayload {
            requested_attributes: HashMap::from([("attr1_referent".to_string(), _attribute())]),
            .._base_presentation_request()
        }
    }

    #[fixture]
    fn _presentation_request_with_multiple_attributes() -> PresentationRequestPayload {
        PresentationRequestPayload {
            requested_attributes: HashMap::from([
                ("attr1_referent".to_string(), _attribute()),
                (
                    "attr2_referent".to_string(),
                    AttributeInfo {
                        name: Some("height".to_string()),
                        names: None,
                        restrictions: None,
                        non_revoked: None,
                    },
                ),
            ]),
            .._base_presentation_request()
        }
    }

    #[fixture]
    fn _presentation_request_with_attribute_names() -> PresentationRequestPayload {
        PresentationRequestPayload {
            requested_attributes: HashMap::from([(
                "attr1_referent".to_string(),
                _attributes_group(),
            )]),
            .._base_presentation_request()
        }
    }

    #[fixture]
    fn _presentation_request_with_predicate() -> PresentationRequestPayload {
        PresentationRequestPayload {
            requested_predicates: HashMap::from([(
                "predicate1_referent".to_string(),
                _predicate(),
            )]),
            .._base_presentation_request()
        }
    }

    #[fixture]
    fn _presentation_request_with_attribute_restrictions() -> PresentationRequestPayload {
        PresentationRequestPayload {
            requested_attributes: HashMap::from([(
                "attr1_referent".to_string(),
                AttributeInfo {
                    restrictions: Some(Query::Eq("schema_id".to_string(), schema_id().to_string())),
                    .._attribute()
                },
            )]),
            .._base_presentation_request()
        }
    }

    #[fixture]
    fn _presentation_request_with_case_insensitive_attribute_and_predicate(
    ) -> PresentationRequestPayload {
        PresentationRequestPayload {
            requested_attributes: HashMap::from([
                (
                    "attr1_referent".to_string(),
                    AttributeInfo {
                        name: Some("NAME".to_string()),
                        .._attribute()
                    },
                ),
                (
                    "attr2_referent".to_string(),
                    AttributeInfo {
                        name: Some("Height".to_string()),
                        .._attribute()
                    },
                ),
            ]),
            requested_predicates: HashMap::from([(
                "predicate1_referent".to_string(),
                PredicateInfo {
                    name: "AGE".to_string(),
                    .._predicate()
                },
            )]),
            .._base_presentation_request()
        }
    }

    #[fixture]
    fn _presentation_request_with_missing_attribute() -> PresentationRequestPayload {
        PresentationRequestPayload {
            requested_attributes: HashMap::from([(
                "attr1_referent".to_string(),
                AttributeInfo {
                    name: Some("missing".to_string()),
                    .._attribute()
                },
            )]),
            .._presentation_request_with_single_attribute()
        }
    }

    #[fixture]
    fn _presentation_request_with_missing_attribute_group() -> PresentationRequestPayload {
        PresentationRequestPayload {
            requested_attributes: HashMap::from([(
                "attr1_referent".to_string(),
                AttributeInfo {
                    names: Some(vec![
                        "name".to_string(),
                        "height".to_string(),
                        "missing".to_string(),
                    ]),
                    .._attribute()
                },
            )]),
            .._presentation_request_with_single_attribute()
        }
    }

    #[fixture]
    fn _presentation_request_with_missing_predicate() -> PresentationRequestPayload {
        PresentationRequestPayload {
            requested_predicates: HashMap::from([(
                "predicate1_referent".to_string(),
                PredicateInfo {
                    name: "missing".to_string(),
                    .._predicate()
                },
            )]),
            .._presentation_request_with_predicate()
        }
    }

    #[fixture]
    fn _presentation_request_with_invalid_predicate_restrictions() -> PresentationRequestPayload {
        PresentationRequestPayload {
            requested_predicates: HashMap::from([(
                "predicate1_referent".to_string(),
                PredicateInfo {
                    restrictions: Some(Query::Eq("schema_id".to_string(), "invalid".to_string())),
                    .._predicate()
                },
            )]),
            .._presentation_request_with_predicate()
        }
    }

    #[fixture]
    fn _presentation_request_with_invalid_attribute_restrictions() -> PresentationRequestPayload {
        PresentationRequestPayload {
            requested_attributes: HashMap::from([(
                "attr1_referent".to_string(),
                AttributeInfo {
                    restrictions: Some(Query::Eq("schema_id".to_string(), "invalid".to_string())),
                    .._attribute()
                },
            )]),
            .._presentation_request_with_single_attribute()
        }
    }

    #[fixture]
    fn _presentation_request_with_different_predicate() -> PresentationRequestPayload {
        PresentationRequestPayload {
            requested_predicates: HashMap::from([(
                "predicate1_referent".to_string(),
                PredicateInfo {
                    p_type: PredicateTypes::LE,
                    .._predicate()
                },
            )]),
            .._base_presentation_request()
        }
    }

    #[fixture]
    fn _presentation_request_with_non_revoke_interval() -> PresentationRequestPayload {
        PresentationRequestPayload {
            non_revoked: Some(NonRevokedInterval {
                from: Some(PROOF_TIMESTAMP_FROM),
                to: Some(PROOF_TIMESTAMP_TO),
            }),
            .._presentation_request_with_single_attribute()
        }
    }

    #[fixture]
    fn _presentation_request_with_invalid_non_revoke_interval() -> PresentationRequestPayload {
        PresentationRequestPayload {
            non_revoked: Some(NonRevokedInterval {
                from: Some(PROOF_TIMESTAMP_TO + 1),
                to: Some(PROOF_TIMESTAMP_TO + 10),
            }),
            .._presentation_request_with_single_attribute()
        }
    }

    #[fixture]
    fn schemas() -> HashMap<SchemaId, Schema> {
        HashMap::from([(schema_id(), schema())])
    }

    #[fixture]
    fn cred_defs() -> HashMap<CredentialDefinitionId, CredentialDefinition> {
        HashMap::from([(cred_def_id(), credential_definition())])
    }

    #[fixture]
    fn presentation() -> W3CPresentation {
        _w3_presentation()
    }

    impl W3CPresentation {
        fn credential_proofs(&self) -> Vec<CredentialPresentationProofValue> {
            self.verifiable_credential
                .iter()
                .map(|vc| vc.get_credential_presentation_proof().cloned())
                .collect::<Result<Vec<CredentialPresentationProofValue>>>()
                .unwrap()
        }
    }

    #[rstest]
    #[case(_presentation_request_with_single_attribute())]
    #[case(_presentation_request_with_attribute_and_predicate())]
    #[case(_presentation_request_with_multiple_attributes())]
    #[case(_presentation_request_with_attribute_names())]
    #[case(_presentation_request_with_predicate())]
    #[case(_presentation_request_with_attribute_restrictions())]
    #[case(_presentation_request_with_case_insensitive_attribute_and_predicate())]
    #[case(_presentation_request_with_non_revoke_interval())]
    fn test_check_request_data_works_for_positive_cases(
        schemas: HashMap<SchemaId, Schema>,
        cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition>,
        presentation: W3CPresentation,
        #[case] presentation_request: PresentationRequestPayload,
    ) {
        check_request_data(
            &presentation_request,
            &presentation,
            &schemas,
            &cred_defs,
            None,
            &presentation.credential_proofs(),
        )
        .unwrap();
    }

    #[rstest]
    #[case(_presentation_request_with_missing_attribute())]
    #[case(_presentation_request_with_missing_predicate())]
    #[case(_presentation_request_with_missing_attribute_group())]
    #[case(_presentation_request_with_invalid_predicate_restrictions())]
    #[case(_presentation_request_with_invalid_attribute_restrictions())]
    #[case(_presentation_request_with_different_predicate())]
    #[case(_presentation_request_with_invalid_non_revoke_interval())]
    fn test_check_request_data_works_for_negative_cases(
        schemas: HashMap<SchemaId, Schema>,
        cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition>,
        presentation: W3CPresentation,
        #[case] presentation_request: PresentationRequestPayload,
    ) {
        let err = check_request_data(
            &presentation_request,
            &presentation,
            &schemas,
            &cred_defs,
            None,
            &presentation.credential_proofs(),
        )
        .unwrap_err();
        assert_eq!(ErrorKind::Input, err.kind());
    }

    #[rstest]
    fn test_check_request_data_works_for_unrevealed_attributes(
        schemas: HashMap<SchemaId, Schema>,
        cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition>,
        mut presentation: W3CPresentation,
    ) {
        // empty credential_subject means there is no revealed attributes - only unrevealed
        presentation.verifiable_credential[0].credential_subject = CredentialSubject::default();

        check_request_data(
            &_presentation_request_with_single_attribute(),
            &presentation,
            &schemas,
            &cred_defs,
            None,
            &presentation.credential_proofs(),
        )
        .unwrap();
    }

    #[rstest]
    fn test_check_request_data_fails_for_presentation_with_empty_credential_list(
        schemas: HashMap<SchemaId, Schema>,
        cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition>,
        mut presentation: W3CPresentation,
    ) {
        presentation.verifiable_credential = Vec::default();

        let err = check_request_data(
            &_presentation_request_with_single_attribute(),
            &presentation,
            &schemas,
            &cred_defs,
            None,
            &presentation.credential_proofs(),
        )
        .unwrap_err();
        assert_eq!(ErrorKind::Input, err.kind());
    }

    #[rstest]
    fn test_check_request_data_fails_for_empty_schema(
        cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition>,
        presentation: W3CPresentation,
    ) {
        let schemas = HashMap::new();

        let err = check_request_data(
            &_presentation_request_with_attribute_restrictions(),
            &presentation,
            &schemas,
            &cred_defs,
            None,
            &presentation.credential_proofs(),
        )
        .unwrap_err();
        assert_eq!(ErrorKind::Input, err.kind());
    }

    #[rstest]
    fn test_check_request_data_fails_for_empty_cred_defs(
        schemas: HashMap<SchemaId, Schema>,
        presentation: W3CPresentation,
    ) {
        let cred_defs = HashMap::new();

        let err = check_request_data(
            &_presentation_request_with_attribute_restrictions(),
            &presentation,
            &schemas,
            &cred_defs,
            None,
            &presentation.credential_proofs(),
        )
        .unwrap_err();
        assert_eq!(ErrorKind::Input, err.kind());
    }

    #[rstest]
    #[case(_presentation_request_with_non_revoke_interval())]
    fn test_check_request_data_works_for_valid_non_revoke_interval_override(
        schemas: HashMap<SchemaId, Schema>,
        cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition>,
        presentation: W3CPresentation,
        #[case] presentation_request: PresentationRequestPayload,
    ) {
        let interval_override =
            _non_revoke_override_interval(PROOF_TIMESTAMP_FROM, PROOF_TIMESTAMP_FROM + 1);

        check_request_data(
            &presentation_request,
            &presentation,
            &schemas,
            &cred_defs,
            Some(&interval_override),
            &presentation.credential_proofs(),
        )
        .unwrap();
    }

    #[rstest]
    #[case(_presentation_request_with_non_revoke_interval())]
    fn test_check_request_data_fails_for_invalid_non_revoke_interval_override(
        schemas: HashMap<SchemaId, Schema>,
        cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition>,
        presentation: W3CPresentation,
        #[case] presentation_request: PresentationRequestPayload,
    ) {
        let interval_override =
            _non_revoke_override_interval(PROOF_TIMESTAMP_FROM, PROOF_TIMESTAMP + 1);

        let err = check_request_data(
            &presentation_request,
            &presentation,
            &schemas,
            &cred_defs,
            Some(&interval_override),
            &presentation.credential_proofs(),
        )
        .unwrap_err();
        assert_eq!(ErrorKind::Input, err.kind());
    }

    #[rstest]
    #[case(_presentation_request_with_single_attribute())]
    fn test_check_cred_def_id_mismatch_fails(
        schemas: HashMap<SchemaId, Schema>,
        cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition>,
        presentation: W3CPresentation,
        #[case] presentation_request: PresentationRequestPayload,
    ) {
        let mut cred_proofs = presentation.credential_proofs();
        cred_proofs[0].cred_def_id = "other:id".try_into().unwrap();

        let err = check_request_data(
            &presentation_request,
            &presentation,
            &schemas,
            &cred_defs,
            None,
            &cred_proofs,
        )
        .unwrap_err();
        assert_eq!(ErrorKind::Input, err.kind());
    }

    #[rstest]
    #[case(_presentation_request_with_single_attribute())]
    fn test_check_issuer_id_mismatch_fails(
        schemas: HashMap<SchemaId, Schema>,
        mut cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition>,
        presentation: W3CPresentation,
        #[case] presentation_request: PresentationRequestPayload,
    ) {
        let cred_def = cred_defs.iter_mut().next().unwrap().1;
        cred_def.issuer_id = "other:id".try_into().unwrap();

        let err = check_request_data(
            &presentation_request,
            &presentation,
            &schemas,
            &cred_defs,
            None,
            &presentation.credential_proofs(),
        )
        .unwrap_err();
        assert_eq!(ErrorKind::Input, err.kind());
    }
}
