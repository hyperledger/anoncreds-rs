use crate::data_types::cred_def::CredentialDefinition;
use crate::data_types::cred_def::CredentialDefinitionId;
use crate::data_types::pres_request::PresentationRequestPayload;
use crate::data_types::pres_request::{NonRevokedInterval, PredicateInfo};
use crate::data_types::presentation::Identifier;
use crate::data_types::rev_reg_def::RevocationRegistryDefinitionId;
use crate::data_types::schema::Schema;
use crate::data_types::schema::SchemaId;
use crate::data_types::w3c::credential::CredentialAttributeValue;
use crate::data_types::w3c::credential::W3CCredential;
use crate::data_types::w3c::presentation::W3CPresentation;
use crate::data_types::w3c::presentation_proof::{
    CredentialPresentationProof, CredentialPresentationProofValue,
};
use crate::error::Result;
use crate::services::helpers::{encode_credential_attribute, get_requested_non_revoked_interval};
use crate::types::{PresentationRequest, RevocationRegistryDefinition, RevocationStatusList};
use crate::utils::query::Query;
use crate::verifier::{gather_filter_info, process_operator};
use crate::verifier::{verify_revealed_attribute_value, CLProofVerifier};
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
    trace!("verify >>> verify_w3c_presentation: {:?}, pres_req: {:?}, schemas: {:?}, cred_defs: {:?}, rev_reg_defs: {:?} rev_status_lists: {:?}",
    presentation, pres_req, schemas, cred_defs, rev_reg_defs, rev_status_lists);

    let presentation_request = pres_req.value();

    // we need to decode proofs in advance as their data needed for restrictions check
    let credential_proofs = presentation
        .verifiable_credential
        .iter()
        .map(W3CCredential::get_presentation_proof)
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
        proofs: Vec::with_capacity(presentation.verifiable_credential.len()),
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

        let attributes = verifiable_credential.attributes();
        let predicates = verifiable_credential.predicates();
        let attribute_names: Vec<String> = attributes.keys().cloned().collect();

        verify_revealed_attribute_values(&attributes, &proof_data)?;

        proof_verifier.add_sub_proof(
            &attribute_names,
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
    if let Some(rev_reg_id) = credential.get_rev_reg_id() {
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
            return Ok(credential);
        }
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

        let valid_credential = schema.has_case_insensitive_attribute(attribute)
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
            return Ok(credential);
        }
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

fn verify_revealed_attribute_values(
    attributes: &HashMap<String, String>,
    credential_proof: &CredentialPresentationProofValue,
) -> Result<()> {
    attributes
        .iter()
        .map(|(name, value)| {
            encode_credential_attribute(value).and_then(|encoded| {
                verify_revealed_attribute_value(name, &credential_proof.sub_proof, &encoded)
            })
        })
        .collect::<Result<Vec<()>>>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_types::nonce::Nonce;
    use crate::data_types::pres_request::{AttributeInfo, PredicateTypes};
    use crate::data_types::w3c::credential::{CredentialAttributes, CredentialStatus};
    use crate::data_types::w3c::credential_proof::CredentialProof;
    use crate::data_types::w3c::presentation_proof::{PredicateAttribute, PresentationProofType};
    use crate::w3c::credential_conversion::tests::{
        cred_def_id, cred_schema, credential_definition, issuer_id, schema, schema_id,
    };
    use crate::ErrorKind;
    use rstest::*;

    const PROOF_TIMESTAMP_FROM: u64 = 40;
    const PROOF_TIMESTAMP_TO: u64 = 50;
    const PROOF_TIMESTAMP: u64 = 50;

    fn _credential_attributes() -> CredentialAttributes {
        CredentialAttributes(HashMap::from([
            (
                "name".to_string(),
                CredentialAttributeValue::Attribute("Alice".to_string()),
            ),
            (
                "height".to_string(),
                CredentialAttributeValue::Attribute("178".to_string()),
            ),
            (
                "age".to_string(),
                CredentialAttributeValue::Predicate(vec![PredicateAttribute {
                    type_: Default::default(),
                    predicate: _predicate().p_type,
                    value: _predicate().p_value,
                }]),
            ),
        ]))
    }

    fn _revocation_id() -> RevocationRegistryDefinitionId {
        RevocationRegistryDefinitionId::new_unchecked("mock:uri")
    }

    fn _non_revoke_override_interval(
        timestamp: u64,
        change: u64,
    ) -> HashMap<RevocationRegistryDefinitionId, HashMap<u64, u64>> {
        let non_revoke_override =
            HashMap::from([(_revocation_id(), HashMap::from([(timestamp, change)]))]);

        non_revoke_override
    }

    fn _credential() -> W3CCredential {
        let mut credential = W3CCredential::new();
        credential.set_issuer(issuer_id());
        credential.set_credential_schema(cred_schema());
        credential.set_attributes(_credential_attributes());
        credential.add_proof(CredentialProof::AnonCredsCredentialPresentationProof(
            CredentialPresentationProof {
                type_: PresentationProofType::AnonCredsPresentationProof2023,
                proof_value: "bla".to_string(),
                timestamp: Some(PROOF_TIMESTAMP),
            },
        ));
        credential.set_credential_status(CredentialStatus::new(_revocation_id()));
        credential
    }

    fn _w3_presentation() -> W3CPresentation {
        let credential = _credential();
        let mut presentation = W3CPresentation::new();
        presentation.add_verifiable_credential(credential);
        presentation
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
        fn credential_proofs(&self) -> Vec<&CredentialPresentationProof> {
            self.verifiable_credential
                .iter()
                .map(|verifiable_credential| verifiable_credential.get_presentation_proof())
                .collect::<Result<Vec<&CredentialPresentationProof>>>()
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
        presentation.verifiable_credential[0]
            .credential_subject
            .attributes = CredentialAttributes::default();

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
}
