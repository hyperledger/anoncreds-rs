use crate::data_types::cred_def::CredentialDefinition;
use crate::data_types::cred_def::CredentialDefinitionId;
use crate::data_types::pres_request::PredicateInfo;
use crate::data_types::pres_request::{AttributeInfo, PresentationRequestPayload};
use crate::data_types::presentation::Identifier;
use crate::data_types::rev_reg_def::RevocationRegistryDefinitionId;
use crate::data_types::schema::Schema;
use crate::data_types::schema::SchemaId;
use crate::data_types::w3c::credential::W3CCredential;
use crate::data_types::w3c::credential_attributes::CredentialAttributeValue;
use crate::data_types::w3c::presentation::W3CPresentation;
use crate::data_types::w3c::proof::CredentialPresentationProofValue;
use crate::error::Result;
use crate::services::helpers::encode_credential_attribute;
use crate::types::{PresentationRequest, RevocationRegistryDefinition, RevocationStatusList};
use crate::utils::query::Query;
use crate::verifier::{gather_filter_info, process_operator};
use crate::verifier::{verify_revealed_attribute_value, CLProofVerifier};
use anoncreds_clsignatures::{Proof, SubProof};
use std::collections::{HashMap, HashSet};

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
        .map(W3CCredential::get_credential_presentation_proof)
        .collect::<Result<Vec<CredentialPresentationProofValue>>>()?;

    // These values are from the prover and cannot be trusted
    // Check that all requested attributes and predicates included into the presentation
    // Also check that all requested credential restriction are valid
    check_request_data(
        presentation_request,
        presentation,
        &credential_proofs,
        schemas,
        cred_defs,
    )?;

    let presentation_proof = presentation.get_presentation_proof()?;

    let mut proof_verifier = CLProofVerifier::new(
        presentation_request,
        schemas,
        cred_defs,
        rev_reg_defs,
        rev_status_lists.as_ref(),
    )?;

    let mut sub_proofs: Vec<SubProof> =
        Vec::with_capacity(presentation.verifiable_credential.len());

    for credential_proof in credential_proofs {
        let mut revealed_attribute: HashSet<String> =
            credential_proof.mapping.revealed_attributes.clone();
        revealed_attribute.extend(credential_proof.mapping.revealed_attribute_groups.clone());

        proof_verifier.add_sub_proof(
            &revealed_attribute,
            &credential_proof.mapping.predicates,
            &credential_proof.schema_id,
            &credential_proof.cred_def_id,
            credential_proof.rev_reg_id.as_ref(),
            nonrevoke_interval_override,
            credential_proof.timestamp,
        )?;

        sub_proofs.push(credential_proof.sub_proof);
    }

    let cl_proof = Proof {
        proofs: sub_proofs,
        aggregated_proof: presentation_proof.aggregated,
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

#[allow(clippy::too_many_arguments)]
fn check_requested_attribute<'a>(
    presentation: &'a W3CPresentation,
    credential_proofs: &[CredentialPresentationProofValue],
    referent: &str,
    attribute: &AttributeInfo,
    schemas: &HashMap<SchemaId, Schema>,
    cred_defs: &HashMap<CredentialDefinitionId, CredentialDefinition>,
) -> Result<&'a W3CCredential> {
    let iter = presentation
        .verifiable_credential
        .iter()
        .zip(credential_proofs);

    for (credential, proof) in iter {
        if let Some(ref name) = attribute.name {
            if proof.mapping.revealed_attributes.contains(referent) {
                let (_, value) = credential.get_attribute(name)?;

                let encoded = encode_credential_attribute(&value)?;
                verify_revealed_attribute_value(name, &proof.sub_proof, &encoded)?;

                check_credential_restrictions(
                    credential,
                    attribute.restrictions.as_ref(),
                    schemas,
                    cred_defs,
                    proof,
                )?;

                return Ok(credential);
            }

            if proof.mapping.unrevealed_attributes.contains(referent) {
                check_credential_restrictions(
                    credential,
                    attribute.restrictions.as_ref(),
                    schemas,
                    cred_defs,
                    proof,
                )?;
                return Ok(credential);
            }
        }
        if let Some(ref names) = attribute.names {
            if proof.mapping.revealed_attribute_groups.contains(referent) {
                for name in names {
                    let (_, value) = credential.get_attribute(name)?;

                    let encoded = encode_credential_attribute(&value)?;
                    verify_revealed_attribute_value(name, &proof.sub_proof, &encoded)?;

                    check_credential_restrictions(
                        credential,
                        attribute.restrictions.as_ref(),
                        schemas,
                        cred_defs,
                        proof,
                    )?;
                }
                return Ok(credential);
            }
        }
    }

    Err(err_msg!(
        "Presentation does not contain attribute {}",
        referent
    ))
}

#[allow(clippy::too_many_arguments)]
fn check_requested_predicate<'a>(
    presentation: &'a W3CPresentation,
    credential_proofs: &[CredentialPresentationProofValue],
    referent: &str,
    predicate: &PredicateInfo,
    schemas: &HashMap<SchemaId, Schema>,
    cred_defs: &HashMap<CredentialDefinitionId, CredentialDefinition>,
) -> Result<&'a W3CCredential> {
    let iter = presentation
        .verifiable_credential
        .iter()
        .zip(credential_proofs);

    for (credential, proof) in iter {
        if proof.mapping.predicates.contains(referent) {
            let (predicate_name, _) = credential.get_predicate(&predicate.name)?;

            let matches_cl_proof_predicate = proof.sub_proof.predicates().into_iter().find(|p| {
                p.attr_name == predicate_name
                    && p.p_type == predicate.p_type.clone().into()
                    && p.value == predicate.p_value
            });

            if matches_cl_proof_predicate.is_none() {
                return Err(err_msg!(
                    "Predicate does not match to requested {}",
                    predicate.name
                ));
            }

            check_credential_restrictions(
                credential,
                predicate.restrictions.as_ref(),
                schemas,
                cred_defs,
                proof,
            )?;

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
    credential_proofs: &[CredentialPresentationProofValue],
    schemas: &HashMap<SchemaId, Schema>,
    cred_defs: &HashMap<CredentialDefinitionId, CredentialDefinition>,
) -> Result<()> {
    for (referent, attribute) in presentation_request.requested_attributes.iter() {
        check_requested_attribute(
            presentation,
            credential_proofs,
            referent,
            attribute,
            schemas,
            cred_defs,
        )?;
    }
    for (referent, predicate) in presentation_request.requested_predicates.iter() {
        check_requested_predicate(
            presentation,
            credential_proofs,
            referent,
            predicate,
            schemas,
            cred_defs,
        )?;
    }

    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::data_types::nonce::Nonce;
    use crate::data_types::pres_request::{AttributeInfo, NonRevokedInterval, PredicateTypes};
    use crate::data_types::w3c::credential_attributes::CredentialAttributes;
    use crate::data_types::w3c::proof::tests::{
        credential_pres_proof_value, presentation_proof_value,
    };
    use crate::data_types::w3c::proof::{CredentialAttributesMapping, DataIntegrityProof};
    use crate::w3c::credential_conversion::tests::{
        cred_def_id, credential_definition, issuer_id, schema, schema_id,
    };
    use crate::ErrorKind;
    use rstest::*;

    const PROOF_TIMESTAMP_FROM: u64 = 40;
    const PROOF_TIMESTAMP_TO: u64 = 50;

    fn credential_attributes() -> CredentialAttributes {
        CredentialAttributes(HashMap::from([
            (
                "name".to_string(),
                CredentialAttributeValue::Attribute("Alice".to_string()),
            ),
            (
                "height".to_string(),
                CredentialAttributeValue::Attribute("178".to_string()),
            ),
            ("age".to_string(), CredentialAttributeValue::Predicate(true)),
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
    fn _presentation_request_with_attribute_group() -> PresentationRequestPayload {
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
            requested_attributes: HashMap::from([(
                "attr1_referent".to_string(),
                AttributeInfo {
                    name: Some("NAME".to_string()),
                    .._attribute()
                },
            )]),
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
                    name: None,
                    names: Some(vec![
                        "name".to_string(),
                        "height".to_string(),
                        "missing".to_string(),
                    ]),
                    restrictions: None,
                    non_revoked: None,
                },
            )]),
            .._base_presentation_request()
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
    fn _presentation_request_with_unrevealed_attribute() -> PresentationRequestPayload {
        PresentationRequestPayload {
            requested_attributes: HashMap::from([("attr4_referent".to_string(), _attribute())]),
            .._base_presentation_request()
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

    fn presentation(mapping: CredentialAttributesMapping) -> W3CPresentation {
        let credential_pres_proof_value = CredentialPresentationProofValue {
            mapping,
            ..credential_pres_proof_value()
        };

        let proof =
            DataIntegrityProof::new_credential_presentation_proof(&credential_pres_proof_value)
                .unwrap();
        let credential = W3CCredential::new(issuer_id(), credential_attributes(), proof, None);

        let proof = DataIntegrityProof::new_presentation_proof(
            &presentation_proof_value(),
            "1".to_string(),
            cred_def_id().to_string(),
        )
        .unwrap();
        W3CPresentation::new(vec![credential], proof, None)
    }

    impl W3CPresentation {
        fn credential_proofs(&self) -> Vec<CredentialPresentationProofValue> {
            self.verifiable_credential
                .iter()
                .map(|verifiable_credential| {
                    verifiable_credential.get_credential_presentation_proof()
                })
                .collect::<Result<Vec<CredentialPresentationProofValue>>>()
                .unwrap()
        }
    }

    #[fixture]
    fn _mapping_empty() -> CredentialAttributesMapping {
        CredentialAttributesMapping {
            ..Default::default()
        }
    }

    #[fixture]
    fn _mapping_single_revealed_attribute() -> CredentialAttributesMapping {
        CredentialAttributesMapping {
            revealed_attributes: HashSet::from(["attr1_referent".to_string()]),
            ..Default::default()
        }
    }

    #[fixture]
    fn _mapping_multiple_revealed_attribute() -> CredentialAttributesMapping {
        CredentialAttributesMapping {
            revealed_attributes: HashSet::from([
                "attr1_referent".to_string(),
                "attr2_referent".to_string(),
            ]),
            ..Default::default()
        }
    }

    #[fixture]
    fn _mapping_single_revealed_attribute_group() -> CredentialAttributesMapping {
        CredentialAttributesMapping {
            revealed_attribute_groups: HashSet::from(["attr1_referent".to_string()]),
            ..Default::default()
        }
    }

    #[fixture]
    fn _mapping_single_unrevealed_attribute_group() -> CredentialAttributesMapping {
        CredentialAttributesMapping {
            unrevealed_attributes: HashSet::from(["attr1_referent".to_string()]),
            ..Default::default()
        }
    }

    #[fixture]
    fn _mapping_revealed_attribute_and_predicate() -> CredentialAttributesMapping {
        CredentialAttributesMapping {
            revealed_attributes: HashSet::from(["attr1_referent".to_string()]),
            predicates: HashSet::from(["predicate1_referent".to_string()]),
            ..Default::default()
        }
    }

    #[fixture]
    fn _mapping_predicate() -> CredentialAttributesMapping {
        CredentialAttributesMapping {
            predicates: HashSet::from(["predicate1_referent".to_string()]),
            ..Default::default()
        }
    }

    #[fixture]
    fn _mapping_revealed_attribute_and_group() -> CredentialAttributesMapping {
        CredentialAttributesMapping {
            revealed_attributes: HashSet::from(["attr1_referent".to_string()]),
            revealed_attribute_groups: HashSet::from(["attr2_referent".to_string()]),
            ..Default::default()
        }
    }

    #[rstest]
    #[case(
        _presentation_request_with_single_attribute(),
        _mapping_single_revealed_attribute()
    )]
    #[case(
        _presentation_request_with_attribute_and_predicate(),
        _mapping_revealed_attribute_and_predicate()
    )]
    #[case(
        _presentation_request_with_multiple_attributes(),
        _mapping_multiple_revealed_attribute()
    )]
    #[case(
        _presentation_request_with_attribute_group(),
        _mapping_single_revealed_attribute_group()
    )]
    #[case(_presentation_request_with_predicate(), _mapping_predicate())]
    #[case(
        _presentation_request_with_attribute_restrictions(),
        _mapping_single_revealed_attribute()
    )]
    #[case(
        _presentation_request_with_case_insensitive_attribute_and_predicate(),
        _mapping_revealed_attribute_and_predicate()
    )]
    #[case(
        _presentation_request_with_non_revoke_interval(),
        _mapping_single_revealed_attribute()
    )]
    #[case(
        _presentation_request_with_single_attribute(),
        _mapping_single_unrevealed_attribute_group()
    )]
    fn test_check_request_data_works_for_positive_cases(
        schemas: HashMap<SchemaId, Schema>,
        cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition>,
        #[case] presentation_request: PresentationRequestPayload,
        #[case] mapping: CredentialAttributesMapping,
    ) {
        let presentation_ = presentation(mapping);
        check_request_data(
            &presentation_request,
            &presentation_,
            &presentation_.credential_proofs(),
            &schemas,
            &cred_defs,
        )
        .unwrap();
    }

    #[rstest]
    #[case(
        _presentation_request_with_missing_attribute(),
        _mapping_single_revealed_attribute()
    )]
    #[rstest]
    #[case(_presentation_request_with_single_attribute(), _mapping_empty())]
    #[case(_presentation_request_with_missing_predicate(), _mapping_predicate())]
    #[case(_presentation_request_with_predicate(), _mapping_empty())]
    #[case(_presentation_request_with_unrevealed_attribute(), _mapping_empty())]
    #[case(
        _presentation_request_with_missing_attribute_group(),
        _mapping_single_revealed_attribute_group()
    )]
    #[case(_presentation_request_with_attribute_group(), _mapping_empty())]
    #[case(
        _presentation_request_with_invalid_predicate_restrictions(),
        _mapping_predicate()
    )]
    #[case(
        _presentation_request_with_invalid_attribute_restrictions(),
        _mapping_single_revealed_attribute()
    )]
    fn test_check_request_data_works_for_negative_cases(
        schemas: HashMap<SchemaId, Schema>,
        cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition>,
        #[case] presentation_request: PresentationRequestPayload,
        #[case] mapping: CredentialAttributesMapping,
    ) {
        let presentation_ = presentation(mapping);
        let err = check_request_data(
            &presentation_request,
            &presentation_,
            &presentation_.credential_proofs(),
            &schemas,
            &cred_defs,
        )
        .unwrap_err();
        assert_eq!(ErrorKind::Input, err.kind());
    }

    #[rstest]
    fn test_check_request_data_fails_for_presentation_with_empty_credential_list(
        schemas: HashMap<SchemaId, Schema>,
        cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition>,
    ) {
        let mut presentation_ = presentation(_mapping_single_revealed_attribute());
        presentation_.verifiable_credential = Vec::default();

        let err = check_request_data(
            &_presentation_request_with_single_attribute(),
            &presentation_,
            &presentation_.credential_proofs(),
            &schemas,
            &cred_defs,
        )
        .unwrap_err();
        assert_eq!(ErrorKind::Input, err.kind());
    }

    #[rstest]
    fn test_check_request_data_fails_for_empty_schema(
        cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition>,
    ) {
        let schemas = HashMap::new();
        let presentation_ = &presentation(_mapping_single_revealed_attribute());

        let err = check_request_data(
            &_presentation_request_with_attribute_restrictions(),
            &presentation_,
            &presentation_.credential_proofs(),
            &schemas,
            &cred_defs,
        )
        .unwrap_err();
        assert_eq!(ErrorKind::Input, err.kind());
    }

    #[rstest]
    fn test_check_request_data_fails_for_empty_cred_defs(schemas: HashMap<SchemaId, Schema>) {
        let cred_defs = HashMap::new();
        let presentation_ = &presentation(_mapping_single_revealed_attribute());

        let err = check_request_data(
            &_presentation_request_with_attribute_restrictions(),
            &presentation_,
            &presentation_.credential_proofs(),
            &schemas,
            &cred_defs,
        )
        .unwrap_err();
        assert_eq!(ErrorKind::Input, err.kind());
    }
}
