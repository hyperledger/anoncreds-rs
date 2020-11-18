use std::collections::hash_map::Entry;
use std::collections::HashMap;

use super::types::*;
use crate::error::Result;
use crate::services::helpers::*;
use crate::ursa::cl::{
    issuer::Issuer as CryptoIssuer, prover::Prover as CryptoProver,
    verifier::Verifier as CryptoVerifier, CredentialPublicKey,
    RevocationRegistry as CryptoRevocationRegistry, SubProofRequest, Witness,
};
use indy_data_types::anoncreds::{
    credential::AttributeValues,
    pres_request::{PresentationRequestPayload, RequestedAttributeInfo, RequestedPredicateInfo},
    presentation::{
        AttributeValue, Identifier, RequestedProof, RevealedAttributeGroupInfo,
        RevealedAttributeInfo, SubProofReferent,
    },
};
use indy_utils::Qualifiable;

use super::tails::TailsReader;

pub fn new_master_secret() -> Result<MasterSecret> {
    MasterSecret::new().map_err(err_map!(Unexpected))
}

pub fn new_credential_request(
    prover_did: &DidValue,
    cred_def: &CredentialDefinition,
    master_secret: &MasterSecret,
    master_secret_id: &str,
    credential_offer: &CredentialOffer,
) -> Result<(CredentialRequest, CredentialRequestMetadata)> {
    trace!(
        "new_credential_request >>> cred_def: {:?}, master_secret: {:?}, credential_offer: {:?}",
        cred_def,
        secret!(&master_secret),
        credential_offer
    );

    let cred_def = match cred_def {
        CredentialDefinition::CredentialDefinitionV1(cd) => cd,
    };
    let credential_pub_key = CredentialPublicKey::build_from_parts(
        &cred_def.value.primary,
        cred_def.value.revocation.as_ref(),
    )?;
    let mut credential_values_builder = CryptoIssuer::new_credential_values_builder()?;
    credential_values_builder.add_value_hidden("master_secret", &master_secret.value.value()?)?;
    let cred_values = credential_values_builder.finalize()?;

    let nonce = new_nonce()?;
    let nonce_copy = nonce.try_clone().map_err(err_map!(Unexpected))?;

    let (blinded_ms, master_secret_blinding_data, blinded_ms_correctness_proof) =
        CryptoProver::blind_credential_secrets(
            &credential_pub_key,
            &credential_offer.key_correctness_proof,
            &cred_values,
            credential_offer.nonce.as_native(),
        )?;

    let credential_request = CredentialRequest {
        prover_did: prover_did.clone(),
        cred_def_id: credential_offer.cred_def_id.clone(),
        blinded_ms,
        blinded_ms_correctness_proof,
        nonce,
    };

    let credential_request_metadata = CredentialRequestMetadata {
        master_secret_blinding_data,
        nonce: nonce_copy,
        master_secret_name: master_secret_id.to_string(),
    };

    trace!(
        "new_credential_request <<< credential_request: {:?}, credential_request_metadata: {:?}",
        credential_request,
        credential_request_metadata
    );

    Ok((credential_request, credential_request_metadata))
}

pub fn process_credential(
    credential: &mut Credential,
    cred_request_metadata: &CredentialRequestMetadata,
    master_secret: &MasterSecret,
    cred_def: &CredentialDefinition,
    rev_reg_def: Option<&RevocationRegistryDefinition>,
) -> Result<()> {
    trace!("process_credential >>> credential: {:?}, cred_request_metadata: {:?}, master_secret: {:?}, cred_def: {:?}, rev_reg_def: {:?}",
            credential, cred_request_metadata, secret!(&master_secret), cred_def, rev_reg_def);

    let cred_def = match cred_def {
        CredentialDefinition::CredentialDefinitionV1(cd) => cd,
    };
    let credential_pub_key = CredentialPublicKey::build_from_parts(
        &cred_def.value.primary,
        cred_def.value.revocation.as_ref(),
    )?;
    let credential_values =
        build_credential_values(&credential.values.0, Some(&master_secret.value))?;
    let rev_pub_key = match rev_reg_def {
        Some(RevocationRegistryDefinition::RevocationRegistryDefinitionV1(def)) => {
            Some(&def.value.public_keys.accum_key)
        }
        _ => None,
    };

    CryptoProver::process_credential_signature(
        &mut credential.signature,
        &credential_values,
        &credential.signature_correctness_proof,
        &cred_request_metadata.master_secret_blinding_data,
        &credential_pub_key,
        cred_request_metadata.nonce.as_native(),
        rev_pub_key,
        credential.rev_reg.as_ref(),
        credential.witness.as_ref(),
    )?;

    trace!("process_credential <<< ");

    Ok(())
}

pub fn create_proof(
    proof_req: &PresentationRequest,
    credentials: &HashMap<String, &Credential>,
    requested_credentials: &RequestedCredentials,
    master_secret: &MasterSecret,
    schemas: &HashMap<SchemaId, &Schema>,
    cred_defs: &HashMap<CredentialDefinitionId, &CredentialDefinition>,
    rev_states: &HashMap<String, Vec<&RevocationState>>,
) -> Result<Presentation> {
    trace!("create_proof >>> credentials: {:?}, proof_req: {:?}, requested_credentials: {:?}, master_secret: {:?}, schemas: {:?}, cred_defs: {:?}, rev_states: {:?}",
            credentials, proof_req, requested_credentials, secret!(&master_secret), schemas, cred_defs, rev_states);

    let proof_req_val = proof_req.value();
    let mut proof_builder = CryptoProver::new_proof_builder()?;
    proof_builder.add_common_attribute("master_secret")?;

    let mut requested_proof = RequestedProof::default();

    requested_proof.self_attested_attrs = requested_credentials.self_attested_attributes.clone();

    let credentials_for_proving =
        prepare_credentials_for_proving(requested_credentials, proof_req_val)?;
    let mut sub_proof_index = 0;
    let non_credential_schema = build_non_credential_schema()?;

    let mut identifiers: Vec<Identifier> = Vec::with_capacity(credentials_for_proving.len());
    for (cred_key, (req_attrs_for_cred, req_predicates_for_cred)) in credentials_for_proving {
        let credential = credentials.get(cred_key.cred_id.as_str()).ok_or_else(|| {
            err_msg!(
                "Credential not provided for ID: {}",
                cred_key.cred_id.as_str()
            )
        })?;

        let schema = schemas.get(&credential.schema_id).ok_or_else(|| {
            error!("schemas {:?}", schemas);
            err_msg!("Schema not provided for ID: {}", credential.schema_id)
        })?;
        let schema = match schema {
            Schema::SchemaV1(schema) => schema,
        };

        let cred_def = cred_defs.get(&credential.cred_def_id).ok_or_else(|| {
            err_msg!(
                "Credential Definition not provided for ID: {}",
                credential.cred_def_id
            )
        })?;
        let cred_def = match cred_def {
            CredentialDefinition::CredentialDefinitionV1(cd) => cd,
        };

        let rev_state = if let Some(timestamp) = cred_key.timestamp {
            let rev_reg_id = credential
                .rev_reg_id
                .clone()
                .ok_or_else(|| err_msg!("Revocation Registry Id not found"))?;

            let cred_rev_states = rev_states
                .get(&rev_reg_id.0)
                .or(rev_states.get(cred_key.cred_id.as_str()))
                .ok_or_else(|| err_msg!("Revocation State not provided for ID: {}", rev_reg_id))?;

            Some(
                cred_rev_states
                    .iter()
                    .find(|state| state.timestamp == timestamp)
                    .ok_or_else(|| {
                        err_msg!("Revocation Info not provided for timestamp: {}", timestamp)
                    })?,
            )
        } else {
            None
        };

        let credential_pub_key = CredentialPublicKey::build_from_parts(
            &cred_def.value.primary,
            cred_def.value.revocation.as_ref(),
        )?;

        let credential_schema = build_credential_schema(&schema.attr_names.0)?;
        let credential_values =
            build_credential_values(&credential.values.0, Some(&master_secret.value))?;
        let sub_proof_request =
            build_sub_proof_request(&req_attrs_for_cred, &req_predicates_for_cred)?;

        proof_builder.add_sub_proof_request(
            &sub_proof_request,
            &credential_schema,
            &non_credential_schema,
            &credential.signature,
            &credential_values,
            &credential_pub_key,
            rev_state.as_ref().map(|r_info| &r_info.rev_reg),
            rev_state.as_ref().map(|r_info| &r_info.witness),
        )?;

        let identifier = match proof_req {
            PresentationRequest::PresentationRequestV1(_) => Identifier {
                schema_id: credential.schema_id.to_unqualified(),
                cred_def_id: credential.cred_def_id.to_unqualified(),
                rev_reg_id: credential.rev_reg_id.as_ref().map(|id| id.to_unqualified()),
                timestamp: cred_key.timestamp,
            },
            PresentationRequest::PresentationRequestV2(_) => Identifier {
                schema_id: credential.schema_id.clone(),
                cred_def_id: credential.cred_def_id.clone(),
                rev_reg_id: credential.rev_reg_id.clone(),
                timestamp: cred_key.timestamp,
            },
        };

        identifiers.push(identifier);

        update_requested_proof(
            req_attrs_for_cred,
            req_predicates_for_cred,
            proof_req_val,
            credential,
            sub_proof_index,
            &mut requested_proof,
        )?;

        sub_proof_index += 1;
    }

    let proof = proof_builder.finalize(proof_req_val.nonce.as_native())?;

    let full_proof = Presentation {
        proof,
        requested_proof,
        identifiers,
    };

    trace!("create_proof <<< full_proof: {:?}", secret!(&full_proof));

    Ok(full_proof)
}

pub fn create_or_update_revocation_state(
    tails_reader: TailsReader,
    revoc_reg_def: &RevocationRegistryDefinition,
    rev_reg_delta: &RevocationRegistryDelta,
    rev_reg_idx: u32,
    timestamp: u64,
    rev_state: Option<RevocationState>,
) -> Result<RevocationState> {
    trace!(
        "create_or_update_revocation_state >>> , tails_reader: {:?}, revoc_reg_def: {:?}, \
rev_reg_delta: {:?}, rev_reg_idx: {}, timestamp: {:?}, rev_state: {:?}",
        tails_reader,
        revoc_reg_def,
        rev_reg_delta,
        rev_reg_idx,
        timestamp,
        rev_state
    );

    let revoc_reg_def = match revoc_reg_def {
        RevocationRegistryDefinition::RevocationRegistryDefinitionV1(v1) => v1,
    };
    let rev_reg_delta = match rev_reg_delta {
        RevocationRegistryDelta::RevocationRegistryDeltaV1(v1) => v1,
    };

    let rev_state = match rev_state {
        None => {
            let witness = Witness::new(
                rev_reg_idx,
                revoc_reg_def.value.max_cred_num,
                revoc_reg_def.value.issuance_type.to_bool(),
                &rev_reg_delta.value,
                &tails_reader,
            )?;

            RevocationState {
                witness,
                rev_reg: CryptoRevocationRegistry::from(rev_reg_delta.value.clone()),
                timestamp,
            }
        }
        Some(mut rev_state) => {
            rev_state.witness.update(
                rev_reg_idx,
                revoc_reg_def.value.max_cred_num,
                &rev_reg_delta.value,
                &tails_reader,
            )?;
            rev_state.rev_reg = CryptoRevocationRegistry::from(rev_reg_delta.value.clone());
            rev_state.timestamp = timestamp;
            rev_state
        }
    };

    Ok(rev_state)
}

fn prepare_credentials_for_proving(
    requested_credentials: &RequestedCredentials,
    proof_req: &PresentationRequestPayload,
) -> Result<HashMap<ProvingCredentialKey, (Vec<RequestedAttributeInfo>, Vec<RequestedPredicateInfo>)>>
{
    trace!(
        "_prepare_credentials_for_proving >>> requested_credentials: {:?}, proof_req: {:?}",
        requested_credentials,
        proof_req
    );

    let mut credentials_for_proving: HashMap<
        ProvingCredentialKey,
        (Vec<RequestedAttributeInfo>, Vec<RequestedPredicateInfo>),
    > = HashMap::new();

    for (attr_referent, requested_attr) in requested_credentials.requested_attributes.iter() {
        let attr_info = proof_req
            .requested_attributes
            .get(attr_referent.as_str())
            .ok_or_else(|| {
                err_msg!(
                    "AttributeInfo not found in PresentationRequest for referent \"{}\"",
                    attr_referent.as_str()
                )
            })?;

        let req_attr_info = RequestedAttributeInfo {
            attr_referent: attr_referent.clone(),
            attr_info: attr_info.clone(),
            revealed: requested_attr.revealed,
        };

        match credentials_for_proving.entry(ProvingCredentialKey {
            cred_id: requested_attr.cred_id.clone(),
            timestamp: requested_attr.timestamp,
        }) {
            Entry::Occupied(cred_for_proving) => {
                let &mut (ref mut attributes_for_credential, _) = cred_for_proving.into_mut();
                attributes_for_credential.push(req_attr_info);
            }
            Entry::Vacant(attributes_for_credential) => {
                attributes_for_credential.insert((vec![req_attr_info], Vec::new()));
            }
        };
    }

    for (predicate_referent, proving_cred_key) in requested_credentials.requested_predicates.iter()
    {
        let predicate_info = proof_req
            .requested_predicates
            .get(predicate_referent.as_str())
            .ok_or_else(|| {
                err_msg!(
                    "PredicateInfo not found in PresentationRequest for referent \"{}\"",
                    predicate_referent.as_str()
                )
            })?;

        let req_predicate_info = RequestedPredicateInfo {
            predicate_referent: predicate_referent.clone(),
            predicate_info: predicate_info.clone(),
        };

        match credentials_for_proving.entry(proving_cred_key.clone()) {
            Entry::Occupied(cred_for_proving) => {
                let &mut (_, ref mut predicates_for_credential) = cred_for_proving.into_mut();
                predicates_for_credential.push(req_predicate_info);
            }
            Entry::Vacant(v) => {
                v.insert((Vec::new(), vec![req_predicate_info]));
            }
        };
    }

    trace!(
        "_prepare_credentials_for_proving <<< credentials_for_proving: {:?}",
        credentials_for_proving
    );

    Ok(credentials_for_proving)
}

fn get_credential_values_for_attribute(
    credential_attrs: &HashMap<String, AttributeValues>,
    requested_attr: &str,
) -> Option<AttributeValues> {
    trace!(
        "get_credential_values_for_attribute >>> credential_attrs: {:?}, requested_attr: {:?}",
        secret!(credential_attrs),
        requested_attr
    );

    let res = credential_attrs
        .iter()
        .find(|&(ref key, _)| attr_common_view(key) == attr_common_view(&requested_attr))
        .map(|(_, values)| values.clone());

    trace!(
        "get_credential_values_for_attribute <<< res: {:?}",
        secret!(&res)
    );

    res
}

fn update_requested_proof(
    req_attrs_for_credential: Vec<RequestedAttributeInfo>,
    req_predicates_for_credential: Vec<RequestedPredicateInfo>,
    proof_req: &PresentationRequestPayload,
    credential: &Credential,
    sub_proof_index: u32,
    requested_proof: &mut RequestedProof,
) -> Result<()> {
    trace!("_update_requested_proof >>> req_attrs_for_credential: {:?}, req_predicates_for_credential: {:?}, proof_req: {:?}, credential: {:?}, \
           sub_proof_index: {:?}, requested_proof: {:?}",
           req_attrs_for_credential, req_predicates_for_credential, proof_req, secret!(&credential), sub_proof_index, secret!(&requested_proof));

    for attr_info in req_attrs_for_credential {
        if attr_info.revealed {
            let attribute = &proof_req.requested_attributes[&attr_info.attr_referent];

            if let Some(name) = &attribute.name {
                let attribute_values =
                    get_credential_values_for_attribute(&credential.values.0, &name).ok_or_else(
                        || err_msg!("Credential value not found for attribute {:?}", name),
                    )?;

                requested_proof.revealed_attrs.insert(
                    attr_info.attr_referent.clone(),
                    RevealedAttributeInfo {
                        sub_proof_index,
                        raw: attribute_values.raw,
                        encoded: attribute_values.encoded,
                    },
                );
            } else if let Some(names) = &attribute.names {
                let mut value_map: HashMap<String, AttributeValue> = HashMap::new();
                for name in names {
                    let attr_value =
                        get_credential_values_for_attribute(&credential.values.0, &name)
                            .ok_or_else(|| {
                                err_msg!("Credential value not found for attribute {:?}", name)
                            })?;
                    value_map.insert(
                        name.clone(),
                        AttributeValue {
                            raw: attr_value.raw,
                            encoded: attr_value.encoded,
                        },
                    );
                }
                requested_proof.revealed_attr_groups.insert(
                    attr_info.attr_referent.clone(),
                    RevealedAttributeGroupInfo {
                        sub_proof_index,
                        values: value_map,
                    },
                );
            }
        } else {
            requested_proof.unrevealed_attrs.insert(
                attr_info.attr_referent,
                SubProofReferent { sub_proof_index },
            );
        }
    }

    for predicate_info in req_predicates_for_credential {
        requested_proof.predicates.insert(
            predicate_info.predicate_referent,
            SubProofReferent { sub_proof_index },
        );
    }

    trace!("_update_requested_proof <<<");

    Ok(())
}

fn build_sub_proof_request(
    req_attrs_for_credential: &[RequestedAttributeInfo],
    req_predicates_for_credential: &[RequestedPredicateInfo],
) -> Result<SubProofRequest> {
    trace!("_build_sub_proof_request <<< req_attrs_for_credential: {:?}, req_predicates_for_credential: {:?}",
           req_attrs_for_credential, req_predicates_for_credential);

    let mut sub_proof_request_builder = CryptoVerifier::new_sub_proof_request_builder()?;

    for attr in req_attrs_for_credential {
        if attr.revealed {
            if let Some(ref name) = &attr.attr_info.name {
                sub_proof_request_builder.add_revealed_attr(&attr_common_view(name))?
            } else if let Some(ref names) = &attr.attr_info.names {
                for name in names {
                    sub_proof_request_builder.add_revealed_attr(&attr_common_view(name))?
                }
            }
        }
    }

    for predicate in req_predicates_for_credential {
        let p_type = format!("{}", predicate.predicate_info.p_type);

        sub_proof_request_builder.add_predicate(
            &attr_common_view(&predicate.predicate_info.name),
            &p_type,
            predicate.predicate_info.p_value,
        )?;
    }

    let sub_proof_request = sub_proof_request_builder.finalize()?;

    trace!(
        "_build_sub_proof_request <<< sub_proof_request: {:?}",
        sub_proof_request
    );

    Ok(sub_proof_request)
}

#[cfg(test)]
mod tests {
    use super::*;

    use indy_data_types::anoncreds::pres_request::PredicateTypes;

    macro_rules! hashmap {
        ($( $key: expr => $val: expr ),*) => {
            {
                let mut map = ::std::collections::HashMap::new();
                $(
                    map.insert($key, $val);
                )*
                map
            }
        }
    }

    mod prepare_credentials_for_proving {
        use indy_data_types::anoncreds::pres_request::{AttributeInfo, PredicateInfo};

        use super::*;

        const CRED_ID: &str = "8591bcac-ee7d-4bef-ba7e-984696440b30";
        const ATTRIBUTE_REFERENT: &str = "attribute_referent";
        const PREDICATE_REFERENT: &str = "predicate_referent";

        fn _attr_info() -> AttributeInfo {
            AttributeInfo {
                name: Some("name".to_string()),
                names: None,
                restrictions: None,
                non_revoked: None,
            }
        }

        fn _predicate_info() -> PredicateInfo {
            PredicateInfo {
                name: "age".to_string(),
                p_type: PredicateTypes::GE,
                p_value: 8,
                restrictions: None,
                non_revoked: None,
            }
        }

        fn _proof_req() -> PresentationRequestPayload {
            PresentationRequestPayload {
                nonce: new_nonce().unwrap(),
                name: "Job-Application".to_string(),
                version: "0.1".to_string(),
                requested_attributes: hashmap!(
                    ATTRIBUTE_REFERENT.to_string() => _attr_info()
                ),
                requested_predicates: hashmap!(
                    PREDICATE_REFERENT.to_string() => _predicate_info()
                ),
                non_revoked: None,
            }
        }

        fn _req_cred() -> RequestedCredentials {
            RequestedCredentials {
                self_attested_attributes: HashMap::new(),
                requested_attributes: hashmap!(
                    ATTRIBUTE_REFERENT.to_string() => RequestedAttribute{
                        cred_id: CRED_ID.to_string(),
                        timestamp: None,
                        revealed: false,
                    }
                ),
                requested_predicates: hashmap!(
                    PREDICATE_REFERENT.to_string() => ProvingCredentialKey{ cred_id: CRED_ID.to_string(), timestamp: None }
                ),
            }
        }

        #[test]
        fn prepare_credentials_for_proving_works() {
            let req_cred = _req_cred();
            let proof_req = _proof_req();

            let res = prepare_credentials_for_proving(&req_cred, &proof_req).unwrap();

            assert_eq!(1, res.len());
            assert!(res.contains_key(&ProvingCredentialKey {
                cred_id: CRED_ID.to_string(),
                timestamp: None
            }));

            let (req_attr_info, req_pred_info) = res
                .get(&ProvingCredentialKey {
                    cred_id: CRED_ID.to_string(),
                    timestamp: None,
                })
                .unwrap();
            assert_eq!(1, req_attr_info.len());
            assert_eq!(1, req_pred_info.len());
        }

        #[test]
        fn prepare_credentials_for_proving_works_for_multiple_attributes_with_same_credential() {
            let mut req_cred = _req_cred();
            let mut proof_req = _proof_req();

            req_cred.requested_attributes.insert(
                "attribute_referent_2".to_string(),
                RequestedAttribute {
                    cred_id: CRED_ID.to_string(),
                    timestamp: None,
                    revealed: false,
                },
            );

            proof_req.requested_attributes.insert(
                "attribute_referent_2".to_string(),
                AttributeInfo {
                    name: Some("last_name".to_string()),
                    names: None,
                    restrictions: None,
                    non_revoked: None,
                },
            );

            let res = prepare_credentials_for_proving(&req_cred, &proof_req).unwrap();

            assert_eq!(1, res.len());
            assert!(res.contains_key(&ProvingCredentialKey {
                cred_id: CRED_ID.to_string(),
                timestamp: None
            }));

            let (req_attr_info, req_pred_info) = res
                .get(&ProvingCredentialKey {
                    cred_id: CRED_ID.to_string(),
                    timestamp: None,
                })
                .unwrap();
            assert_eq!(2, req_attr_info.len());
            assert_eq!(1, req_pred_info.len());
        }

        #[test]
        fn prepare_credentials_for_proving_works_for_missed_attribute() {
            let req_cred = _req_cred();
            let mut proof_req = _proof_req();

            proof_req.requested_attributes.clear();

            let res = prepare_credentials_for_proving(&req_cred, &proof_req);
            assert_kind!(Input, res);
        }

        #[test]
        fn prepare_credentials_for_proving_works_for_missed_predicate() {
            let req_cred = _req_cred();
            let mut proof_req = _proof_req();

            proof_req.requested_predicates.clear();

            let res = prepare_credentials_for_proving(&req_cred, &proof_req);
            assert_kind!(Input, res);
        }
    }

    mod get_credential_values_for_attribute {
        use super::*;

        fn _attr_values() -> AttributeValues {
            AttributeValues {
                raw: "Alex".to_string(),
                encoded: "123".to_string(),
            }
        }

        fn _cred_values() -> HashMap<String, AttributeValues> {
            hashmap!("name".to_string() => _attr_values())
        }

        #[test]
        fn get_credential_values_for_attribute_works() {
            let res = get_credential_values_for_attribute(&_cred_values(), "name").unwrap();
            assert_eq!(_attr_values(), res);
        }

        #[test]
        fn get_credential_values_for_attribute_works_for_requested_attr_different_case() {
            let res = get_credential_values_for_attribute(&_cred_values(), "NAme").unwrap();
            assert_eq!(_attr_values(), res);
        }

        #[test]
        fn get_credential_values_for_attribute_works_for_requested_attr_contains_spaces() {
            let res = get_credential_values_for_attribute(&_cred_values(), "   na me  ").unwrap();
            assert_eq!(_attr_values(), res);
        }

        #[test]
        fn get_credential_values_for_attribute_works_for_cred_values_different_case() {
            let cred_values = hashmap!("NAME".to_string() => _attr_values());

            let res = get_credential_values_for_attribute(&cred_values, "name").unwrap();
            assert_eq!(_attr_values(), res);
        }

        #[test]
        fn get_credential_values_for_attribute_works_for_cred_values_contains_spaces() {
            let cred_values = hashmap!("    name    ".to_string() => _attr_values());

            let res = get_credential_values_for_attribute(&cred_values, "name").unwrap();
            assert_eq!(_attr_values(), res);
        }

        #[test]
        fn get_credential_values_for_attribute_works_for_cred_values_and_requested_attr_contains_spaces(
        ) {
            let cred_values = hashmap!("    name    ".to_string() => _attr_values());

            let res =
                get_credential_values_for_attribute(&cred_values, "            name            ")
                    .unwrap();
            assert_eq!(_attr_values(), res);
        }
    }
}
