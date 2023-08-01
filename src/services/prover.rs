use super::tails::TailsFileReader;
use super::types::{
    Credential, CredentialOffer, CredentialRequest, CredentialRequestMetadata, LinkSecret,
    Presentation, PresentationRequest, RevocationRegistryDefinition,
};
use crate::cl::{
    CredentialPublicKey, Issuer, Prover, RevocationRegistry, RevocationRegistryDelta,
    SubProofRequest, Verifier, Witness,
};
use crate::data_types::cred_def::{CredentialDefinition, CredentialDefinitionId};
use crate::data_types::credential::AttributeValues;
use crate::data_types::pres_request::{
    PresentationRequestPayload, RequestedAttributeInfo, RequestedPredicateInfo,
};
use crate::data_types::presentation::AttributeValue;
use crate::data_types::presentation::Identifier;
use crate::data_types::presentation::RequestedProof;
use crate::data_types::presentation::RevealedAttributeGroupInfo;
use crate::data_types::presentation::RevealedAttributeInfo;
use crate::data_types::presentation::SubProofReferent;
use crate::data_types::rev_status_list::RevocationStatusList;
use crate::data_types::schema::{Schema, SchemaId};
use crate::error::{Error, Result};
use crate::services::helpers::{
    attr_common_view, build_credential_schema, build_credential_values,
    build_non_credential_schema, get_predicates_for_credential,
    get_revealed_attributes_for_credential, new_nonce,
};
use crate::types::{CredentialRevocationState, PresentCredentials};
use crate::utils::validation::Validatable;
use bitvec::bitvec;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::ops::BitXor;

/// Create a new random link secret which is cryptographically strong and pseudo-random
///
/// # Example
///
/// ```rust
/// use anoncreds::prover;
///
/// let link_secret = prover::create_link_secret()
///     .expect("Unable to create link secret");
///
/// ```
pub fn create_link_secret() -> Result<LinkSecret> {
    LinkSecret::new().map_err(err_map!(Unexpected))
}

/// Create an Anoncreds credential request according to the [Anoncreds v1.0 specification -
/// Credential Request](https://hyperledger.github.io/anoncreds-spec/#credential-request)
///
/// This object can be send as a response to a [`crate::types::CredentialOffer`] received from an
/// isuer
///
/// # Example
///
/// ```rust
/// use anoncreds::issuer;
/// use anoncreds::prover;
///
/// use anoncreds::types::CredentialDefinitionConfig;
/// use anoncreds::types::SignatureType;
///
/// let attribute_names: &[&str] = &["name", "age"];
/// let schema = issuer::create_schema("schema name",
///                                    "1.0",
///                                    "did:web:xyz",
///                                    attribute_names.into()
///                                    ).expect("Unable to create schema");
///
/// let (cred_def, cred_def_priv, key_correctness_proof) =
///     issuer::create_credential_definition("did:web:xyz/resource/schema",
///                                          &schema,
///                                          "did:web:xyz",
///                                          "default-tag",
///                                          SignatureType::CL,
///                                          CredentialDefinitionConfig::default()
///                                          ).expect("Unable to create Credential Definition");
///
/// let credential_offer =
///     issuer::create_credential_offer("did:web:xyz/resource/schema",
///                                     "did:web:xyz/resource/cred-def",
///                                     &key_correctness_proof,
///                                     ).expect("Unable to create Credential Offer");
///
/// let link_secret =
///     prover::create_link_secret().expect("Unable to create link secret");
///
/// let (credential_request, credential_request_metadata) =
///     prover::create_credential_request(Some("entropy"),
///                                       None,
///                                       &cred_def,
///                                       &link_secret,
///                                       "my-secret-id",
///                                       &credential_offer,
///                                       ).expect("Unable to create credential request");
/// ```
pub fn create_credential_request(
    entropy: Option<&str>,
    prover_did: Option<&str>,
    cred_def: &CredentialDefinition,
    link_secret: &LinkSecret,
    link_secret_id: &str,
    credential_offer: &CredentialOffer,
) -> Result<(CredentialRequest, CredentialRequestMetadata)> {
    trace!(
        "create_credential_request >>> entropy {:?}, prover_did {:?}, cred_def: {:?}, link_secret: {:?}, credential_offer: {:?}",
        entropy,
        prover_did,
        cred_def,
        secret!(&link_secret),
        credential_offer
    );

    let credential_pub_key = CredentialPublicKey::build_from_parts(
        &cred_def.value.primary,
        cred_def.value.revocation.as_ref(),
    )?;

    let mut credential_values_builder = Issuer::new_credential_values_builder()?;
    credential_values_builder.add_value_hidden("master_secret", &link_secret.0)?;
    let cred_values = credential_values_builder.finalize()?;

    let nonce = new_nonce()?;
    let nonce_copy = nonce.try_clone().map_err(err_map!(Unexpected))?;

    let (blinded_ms, link_secret_blinding_data, blinded_ms_correctness_proof) =
        Prover::blind_credential_secrets(
            &credential_pub_key,
            &credential_offer.key_correctness_proof,
            &cred_values,
            credential_offer.nonce.as_native(),
        )?;

    let credential_request = CredentialRequest::new(
        entropy,
        prover_did,
        credential_offer.cred_def_id.clone(),
        blinded_ms,
        blinded_ms_correctness_proof,
        nonce,
    )?;

    let credential_request_metadata = CredentialRequestMetadata {
        link_secret_blinding_data,
        nonce: nonce_copy,
        link_secret_name: link_secret_id.to_string(),
    };

    trace!(
        "create_credential_request <<< credential_request: {:?}, credential_request_metadata: {:?}",
        credential_request,
        credential_request_metadata
    );

    Ok((credential_request, credential_request_metadata))
}

/// Process an incoming credential as received from the issuer.
///
/// # Example
///
/// ```rust
/// use anoncreds::issuer;
/// use anoncreds::prover;
/// use anoncreds::types::MakeCredentialValues;
///
/// use anoncreds::types::CredentialDefinitionConfig;
/// use anoncreds::types::SignatureType;
///
/// let attribute_names: &[&str] = &["name", "age"];
/// let schema = issuer::create_schema("schema name",
///                                    "1.0",
///                                    "did:web:xyz",
///                                    attribute_names.into()
///                                    ).expect("Unable to create schema");
///
/// let (cred_def, cred_def_priv, key_correctness_proof) =
///     issuer::create_credential_definition("did:web:xyz/resource/schema",
///                                          &schema,
///                                          "did:web:xyz",
///                                          "default-tag",
///                                          SignatureType::CL,
///                                          CredentialDefinitionConfig::default()
///                                          ).expect("Unable to create Credential Definition");
///
/// let credential_offer =
///     issuer::create_credential_offer("did:web:xyz/resource/schema",
///                                     "did:web:xyz/resource/cred-def",
///                                     &key_correctness_proof,
///                                     ).expect("Unable to create Credential Offer");
///
/// let link_secret =
///     prover::create_link_secret().expect("Unable to create link secret");
///
/// let (credential_request, credential_request_metadata) =
///     prover::create_credential_request(Some("entropy"),
///                                       None,
///                                       &cred_def,
///                                       &link_secret,
///                                       "my-secret-id",
///                                       &credential_offer,
///                                       ).expect("Unable to create credential request");
///
/// let mut credential_values = MakeCredentialValues::default();
/// credential_values.add_raw("name", "john").expect("Unable to add credential value");
/// credential_values.add_raw("age", "28").expect("Unable to add credential value");
///
/// let mut credential =
///     issuer::create_credential(&cred_def,
///                               &cred_def_priv,
///                               &credential_offer,
///                               &credential_request,
///                               credential_values.into(),
///                               None,
///                               None,
///                               None
///                               ).expect("Unable to create credential");
///
/// prover::process_credential(&mut credential,
///                            &credential_request_metadata,
///                            &link_secret,
///                            &cred_def,
///                            None
///                            ).expect("Unable to process the credential");
/// ```
pub fn process_credential(
    credential: &mut Credential,
    cred_request_metadata: &CredentialRequestMetadata,
    link_secret: &LinkSecret,
    cred_def: &CredentialDefinition,
    rev_reg_def: Option<&RevocationRegistryDefinition>,
) -> Result<()> {
    trace!("process_credential >>> credential: {:?}, cred_request_metadata: {:?}, link_secret: {:?}, cred_def: {:?}, rev_reg_def: {:?}",
            credential, cred_request_metadata, secret!(&link_secret), cred_def, rev_reg_def);

    let credential_pub_key = CredentialPublicKey::build_from_parts(
        &cred_def.value.primary,
        cred_def.value.revocation.as_ref(),
    )?;
    let credential_values =
        build_credential_values(&credential.values.0, Some(&link_secret.try_into()?))?;
    let rev_pub_key = rev_reg_def.map(|d| &d.value.public_keys.accum_key);

    Prover::process_credential_signature(
        &mut credential.signature,
        &credential_values,
        &credential.signature_correctness_proof,
        &cred_request_metadata.link_secret_blinding_data,
        &credential_pub_key,
        cred_request_metadata.nonce.as_native(),
        rev_pub_key,
        credential.rev_reg.as_ref(),
        credential.witness.as_ref(),
    )?;

    trace!("process_credential <<< ");

    Ok(())
}

/// Process an incoming credential as received from the issuer.
///
/// # Example
///
/// ```rust
/// use std::collections::HashMap;
///
/// use anoncreds::issuer;
/// use anoncreds::prover;
/// use anoncreds::verifier;
/// use anoncreds::types::MakeCredentialValues;
/// use anoncreds::types::PresentCredentials;
/// use anoncreds::types::CredentialDefinitionConfig;
/// use anoncreds::types::SignatureType;
/// use anoncreds::data_types::schema::SchemaId;
/// use anoncreds::data_types::cred_def::CredentialDefinitionId;
///
/// let attribute_names: &[&str] = &["name", "age"];
/// let schema = issuer::create_schema("schema name",
///                                    "1.0",
///                                    "did:web:xyz",
///                                    attribute_names.into()
///                                    ).expect("Unable to create schema");
///
/// let (cred_def, cred_def_priv, key_correctness_proof) =
///     issuer::create_credential_definition("did:web:xyz/resource/schema",
///                                          &schema,
///                                          "did:web:xyz",
///                                          "default-tag",
///                                          SignatureType::CL,
///                                          CredentialDefinitionConfig::default()
///                                          ).expect("Unable to create Credential Definition");
///
/// let credential_offer =
///     issuer::create_credential_offer("did:web:xyz/resource/schema",
///                                     "did:web:xyz/resource/cred-def",
///                                     &key_correctness_proof,
///                                     ).expect("Unable to create Credential Offer");
///
/// let link_secret =
///     prover::create_link_secret().expect("Unable to create link secret");
///
/// let (credential_request, credential_request_metadata) =
///     prover::create_credential_request(Some("entropy"),
///                                       None,
///                                       &cred_def,
///                                       &link_secret,
///                                       "my-secret-id",
///                                       &credential_offer,
///                                       ).expect("Unable to create credential request");
///
/// let mut credential_values = MakeCredentialValues::default();
/// credential_values.add_raw("name", "john").expect("Unable to add credential value");
/// credential_values.add_raw("age", "28").expect("Unable to add credential value");
///
/// let mut credential =
///     issuer::create_credential(&cred_def,
///                               &cred_def_priv,
///                               &credential_offer,
///                               &credential_request,
///                               credential_values.into(),
///                               None,
///                               None,
///                               None
///                               ).expect("Unable to create credential");
///
/// prover::process_credential(&mut credential,
///                            &credential_request_metadata,
///                            &link_secret,
///                            &cred_def,
///                            None
///                            ).expect("Unable to process the credential");
///
/// let nonce = verifier::generate_nonce().expect("Unable to generate nonce");
/// let pres_request = serde_json::from_value(serde_json::json!({
///     "nonce": nonce,
///     "name":"example_presentation_request",
///     "version":"0.1",
///     "requested_attributes":{
///         "attr1_referent":{
///             "name":"name",
///             "restrictions": {
///                 "cred_def_id": "did:web:xyz/resource/cred-def"
///             }
///         },
///     },
///     "requested_predicates":{
///         "predicate1_referent":{"name":"age","p_type":">=","p_value":18}
///     }
/// }))
/// .expect("Unable to create presentation request");
///
/// let mut schemas = HashMap::new();
/// let schema_id = SchemaId::new_unchecked("did:web:xyz/resource/schema");
/// schemas.insert(&schema_id, &schema);
///
/// let mut cred_defs = HashMap::new();
/// let cred_def_id = CredentialDefinitionId::new_unchecked("did:web:xyz/resource/cred-def");
/// cred_defs.insert(&cred_def_id, &cred_def);
///
/// let mut present = PresentCredentials::default();
/// let mut cred1 = present.add_credential(
///     &credential,
///     None,
///     None,
/// );
/// cred1.add_requested_attribute("attr1_referent", true);
/// cred1.add_requested_predicate("predicate1_referent");
///
/// let presentation =
///     prover::create_presentation(&pres_request,
///                                 present,
///                                 None,
///                                 &link_secret,
///                                 &schemas,
///                                 &cred_defs
///                                 ).expect("Unable to create presentation");
/// ```
pub fn create_presentation(
    pres_req: &PresentationRequest,
    credentials: PresentCredentials,
    self_attested: Option<HashMap<String, String>>,
    link_secret: &LinkSecret,
    schemas: &HashMap<&SchemaId, &Schema>,
    cred_defs: &HashMap<&CredentialDefinitionId, &CredentialDefinition>,
) -> Result<Presentation> {
    trace!("create_proof >>> credentials: {:?}, pres_req: {:?}, credentials: {:?}, self_attested: {:?}, link_secret: {:?}, schemas: {:?}, cred_defs: {:?}",
            credentials, pres_req, credentials, &self_attested, secret!(&link_secret), schemas, cred_defs);

    if credentials.is_empty() && self_attested.as_ref().map_or(true, HashMap::is_empty) {
        return Err(err_msg!(
            "No credential mapping or self-attested attributes presented"
        ));
    }
    // check for duplicate referents
    credentials.validate()?;

    let pres_req_val = pres_req.value();
    let mut proof_builder = Prover::new_proof_builder()?;
    proof_builder.add_common_attribute("master_secret")?;

    let mut requested_proof = RequestedProof {
        self_attested_attrs: self_attested.unwrap_or_default(),
        ..Default::default()
    };

    let mut sub_proof_index = 0;
    let non_credential_schema = build_non_credential_schema()?;

    let mut identifiers: Vec<Identifier> = Vec::with_capacity(credentials.len());
    for present in credentials.0 {
        if present.is_empty() {
            continue;
        }
        let credential = present.cred;

        let schema = *schemas
            .get(&credential.schema_id)
            .ok_or_else(|| err_msg!("Schema not provided for ID: {}", credential.schema_id))?;

        let cred_def_id = CredentialDefinitionId::new(credential.cred_def_id.clone())?;
        let cred_def = *cred_defs.get(&cred_def_id).ok_or_else(|| {
            err_msg!(
                "Credential Definition not provided for ID: {}",
                credential.cred_def_id
            )
        })?;

        let credential_pub_key = CredentialPublicKey::build_from_parts(
            &cred_def.value.primary,
            cred_def.value.revocation.as_ref(),
        )?;

        let credential_schema = build_credential_schema(&schema.attr_names.0)?;
        let credential_values =
            build_credential_values(&credential.values.0, Some(&link_secret.try_into()?))?;
        let (req_attrs, req_predicates) = prepare_credential_for_proving(
            present.requested_attributes,
            present.requested_predicates,
            pres_req_val,
        )?;
        let sub_proof_request = build_sub_proof_request(&req_attrs, &req_predicates)?;

        update_requested_proof(
            req_attrs,
            req_predicates,
            pres_req_val,
            credential,
            sub_proof_index,
            &mut requested_proof,
        )?;

        // Checks conditions to add revocation proof
        let (rev_reg, witness) = if pres_req_val.non_revoked.is_some() {
            // Global revocation request
            (
                present.rev_state.as_ref().map(|r_info| &r_info.rev_reg),
                present.rev_state.as_ref().map(|r_info| &r_info.witness),
            )
        } else {
            // There exists at least 1 local revocation request
            let ((_, nonrevoked_attr), (_, nonrevoked_preds)) = (
                get_revealed_attributes_for_credential(
                    sub_proof_index as usize,
                    &requested_proof,
                    pres_req_val,
                ),
                get_predicates_for_credential(
                    sub_proof_index as usize,
                    &requested_proof,
                    pres_req_val,
                ),
            );
            if nonrevoked_attr.is_some() || nonrevoked_preds.is_some() {
                (
                    present.rev_state.as_ref().map(|r_info| &r_info.rev_reg),
                    present.rev_state.as_ref().map(|r_info| &r_info.witness),
                )
            } else {
                // Neither global nor local is required
                (None, None)
            }
        };

        // if `present.rev_state` is available,
        // then it will create an init_proof that contains NRP.
        //
        // Therefore, this will have to be part of the finalised `aggregated_proof`.
        // Regardless if nonrevoke_interval is requested by the verifier
        proof_builder.add_sub_proof_request(
            &sub_proof_request,
            &credential_schema,
            &non_credential_schema,
            &credential.signature,
            &credential_values,
            &credential_pub_key,
            rev_reg,
            witness,
        )?;

        let identifier = match pres_req {
            PresentationRequest::PresentationRequestV2(_)
            | PresentationRequest::PresentationRequestV1(_) => Identifier {
                schema_id: credential.schema_id.clone(),
                cred_def_id: credential.cred_def_id.clone(),
                rev_reg_id: credential.rev_reg_id.clone(),
                timestamp: present.timestamp,
            },
        };

        identifiers.push(identifier);

        sub_proof_index += 1;
    }

    let proof = proof_builder.finalize(pres_req_val.nonce.as_native())?;

    let full_proof = Presentation {
        proof,
        requested_proof,
        identifiers,
    };

    trace!("create_proof <<< full_proof: {:?}", secret!(&full_proof));

    Ok(full_proof)
}

/// Create a [`CredentialRevocationState`] based on a [`Witness`], [`RevocationStatusList`] and
/// timestamp.
pub fn create_revocation_state_with_witness(
    witness: Witness,
    revocation_status_list: &RevocationStatusList,
    timestamp: u64,
) -> Result<CredentialRevocationState> {
    let rev_reg = <&RevocationStatusList as TryInto<Option<RevocationRegistry>>>::try_into(
        revocation_status_list,
    )?
    .ok_or_else(|| err_msg!(Unexpected, "Revocation Status List must have accum value"))?;

    Ok(CredentialRevocationState {
        witness,
        rev_reg,
        timestamp,
    })
}

/// Create or update the revocation state. If both the `rev_state` and `old_rev_status_list` are
/// supplied, it will update it. Otherwise it will create a new [`CredentialRevocationState`]
///
/// This can be done by anyone, allowing prover to offload this task The `tails_path` here is used
/// instead of `tails_location` in `revoc_reg_def` so prover can provide it
///
/// # Example
///
/// ```rust
/// use anoncreds::prover;
/// use anoncreds::issuer;
/// use anoncreds::types::CredentialDefinitionConfig;
/// use anoncreds::types::SignatureType;
/// use anoncreds::types::RegistryType;
/// use anoncreds::tails::TailsFileWriter;
///
/// let attribute_names: &[&str] = &["name", "age"];
/// let schema = issuer::create_schema("schema name",
///                                    "1.0",
///                                    "did:web:xyz",
///                                    attribute_names.into()
///                                    ).expect("Unable to create schema");
///
/// let (cred_def, cred_def_priv, key_correctness_proof) =
///     issuer::create_credential_definition("did:web:xyz/resource/schema",
///                                          &schema,
///                                          "did:web:xyz",
///                                          "default-tag",
///                                          SignatureType::CL,
///                                          CredentialDefinitionConfig {
///                                             support_revocation: true
///                                          },
///                                          ).expect("Unable to create Credential Definition");
///
/// let mut tw = TailsFileWriter::new(None);
/// let (rev_reg_def, rev_reg_def_priv) =
///     issuer::create_revocation_registry_def(&cred_def,
///                                            "did:web:xyz/resource/cred-def",
///                                            "did:web:xyz",
///                                            "default-tag",
///                                            RegistryType::CL_ACCUM,
///                                            1000,
///                                            &mut tw
///                                            ).expect("Unable to create revocation registry");
///
/// let rev_status_list =
///     issuer::create_revocation_status_list(&cred_def,
///                                           "did:web:xyz/resource/rev-reg-def",
///                                           &rev_reg_def,
///                                           &rev_reg_def_priv,
///                                           "did:web:xyz",
///                                           true,
///                                           Some(10)
///                                           ).expect("Unable to create revocation status list");
///
/// let rev_state =
///     prover::create_or_update_revocation_state(&rev_reg_def.value.tails_location,
///                                               &rev_reg_def,
///                                               &rev_status_list,
///                                               0,
///                                               None,
///                                               None
///                                               ).expect("Unable to create or update the revocation state");
/// ```
pub fn create_or_update_revocation_state(
    tails_path: &str,
    rev_reg_def: &RevocationRegistryDefinition,
    rev_status_list: &RevocationStatusList,
    rev_reg_idx: u32,
    rev_state: Option<&CredentialRevocationState>, // for witness update
    old_rev_status_list: Option<&RevocationStatusList>, // for witness update
) -> Result<CredentialRevocationState> {
    trace!(
        "create_or_update_revocation_state >>> revoc_reg_def: {:?}, \
    rev_status_list: {:?}, rev_reg_idx: {},  rev_state: {:?}, old_rev_status_list {:?}",
        rev_reg_def,
        rev_status_list,
        rev_reg_idx,
        rev_state,
        old_rev_status_list,
    );

    let rev_reg: Option<RevocationRegistry> = rev_status_list.try_into()?;
    let rev_reg = rev_reg.ok_or_else(|| {
        err_msg!("revocation registry is required to create or update the revocation state")
    })?;

    let timestamp = rev_status_list.timestamp().ok_or_else(|| {
        err_msg!("Timestamp is required to create or update the revocation state")
    })?;

    let mut issued = HashSet::<u32>::new();
    let mut revoked = HashSet::<u32>::new();
    let tails_reader = TailsFileReader::new_tails_reader(tails_path);
    let witness = if let (Some(source_rev_state), Some(source_rev_list)) =
        (rev_state, old_rev_status_list)
    {
        create_index_deltas(
            &rev_status_list
                .state_owned()
                .bitxor(source_rev_list.state()),
            rev_status_list.state(),
            &mut issued,
            &mut revoked,
        );

        let source_rev_reg: Option<RevocationRegistry> = source_rev_list.try_into()?;

        let rev_reg_delta = RevocationRegistryDelta::from_parts(
            source_rev_reg.as_ref(),
            &rev_reg,
            &issued,
            &revoked,
        );

        let mut witness = source_rev_state.witness.clone();
        witness.update(
            rev_reg_idx,
            rev_reg_def.value.max_cred_num,
            &rev_reg_delta,
            &tails_reader,
        )?;
        witness
    } else {
        let list_size = usize::try_from(rev_reg_def.value.max_cred_num)
            .map_err(|e| Error::from_msg(crate::ErrorKind::InvalidState, e.to_string()))?;
        // Issuance by default
        let bit: usize = 0;
        let list = bitvec![bit; list_size];
        create_index_deltas(
            &rev_status_list.state_owned().bitxor(list),
            rev_status_list.state(),
            &mut issued,
            &mut revoked,
        );
        let rev_reg_delta = RevocationRegistryDelta::from_parts(None, &rev_reg, &issued, &revoked);
        Witness::new(
            rev_reg_idx,
            rev_reg_def.value.max_cred_num,
            // issuance by default
            true,
            &rev_reg_delta,
            &tails_reader,
        )?
    };

    Ok(CredentialRevocationState {
        witness,
        rev_reg,
        timestamp,
    })
}

fn create_index_deltas(
    delta: &bitvec::vec::BitVec,
    list: &bitvec::vec::BitVec,
    issued: &mut HashSet<u32>,
    revoked: &mut HashSet<u32>,
) {
    for i in delta.iter_ones() {
        if list[i] {
            // true means cred has been revoked
            revoked.insert(i as u32);
        } else {
            // false means cred has not been
            issued.insert(i as u32);
        }
    }
}

fn prepare_credential_for_proving(
    requested_attributes: HashSet<(String, bool)>,
    requested_predicates: HashSet<String>,
    pres_req: &PresentationRequestPayload,
) -> Result<(Vec<RequestedAttributeInfo>, Vec<RequestedPredicateInfo>)> {
    trace!(
        "_prepare_credentials_for_proving >>> requested_attributes: {:?}, requested_predicates: {:?}, pres_req: {:?}",
        requested_attributes,
        requested_predicates,
        pres_req
    );

    let mut attrs = Vec::with_capacity(requested_attributes.len());
    let mut preds = Vec::with_capacity(requested_predicates.len());

    for (attr_referent, revealed) in requested_attributes {
        let attr_info = pres_req
            .requested_attributes
            .get(attr_referent.as_str())
            .ok_or_else(|| {
                err_msg!(
                    "AttributeInfo not found in PresentationRequest for referent \"{}\"",
                    attr_referent.as_str()
                )
            })?;

        attrs.push(RequestedAttributeInfo {
            attr_referent,
            attr_info: attr_info.clone(),
            revealed,
        });
    }

    for predicate_referent in requested_predicates {
        let predicate_info = pres_req
            .requested_predicates
            .get(predicate_referent.as_str())
            .ok_or_else(|| {
                err_msg!(
                    "PredicateInfo not found in PresentationRequest for referent \"{}\"",
                    predicate_referent.as_str()
                )
            })?;

        preds.push(RequestedPredicateInfo {
            predicate_referent,
            predicate_info: predicate_info.clone(),
        });
    }

    trace!(
        "_prepare_credential_for_proving <<< attrs: {:?}, preds: {:?}",
        attrs,
        preds
    );

    Ok((attrs, preds))
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
        .find(|(key, _)| attr_common_view(key) == attr_common_view(requested_attr))
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
                    get_credential_values_for_attribute(&credential.values.0, name).ok_or_else(
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
                        get_credential_values_for_attribute(&credential.values.0, name)
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

    let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder()?;

    for attr in req_attrs_for_credential {
        if attr.revealed {
            if let Some(ref name) = &attr.attr_info.name {
                sub_proof_request_builder.add_revealed_attr(&attr_common_view(name))?;
            } else if let Some(ref names) = &attr.attr_info.names {
                for name in names {
                    sub_proof_request_builder.add_revealed_attr(&attr_common_view(name))?;
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

    use crate::data_types::pres_request::PredicateTypes;

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

    macro_rules! hashset {
        ($( $val: expr ),*) => {
            {
                let mut set = ::std::collections::HashSet::new();
                $(
                    set.insert($val);
                )*
                set
            }
        }
    }

    mod prepare_credentials_for_proving {
        use crate::data_types::pres_request::{AttributeInfo, PredicateInfo};

        use super::*;

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

        fn _req_cred() -> (HashSet<(String, bool)>, HashSet<String>) {
            (
                hashset!((ATTRIBUTE_REFERENT.to_string(), false)),
                hashset!(PREDICATE_REFERENT.to_string()),
            )
        }

        #[test]
        fn prepare_credential_for_proving_works() {
            let (req_attrs, req_preds) = _req_cred();
            let proof_req = _proof_req();

            let (req_attr_info, req_pred_info) =
                prepare_credential_for_proving(req_attrs, req_preds, &proof_req).unwrap();

            assert_eq!(1, req_attr_info.len());
            assert_eq!(1, req_pred_info.len());
        }

        #[test]
        fn prepare_credential_for_proving_works_for_multiple_attributes() {
            let (mut req_attrs, req_preds) = _req_cred();
            let mut proof_req = _proof_req();

            req_attrs.insert(("attribute_referent_2".to_string(), false));

            proof_req.requested_attributes.insert(
                "attribute_referent_2".to_string(),
                AttributeInfo {
                    name: Some("last_name".to_string()),
                    names: None,
                    restrictions: None,
                    non_revoked: None,
                },
            );

            let (req_attr_info, req_pred_info) =
                prepare_credential_for_proving(req_attrs, req_preds, &proof_req).unwrap();

            assert_eq!(2, req_attr_info.len());
            assert_eq!(1, req_pred_info.len());
        }

        #[test]
        fn prepare_credential_for_proving_works_for_missed_attribute() {
            let (req_attrs, req_preds) = _req_cred();
            let mut proof_req = _proof_req();

            proof_req.requested_attributes.clear();

            let res = prepare_credential_for_proving(req_attrs, req_preds, &proof_req);
            assert_kind!(Input, res);
        }

        #[test]
        fn prepare_credential_for_proving_works_for_missed_predicate() {
            let (req_attrs, req_preds) = _req_cred();
            let mut proof_req = _proof_req();

            proof_req.requested_predicates.clear();

            let res = prepare_credential_for_proving(req_attrs, req_preds, &proof_req);
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

    mod using_prover_did_with_new_and_legacy_identifiers {
        use crate::{
            data_types::cred_def::{CredentialKeyCorrectnessProof, SignatureType},
            issuer::{create_credential_definition, create_credential_offer, create_schema},
            types::CredentialDefinitionConfig,
        };

        use super::*;

        const SCHEMA_ID: &str = "mock:uri";
        const ISSUER_ID: &str = "mock:uri";
        const CRED_DEF_ID: &str = "mock:uri";

        const LEGACY_DID_IDENTIFIER: &str = "DXoTtQJNtXtiwWaZAK3rB1";
        const LEGACY_SCHEMA_IDENTIFIER: &str = "DXoTtQJNtXtiwWaZAK3rB1:2:example:1.0";
        const LEGACY_CRED_DEF_IDENTIFIER: &str = "DXoTtQJNtXtiwWaZAK3rB1:3:CL:98153:default";

        fn _link_secret() -> LinkSecret {
            LinkSecret::new().expect("Error creating prover link secret")
        }

        fn _schema() -> Schema {
            create_schema(
                "test",
                "1.0",
                ISSUER_ID.try_into().unwrap(),
                ["a", "b", "c"][..].into(),
            )
            .unwrap()
        }

        fn _cred_def_and_key_correctness_proof(
        ) -> (CredentialDefinition, CredentialKeyCorrectnessProof) {
            let (cred_def, _, key_correctness_proof) = create_credential_definition(
                SCHEMA_ID.try_into().unwrap(),
                &_schema(),
                ISSUER_ID.try_into().unwrap(),
                "tag",
                SignatureType::CL,
                CredentialDefinitionConfig {
                    support_revocation: false,
                },
            )
            .unwrap();
            (cred_def, key_correctness_proof)
        }

        fn _cred_offer(key_correctness_proof: CredentialKeyCorrectnessProof) -> CredentialOffer {
            create_credential_offer(
                SCHEMA_ID.try_into().unwrap(),
                CRED_DEF_ID.try_into().unwrap(),
                &key_correctness_proof,
            )
            .unwrap()
        }

        fn _legacy_schema() -> Schema {
            create_schema(
                "test",
                "1.0",
                LEGACY_DID_IDENTIFIER.try_into().unwrap(),
                ["a", "b", "c"][..].into(),
            )
            .unwrap()
        }

        fn _legacy_cred_def_and_key_correctness_proof(
        ) -> (CredentialDefinition, CredentialKeyCorrectnessProof) {
            let (cred_def, _, key_correctness_proof) = create_credential_definition(
                LEGACY_SCHEMA_IDENTIFIER.try_into().unwrap(),
                &_legacy_schema(),
                LEGACY_DID_IDENTIFIER.try_into().unwrap(),
                "tag",
                SignatureType::CL,
                CredentialDefinitionConfig {
                    support_revocation: false,
                },
            )
            .unwrap();
            (cred_def, key_correctness_proof)
        }

        fn _legacy_cred_offer(
            key_correctness_proof: CredentialKeyCorrectnessProof,
        ) -> CredentialOffer {
            create_credential_offer(
                LEGACY_SCHEMA_IDENTIFIER.try_into().unwrap(),
                LEGACY_CRED_DEF_IDENTIFIER.try_into().unwrap(),
                &key_correctness_proof,
            )
            .unwrap()
        }

        #[test]
        fn create_credential_request_with_new_identifiers_and_no_prover_did() {
            let (cred_def, key_correctness_proof) = _cred_def_and_key_correctness_proof();
            let link_secret = _link_secret();
            let cred_offer = _cred_offer(key_correctness_proof);
            let resp = create_credential_request(
                Some("entropy"),
                None,
                &cred_def,
                &link_secret,
                "default",
                &cred_offer,
            );
            assert!(resp.is_ok())
        }

        #[test]
        fn create_credential_request_with_legacy_identifiers_and_a_prover_did() {
            let (cred_def, key_correctness_proof) = _legacy_cred_def_and_key_correctness_proof();
            let link_secret = _link_secret();
            let cred_offer = _legacy_cred_offer(key_correctness_proof);
            let resp = create_credential_request(
                Some("entropy"),
                None,
                &cred_def,
                &link_secret,
                "default",
                &cred_offer,
            );
            assert!(resp.is_ok())
        }

        #[test]
        fn create_credential_request_with_legacy_identifiers_and_no_prover_did() {
            let (cred_def, key_correctness_proof) = _legacy_cred_def_and_key_correctness_proof();
            let link_secret = _link_secret();
            let cred_offer = _legacy_cred_offer(key_correctness_proof);
            let resp = create_credential_request(
                Some("entropy"),
                None,
                &cred_def,
                &link_secret,
                "default",
                &cred_offer,
            );
            assert!(resp.is_ok())
        }

        #[test]
        fn create_credential_request_with_new_identifiers_and_a_prover_did() {
            let (cred_def, key_correctness_proof) = _cred_def_and_key_correctness_proof();
            let link_secret = _link_secret();
            let cred_offer = _cred_offer(key_correctness_proof);
            let resp = create_credential_request(
                Some("entropy"),
                None,
                &cred_def,
                &link_secret,
                "default",
                &cred_offer,
            );
            assert!(resp.is_ok())
        }

        #[test]
        fn create_credential_request_with_new_and_legacy_identifiers_and_a_prover_did() {
            let (cred_def, key_correctness_proof) = _cred_def_and_key_correctness_proof();
            let link_secret = _link_secret();
            let cred_offer = _legacy_cred_offer(key_correctness_proof);
            let resp = create_credential_request(
                Some("entropy"),
                None,
                &cred_def,
                &link_secret,
                "default",
                &cred_offer,
            );
            assert!(resp.is_ok())
        }
    }
}
