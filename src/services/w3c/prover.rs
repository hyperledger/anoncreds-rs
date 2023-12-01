use crate::data_types::cred_def::{CredentialDefinition, CredentialDefinitionId};
use crate::data_types::pres_request::PresentationRequestPayload;
use crate::data_types::schema::{Schema, SchemaId};
use crate::data_types::w3c::credential::{CredentialSubject, W3CCredential};
use crate::data_types::w3c::presentation::W3CPresentation;
use crate::error::Result;
use crate::types::{
    CredentialRequestMetadata, CredentialValues, LinkSecret, PresentCredential, PresentCredentials,
    PresentationRequest, RevocationRegistryDefinition,
};
use crate::utils::validation::Validatable;

use crate::data_types::w3c::credential_proof::{CredentialSignature, CredentialSignatureProof};
use crate::data_types::w3c::presentation_proof::{
    CredentialPresentationProof, CredentialPresentationProofValue, PredicateAttribute,
    PresentationProof, PresentationProofValue,
};
use crate::prover::{CLCredentialProver, CLProofBuilder};
use std::collections::HashMap;

/// Process an incoming credential in W3C form as received from the issuer.
///
/// # Example
///
/// ```rust
/// use anoncreds::{issuer, w3c};
/// use anoncreds::prover;
/// use anoncreds::w3c::types::MakeCredentialAttributes;
///
/// use anoncreds::types::CredentialDefinitionConfig;
/// use anoncreds::types::SignatureType;
/// use anoncreds::data_types::issuer_id::IssuerId;
/// use anoncreds::data_types::schema::SchemaId;
/// use anoncreds::data_types::cred_def::CredentialDefinitionId;
///
/// let attribute_names: &[&str] = &["name", "age"];
/// let issuer_id = IssuerId::new("did:web:xyz").expect("Invalid issuer ID");
/// let schema_id = SchemaId::new("did:web:xyz/resource/schema").expect("Invalid schema ID");
/// let cred_def_id = CredentialDefinitionId::new("did:web:xyz/resource/cred-def",).expect("Invalid credential definition ID");
///
/// let schema = issuer::create_schema("schema name",
///                                    "1.0",
///                                    issuer_id.clone(),
///                                    attribute_names.into()
///                                    ).expect("Unable to create schema");
///
/// let (cred_def, cred_def_priv, key_correctness_proof) =
///     issuer::create_credential_definition(schema_id.clone(),
///                                          &schema,
///                                          issuer_id,
///                                          "default-tag",
///                                          SignatureType::CL,
///                                          CredentialDefinitionConfig::default()
///                                          ).expect("Unable to create Credential Definition");
///
/// let credential_offer =
///     issuer::create_credential_offer(schema_id,
///                                     cred_def_id,
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
/// let mut credential_values = MakeCredentialAttributes::default();
/// credential_values.add("name", "john");
/// credential_values.add("age", "28");
///
/// let mut credential =
///     w3c::issuer::create_credential(&cred_def,
///                               &cred_def_priv,
///                               &credential_offer,
///                               &credential_request,
///                               credential_values.into(),
///                               None,
///                               None
///                               ).expect("Unable to create credential");
///
/// w3c::prover::process_credential(&mut credential,
///                            &credential_request_metadata,
///                            &link_secret,
///                            &cred_def,
///                            None
///                            ).expect("Unable to process the credential");
/// ```
pub fn process_credential(
    w3c_credential: &mut W3CCredential,
    cred_request_metadata: &CredentialRequestMetadata,
    link_secret: &LinkSecret,
    cred_def: &CredentialDefinition,
    rev_reg_def: Option<&RevocationRegistryDefinition>,
) -> Result<()> {
    trace!("process_w3c_credential >>> credential: {:?}, cred_request_metadata: {:?}, link_secret: {:?}, cred_def: {:?}, rev_reg_def: {:?}",
            w3c_credential, cred_request_metadata, secret!(&link_secret), cred_def, rev_reg_def);

    let cred_values = w3c_credential
        .credential_subject
        .attributes
        .encode(&w3c_credential.credential_schema.encoding)?;
    let proof = w3c_credential.get_mut_credential_signature_proof()?;
    let mut signature = proof.get_credential_signature()?;

    CLCredentialProver::new(link_secret).process_credential(
        &mut signature.signature,
        &signature.signature_correctness_proof,
        &cred_values,
        cred_request_metadata,
        cred_def,
        rev_reg_def,
        signature.rev_reg.as_ref(),
        signature.witness.as_ref(),
    )?;

    let signature = CredentialSignature::new(
        signature.signature,
        signature.signature_correctness_proof,
        signature.rev_reg,
        signature.witness,
    );
    *proof = CredentialSignatureProof::new(signature);

    trace!("process_w3c_credential <<< ");

    Ok(())
}

/// Create W3C presentation
pub fn create_presentation(
    pres_req: &PresentationRequest,
    credentials: PresentCredentials<W3CCredential>,
    link_secret: &LinkSecret,
    schemas: &HashMap<SchemaId, Schema>,
    cred_defs: &HashMap<CredentialDefinitionId, CredentialDefinition>,
) -> Result<W3CPresentation> {
    trace!("create_w3c_presentation >>> credentials: {:?}, pres_req: {:?}, credentials: {:?}, link_secret: {:?}, schemas: {:?}, cred_defs: {:?}",
            credentials, pres_req, credentials, secret!(&link_secret), schemas, cred_defs);

    if credentials.is_empty() {
        return Err(err_msg!("No credential mapping"));
    }
    // check for duplicate referents
    credentials.validate()?;

    let pres_req = pres_req.value();

    let mut proof_builder = CLProofBuilder::new(pres_req, schemas, cred_defs)?;

    for present in credentials.0.iter() {
        if present.is_empty() {
            continue;
        }
        let credential = present.cred;
        let credential_values: CredentialValues = credential
            .credential_subject
            .attributes
            .encode(&credential.credential_schema.encoding)?;
        let proof = credential.get_credential_signature_proof()?;
        let signature = proof.get_credential_signature()?;
        let schema_id = credential.get_schema_id();
        let cred_def_id = credential.get_cred_def_id();
        let rev_reg_id = credential.get_rev_reg_id();

        proof_builder.add_sub_proof(
            &credential_values,
            &signature.signature,
            link_secret,
            present,
            schema_id,
            cred_def_id,
            rev_reg_id,
        )?;
    }

    let cl_proof = proof_builder.build()?;

    let presentation_proof_value = PresentationProofValue::new(cl_proof.aggregated_proof);
    let presentation_proof =
        PresentationProof::new(presentation_proof_value, pres_req.nonce.to_string());

    let mut presentation = W3CPresentation::new();
    presentation.set_proof(presentation_proof);

    // cl signatures generates sub proofs and aggregated at once at the end
    // so we need to iterate over credentials again an put sub proofs into their proofs
    for (present, sub_proof) in credentials.0.iter().zip(cl_proof.proofs) {
        let credential_subject = build_credential_subject(pres_req, present)?;
        let proof_value = CredentialPresentationProofValue::new(sub_proof);
        let proof = CredentialPresentationProof::new(proof_value, present.timestamp);

        let mut credential = present.cred.to_owned();
        credential.set_anoncreds_presentation_proof(proof);
        credential.set_attributes(credential_subject.attributes);

        presentation.add_verifiable_credential(credential);
    }

    trace!(
        "create_w3c_presentation <<< presentation: {:?}",
        secret!(&presentation)
    );

    Ok(presentation)
}

fn build_credential_subject<'p>(
    pres_req: &PresentationRequestPayload,
    credentials: &PresentCredential<'p, W3CCredential>,
) -> Result<CredentialSubject> {
    let mut credential_subject = CredentialSubject::default();

    for (referent, reveal) in credentials.requested_attributes.iter() {
        let requested_attribute = pres_req
            .requested_attributes
            .get(referent)
            .ok_or_else(|| err_msg!("Attribute {} not found in ProofRequest", referent))?;

        if let Some(ref name) = requested_attribute.name {
            let (attribute, value) = credentials.cred.get_case_insensitive_attribute(name)?;
            if *reveal {
                credential_subject
                    .attributes
                    .add_attribute(attribute, value);
            }
        }
        if let Some(ref names) = requested_attribute.names {
            for name in names {
                let (attribute, value) = credentials.cred.get_case_insensitive_attribute(name)?;
                credential_subject
                    .attributes
                    .add_attribute(attribute, value);
            }
        }
    }

    for referent in credentials.requested_predicates.iter() {
        let predicate_info = pres_req
            .requested_predicates
            .get(referent)
            .ok_or_else(|| err_msg!("Predicate {} not found in ProofRequest", referent))?
            .to_owned();
        let (attribute, _) = credentials
            .cred
            .get_case_insensitive_attribute(&predicate_info.name)?;
        let predicate = PredicateAttribute::from(predicate_info);
        credential_subject
            .attributes
            .add_predicate(attribute, predicate)?;
    }

    Ok(credential_subject)
}
