use crate::data_types::cred_def::{CredentialDefinition, CredentialDefinitionId};
use crate::data_types::pres_request::PresentationRequestPayload;
use crate::data_types::schema::{Schema, SchemaId};
use crate::data_types::w3c::credential::W3CCredential;
use crate::data_types::w3c::presentation::W3CPresentation;
use crate::error::Result;
use crate::types::{
    CredentialRequestMetadata, CredentialValues, LinkSecret, PresentCredential, PresentCredentials,
    PresentationRequest, RevocationRegistryDefinition,
};
use crate::utils::validation::Validatable;

use crate::data_types::w3c::credential_attributes::CredentialSubject;
use crate::data_types::w3c::proof::{
    CredentialPresentationProofValue, DataIntegrityProof, PresentationProofValue,
};
use crate::data_types::w3c::VerifiableCredentialSpecVersion;
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
///                               None,
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

    let cred_values = w3c_credential.credential_subject.encode()?;

    let proof = w3c_credential.get_mut_data_integrity_proof()?;
    let mut credential_signature = proof.get_credential_signature_proof()?.clone();

    CLCredentialProver::new(link_secret).process_credential(
        &mut credential_signature.signature,
        &credential_signature.signature_correctness_proof,
        &cred_values,
        cred_request_metadata,
        cred_def,
        rev_reg_def,
        credential_signature.rev_reg.as_ref(),
        credential_signature.witness.as_ref(),
    )?;

    *proof = DataIntegrityProof::new_credential_proof(&credential_signature)?;

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
    version: Option<VerifiableCredentialSpecVersion>,
) -> Result<W3CPresentation> {
    trace!(
        "create_w3c_presentation >>> credentials: {:?}, pres_req: {:?}, credentials: {:?}, \
            link_secret: {:?}, schemas: {:?}, cred_defs: {:?}, version: {:?}",
        credentials,
        pres_req,
        credentials,
        secret!(&link_secret),
        schemas,
        cred_defs,
        version
    );

    if credentials.is_empty() {
        return Err(err_msg!("No credential mapping"));
    }
    // check for duplicate referents
    credentials.validate()?;

    let presentation_request = pres_req.value();

    let mut proof_builder = CLProofBuilder::new(presentation_request, schemas, cred_defs)?;

    for present in credentials.0.iter() {
        if present.is_empty() {
            continue;
        }
        let credential = present.cred;
        let credential_values: CredentialValues = credential.credential_subject.encode()?;
        let proof = credential.get_credential_signature_proof()?;

        proof_builder.add_sub_proof(
            &credential_values,
            &proof.signature,
            link_secret,
            present,
            &proof.schema_id,
            &proof.cred_def_id,
            proof.rev_reg_id.as_ref(),
        )?;
    }

    let mut verifiable_credentials: Vec<W3CCredential> = Vec::with_capacity(credentials.len());
    let mut pres_verification_method = String::new();
    let cl_proof = proof_builder.build()?;

    // cl signatures generates sub proofs and aggregated at once at the end
    // so we need to iterate over credentials again an put sub proofs into their proofs
    for (present, sub_proof) in credentials.0.iter().zip(cl_proof.proofs) {
        let credential_attributes = build_credential_attributes(presentation_request, present)?;
        let credential_proof = present.cred.get_credential_signature_proof()?;
        let proof = CredentialPresentationProofValue {
            schema_id: credential_proof.schema_id.to_owned(),
            cred_def_id: credential_proof.cred_def_id.to_owned(),
            rev_reg_id: credential_proof.rev_reg_id.to_owned(),
            timestamp: present.timestamp,
            sub_proof,
        };
        let proof = DataIntegrityProof::new_credential_presentation_proof(&proof)?;
        let credential = W3CCredential::derive(credential_attributes, proof, present.cred);
        verifiable_credentials.push(credential);
        // Temporary hack - use `cred_def_id` verification_method for presentation
        pres_verification_method = credential_proof.cred_def_id.to_string();
    }

    let presentation_proof = PresentationProofValue {
        aggregated: cl_proof.aggregated_proof,
    };
    let proof = DataIntegrityProof::new_presentation_proof(
        &presentation_proof,
        presentation_request.nonce.to_string(),
        pres_verification_method,
    )?;
    let presentation = W3CPresentation::new(verifiable_credentials, proof, version.as_ref());

    trace!(
        "create_w3c_presentation <<< presentation: {:?}",
        secret!(&presentation)
    );

    Ok(presentation)
}

fn build_credential_attributes<'p>(
    pres_req: &PresentationRequestPayload,
    credentials: &PresentCredential<'p, W3CCredential>,
) -> Result<CredentialSubject> {
    let mut attributes = CredentialSubject::default();

    for (referent, reveal) in credentials.requested_attributes.iter() {
        let requested_attribute = pres_req
            .requested_attributes
            .get(referent)
            .ok_or_else(|| err_msg!("Attribute {} not found in ProofRequest", referent))?;

        if let Some(ref name) = requested_attribute.name {
            let (attribute, value) = credentials.cred.get_case_insensitive_attribute(name)?;
            if *reveal {
                attributes.add_attribute(attribute, value);
            }
        }
        if let Some(ref names) = requested_attribute.names {
            for name in names {
                let (attribute, value) = credentials.cred.get_case_insensitive_attribute(name)?;
                attributes.add_attribute(attribute, value);
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
        attributes.add_predicate(attribute)?;
    }

    Ok(attributes)
}
