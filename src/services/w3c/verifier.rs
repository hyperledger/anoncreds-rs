use crate::data_types::cred_def::CredentialDefinition;
use crate::data_types::cred_def::CredentialDefinitionId;
use crate::data_types::pres_request::PresentationRequestPayload;
use crate::data_types::presentation::{
    AttributeValue, Identifier, RequestedProof, RevealedAttributeGroupInfo, RevealedAttributeInfo,
    SubProofReferent,
};
use crate::data_types::rev_reg_def::RevocationRegistryDefinitionId;
use crate::data_types::schema::Schema;
use crate::data_types::schema::SchemaId;
use crate::data_types::w3c::presentation::W3CPresentation;
use crate::error::Result;

use crate::data_types::w3c::credential::CredentialAttributeValue;
use crate::types::{PresentationRequest, RevocationRegistryDefinition, RevocationStatusList};
use crate::verifier::{
    compare_attr_from_proof_and_request, verify_requested_restrictions, CLProofVerifier,
};
use anoncreds_clsignatures::Proof;
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
    trace!("verify_w3c_presentation >>> presentation: {:?}, pres_req: {:?}, schemas: {:?}, cred_defs: {:?}, rev_reg_defs: {:?} rev_status_lists: {:?}",
    presentation, pres_req, schemas, cred_defs, rev_reg_defs, rev_status_lists);

    // These values are from the prover and cannot be trusted
    let (received_revealed_attrs, received_unrevealed_attrs, received_predicates) =
        collect_received_attrs_and_predicates(presentation)?;
    // W3C presentation does not support self-attested attributes
    let self_attested_attrs = HashSet::new();

    let pres_req = pres_req.value();

    // Ensures that all attributes in the request is also in the presentation
    compare_attr_from_proof_and_request(
        pres_req,
        &received_revealed_attrs,
        &received_unrevealed_attrs,
        &self_attested_attrs,
        &received_predicates,
    )?;

    // Ensures the restrictions set out in the request is met
    let requested_proof = build_requested_proof(presentation, pres_req)?;
    verify_requested_restrictions(
        pres_req,
        schemas,
        cred_defs,
        &requested_proof,
        &received_revealed_attrs,
        &received_unrevealed_attrs,
        &received_predicates,
        &self_attested_attrs,
    )?;

    let proof_data = presentation.proof.get_proof_value()?;
    let mut proof = Proof {
        proofs: Vec::new(),
        aggregated_proof: proof_data.aggregated,
    };

    let mut proof_verifier = CLProofVerifier::init(
        pres_req,
        schemas,
        cred_defs,
        rev_reg_defs,
        rev_status_lists.as_ref(),
    )?;

    for verifiable_credential in presentation.verifiable_credential.iter() {
        let credential_proof = verifiable_credential.get_presentation_proof()?;
        let proof_data = credential_proof.get_proof_value()?;
        let schema_id = &verifiable_credential.schema_id();
        let cred_def_id = &verifiable_credential.cred_def_id();
        let rev_reg_id = verifiable_credential.get_rev_reg_id();

        let mut revealed_attribute: HashSet<String> =
            credential_proof.mapping.revealed_attributes.clone();
        revealed_attribute.extend(credential_proof.mapping.revealed_attribute_groups.clone());

        proof_verifier.add_sub_proof(
            &revealed_attribute,
            &credential_proof.mapping.predicates,
            schema_id,
            cred_def_id,
            rev_reg_id,
            credential_proof.timestamp,
            nonrevoke_interval_override,
        )?;
        proof.proofs.push(proof_data.sub_proof);
    }

    let valid = proof_verifier.verify(&proof)?;

    trace!("verify_w3c_presentation <<< valid: {:?}", valid);

    Ok(valid)
}

#[allow(clippy::type_complexity)]
fn collect_received_attrs_and_predicates(
    proof: &W3CPresentation,
) -> Result<(
    HashMap<String, Identifier>,
    HashMap<String, Identifier>,
    HashMap<String, Identifier>,
)> {
    let mut revealed: HashMap<String, Identifier> = HashMap::new();
    let mut unrevealed: HashMap<String, Identifier> = HashMap::new();
    let mut predicates: HashMap<String, Identifier> = HashMap::new();

    for verifiable_credential in proof.verifiable_credential.iter() {
        let presentation_proof = verifiable_credential.get_presentation_proof()?;
        let rev_reg_id = verifiable_credential.get_rev_reg_id().cloned();

        let identifier: Identifier = Identifier {
            schema_id: verifiable_credential.schema_id().clone(),
            cred_def_id: verifiable_credential.cred_def_id().clone(),
            rev_reg_id,
            timestamp: None,
        };
        for revealed_attribute in &presentation_proof.mapping.revealed_attributes {
            revealed.insert(revealed_attribute.to_string(), identifier.clone());
        }
        for revealed_attribute_group in &presentation_proof.mapping.revealed_attribute_groups {
            revealed.insert(revealed_attribute_group.to_string(), identifier.clone());
        }

        for unrevealed_attribute in &presentation_proof.mapping.unrevealed_attributes {
            unrevealed.insert(unrevealed_attribute.to_string(), identifier.clone());
        }

        for predicate in &presentation_proof.mapping.predicates {
            predicates.insert(predicate.to_string(), identifier.clone());
        }
    }

    Ok((revealed, unrevealed, predicates))
}

fn build_requested_proof(
    presentation: &W3CPresentation,
    presentation_request: &PresentationRequestPayload,
) -> Result<RequestedProof> {
    let mut requested_proof = RequestedProof::default();

    for (index, credential) in presentation.verifiable_credential.iter().enumerate() {
        let sub_proof_index = index as u32;
        let proof = credential.get_presentation_proof()?;
        for referent in proof.mapping.revealed_attributes.iter() {
            let requested_attribute = presentation_request
                .requested_attributes
                .get(referent)
                .cloned()
                .ok_or_else(|| err_msg!("Requested Attribute {} not found in request", referent))?;

            let name = requested_attribute
                .name
                .ok_or_else(|| err_msg!("Requested Attribute expected to have a name attribute"))?;

            let (_, raw) = credential.get_attribute(&name)?;
            if let CredentialAttributeValue::Attribute(raw) = raw {
                requested_proof.revealed_attrs.insert(
                    referent.clone(),
                    RevealedAttributeInfo {
                        sub_proof_index,
                        raw: raw.to_string(),
                        encoded: "".to_string(), // encoded value not needed
                    },
                );
            }
        }
        for referent in proof.mapping.revealed_attribute_groups.iter() {
            let requested_attribute = presentation_request
                .requested_attributes
                .get(referent)
                .cloned()
                .ok_or_else(|| err_msg!("Requested Attribute {} not found in request", referent))?;
            let names = requested_attribute.names.ok_or_else(|| {
                err_msg!("Requested Attribute expected to have a names attribute")
            })?;
            let mut group_info = RevealedAttributeGroupInfo {
                sub_proof_index,
                values: HashMap::new(),
            };
            for name in names.iter() {
                let (_, raw) = credential.get_attribute(name)?;
                if let CredentialAttributeValue::Attribute(raw) = raw {
                    group_info.values.insert(
                        name.clone(),
                        AttributeValue {
                            raw: raw.to_string(),
                            encoded: "".to_string(),
                        },
                    );
                }
            }
            requested_proof
                .revealed_attr_groups
                .insert(referent.to_string(), group_info);
        }
        for referent in proof.mapping.unrevealed_attributes.iter() {
            requested_proof
                .unrevealed_attrs
                .insert(referent.to_string(), SubProofReferent { sub_proof_index });
        }
        for referent in proof.mapping.predicates.iter() {
            requested_proof
                .predicates
                .insert(referent.to_string(), SubProofReferent { sub_proof_index });
        }
    }
    Ok(requested_proof)
}
