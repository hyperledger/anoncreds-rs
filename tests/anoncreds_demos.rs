use anoncreds::data_types::cred_def::CredentialDefinitionId;
use anoncreds::data_types::rev_reg::RevocationRegistryId;
use anoncreds::data_types::rev_reg_def::RevocationRegistryDefinitionId;
use anoncreds::data_types::schema::SchemaId;
use anoncreds::issuer;
use anoncreds::prover;
use anoncreds::tails::{TailsFileReader, TailsFileWriter};
use anoncreds::types::{CredentialRevocationConfig, PresentCredentials};
use anoncreds::verifier;
use serde_json::json;
use std::{
    collections::{BTreeSet, HashMap},
    fs::create_dir,
};

use utils::*;
mod utils;

#[test]
fn anoncreds_demo_works_for_single_issuer_single_prover() {
    // Create Prover pseudo wallet and link secret
    let mut prover_wallet = ProverWallet::default();

    // Create schema
    let (gvt_schema, gvt_schema_id) = fixtures::create_schema("GVT");

    // Create credential definition
    let ((gvt_cred_def, gvt_cred_def_priv, gvt_cred_key_correctness_proof), gvt_cred_def_id) =
        fixtures::create_cred_def(&gvt_schema, false);

    // Issuer creates a Credential Offer
    let cred_offer = issuer::create_credential_offer(
        gvt_schema_id,
        gvt_cred_def_id,
        &gvt_cred_key_correctness_proof,
    )
    .expect("Error creating credential offer");

    // Prover creates a Credential Request
    let (cred_request, cred_request_metadata) = prover::create_credential_request(
        Some("entropy"),
        None,
        &gvt_cred_def,
        &prover_wallet.link_secret,
        "default",
        &cred_offer,
    )
    .expect("Error creating credential request");

    // Issuer creates a credential
    let cred_values = fixtures::credential_values("GVT");
    let issue_cred = issuer::create_credential(
        &gvt_cred_def,
        &gvt_cred_def_priv,
        &cred_offer,
        &cred_request,
        cred_values.into(),
        None,
        None,
        None,
    )
    .expect("Error creating credential");

    // Prover receives the credential and processes it
    let mut recv_cred = issue_cred;
    prover::process_credential(
        &mut recv_cred,
        &cred_request_metadata,
        &prover_wallet.link_secret,
        &gvt_cred_def,
        None,
    )
    .expect("Error processing credential");
    prover_wallet.credentials.push(recv_cred);

    // Verifier creates a presentation request
    let nonce = verifier::generate_nonce().expect("Error generating presentation request nonce");
    let pres_request = serde_json::from_value(json!({
        "nonce": nonce,
        "name":"pres_req_1",
        "version":"0.1",
        "requested_attributes":{
            "attr1_referent":{
                "name":"name"
            },
            "attr2_referent":{
                "name":"sex"
            },
            "attr3_referent":{"name":"phone"},
            "attr4_referent":{
                "names": ["name", "height"]
            }
        },
        "requested_predicates":{
            "predicate1_referent":{"name":"age","p_type":">=","p_value":18}
        }
    }))
    .expect("Error creating proof request");

    // TODO: show deriving the wallet query from the proof request (need to add helper)

    // Prover creates presentation
    let mut present = PresentCredentials::default();
    {
        let mut cred1 = present.add_credential(&prover_wallet.credentials[0], None, None);
        cred1.add_requested_attribute("attr1_referent", true);
        cred1.add_requested_attribute("attr2_referent", false);
        cred1.add_requested_attribute("attr4_referent", true);
        cred1.add_requested_predicate("predicate1_referent");
    }

    let mut self_attested = HashMap::new();
    let self_attested_phone = "8-800-300";
    self_attested.insert(
        "attr3_referent".to_string(),
        self_attested_phone.to_string(),
    );

    let mut schemas = HashMap::new();
    let gvt_schema_id = SchemaId::new_unchecked(gvt_schema_id);
    schemas.insert(&gvt_schema_id, &gvt_schema);

    let mut cred_defs = HashMap::new();
    let gvt_cred_def_id = CredentialDefinitionId::new_unchecked(gvt_cred_def_id);
    cred_defs.insert(&gvt_cred_def_id, &gvt_cred_def);

    let presentation = prover::create_presentation(
        &pres_request,
        present,
        Some(self_attested),
        &prover_wallet.link_secret,
        &schemas,
        &cred_defs,
    )
    .expect("Error creating presentation");

    // Verifier verifies presentation
    assert_eq!(
        "Alex",
        presentation
            .requested_proof
            .revealed_attrs
            .get("attr1_referent")
            .unwrap()
            .raw
    );

    assert_eq!(
        0,
        presentation
            .requested_proof
            .unrevealed_attrs
            .get("attr2_referent")
            .unwrap()
            .sub_proof_index
    );

    assert_eq!(
        self_attested_phone,
        presentation
            .requested_proof
            .self_attested_attrs
            .get("attr3_referent")
            .unwrap()
    );

    let revealed_attr_groups = presentation
        .requested_proof
        .revealed_attr_groups
        .get("attr4_referent")
        .unwrap();

    assert_eq!("Alex", revealed_attr_groups.values.get("name").unwrap().raw);

    assert_eq!(
        "175",
        revealed_attr_groups.values.get("height").unwrap().raw
    );

    let valid = verifier::verify_presentation(
        &presentation,
        &pres_request,
        &schemas,
        &cred_defs,
        None,
        None,
        None,
    )
    .expect("Error verifying presentation");

    assert!(valid);
}

#[test]
fn anoncreds_demo_works_with_revocation_for_single_issuer_single_prover() {
    // Create Prover pseudo wallet and link secret
    let mut prover_wallet = ProverWallet::default();

    // Create schema
    let (gvt_schema, gvt_schema_id) = fixtures::create_schema("GVT");

    // Create credential definition
    let ((gvt_cred_def, gvt_cred_def_priv, gvt_cred_key_correctness_proof), gvt_cred_def_id) =
        fixtures::create_cred_def(&gvt_schema, true);

    // This will create a tails file locally in the .tmp dir
    let tf_path = "../.tmp";
    create_dir(tf_path)
        .or_else(|e| -> Result<(), std::io::Error> {
            println!(
                "Tail file path creation error but test can still proceed {}",
                e
            );
            Ok(())
        })
        .unwrap();

    let mut tf = TailsFileWriter::new(Some(tf_path.to_owned()));

    let ((gvt_rev_reg_def, gvt_rev_reg_def_priv), gvt_rev_reg_def_id) =
        fixtures::create_rev_reg_def(&gvt_cred_def, &mut tf);

    // Issuer creates reovcation status list - to be put on the ledger
    let time_create_rev_status_list = 12;
    let gvt_revocation_status_list = fixtures::create_revocation_status_list(
        &gvt_rev_reg_def,
        Some(time_create_rev_status_list),
        true,
    );

    // Issuer creates a Credential Offer
    let cred_offer = issuer::create_credential_offer(
        gvt_schema_id,
        gvt_cred_def_id,
        &gvt_cred_key_correctness_proof,
    )
    .expect("Error creating credential offer");

    // Prover creates a Credential Request
    let (cred_request, cred_request_metadata) = prover::create_credential_request(
        Some("entropy"),
        None,
        &gvt_cred_def,
        &prover_wallet.link_secret,
        "default",
        &cred_offer,
    )
    .expect("Error creating credential request");

    // Issuer creates a credential
    let cred_values = fixtures::credential_values("GVT");

    let gvt_rev_reg_def_id = RevocationRegistryDefinitionId::new_unchecked(gvt_rev_reg_def_id);
    let gvt_rev_reg_id = RevocationRegistryId::new_unchecked(gvt_rev_reg_def_id.clone());

    // Get the location of the tails_file so it can be read
    let location = gvt_rev_reg_def.clone().value.tails_location;
    let tr = TailsFileReader::new_tails_reader(location.as_str());

    let issue_cred = issuer::create_credential(
        &gvt_cred_def,
        &gvt_cred_def_priv,
        &cred_offer,
        &cred_request,
        cred_values.into(),
        Some(gvt_rev_reg_id),
        Some(&gvt_revocation_status_list),
        Some(CredentialRevocationConfig {
            reg_def: &gvt_rev_reg_def,
            reg_def_private: &gvt_rev_reg_def_priv,
            registry_idx: fixtures::GVT_REV_IDX,
            tails_reader: tr,
        }),
    )
    .expect("Error creating credential");

    let time_after_creating_cred = time_create_rev_status_list + 1;
    let issued_rev_status_list = issuer::update_revocation_status_list(
        Some(time_after_creating_cred),
        Some(BTreeSet::from([fixtures::GVT_REV_IDX])),
        None,
        &gvt_rev_reg_def,
        &gvt_revocation_status_list,
    )
    .unwrap();

    // Prover receives the credential and processes it
    let mut recv_cred = issue_cred;
    prover::process_credential(
        &mut recv_cred,
        &cred_request_metadata,
        &prover_wallet.link_secret,
        &gvt_cred_def,
        Some(&gvt_rev_reg_def),
    )
    .expect("Error processing credential");
    prover_wallet.credentials.push(recv_cred);

    // Verifier creates a presentation request
    let nonce = verifier::generate_nonce().expect("Error generating presentation request nonce");

    // There are fields for
    // - global non_revoked - i.e. the PresentationRequest level
    // - local non_revoked - i.e. Each Request Attributes (AttributeInfo) and Request Predicate (PredicateInfo) has a field for NonRevoked.
    let pres_request = serde_json::from_value(json!({
        "nonce": nonce,
        "name":"pres_req_1",
        "version":"0.1",
        "requested_attributes":{
            "attr1_referent":{
                "name":"name",
                "issuer_id": GVT_ISSUER_ID
            },
            "attr2_referent":{
                "name":"sex"
            },
            "attr3_referent":{"name":"phone"},
            "attr4_referent":{
                "names": ["name", "height"]
            }
        },
        "requested_predicates":{
            "predicate1_referent":{"name":"age","p_type":">=","p_value":18}
        },
        "non_revoked": {"from": 10, "to": 200}
    }))
    .expect("Error creating proof request");

    let rev_state = prover::create_or_update_revocation_state(
        &gvt_rev_reg_def.value.tails_location,
        &gvt_rev_reg_def,
        &gvt_revocation_status_list,
        fixtures::GVT_REV_IDX,
        None,
        None,
    )
    .unwrap();

    let mut schemas = HashMap::new();
    let gvt_schema_id = SchemaId::new_unchecked(gvt_schema_id);
    schemas.insert(&gvt_schema_id, &gvt_schema);

    let mut cred_defs = HashMap::new();
    let gvt_cred_def_id = CredentialDefinitionId::new_unchecked(gvt_cred_def_id);
    cred_defs.insert(&gvt_cred_def_id, &gvt_cred_def);

    let mut rev_status_list = vec![&issued_rev_status_list];

    // Prover creates presentation
    let presentation = fixtures::create_presentation(
        &schemas,
        &cred_defs,
        &pres_request,
        &prover_wallet,
        Some(time_after_creating_cred),
        Some(&rev_state),
    );

    // Verifier verifies presentation of not Revoked rev_state
    let rev_reg_def_map = HashMap::from([(&gvt_rev_reg_def_id, &gvt_rev_reg_def)]);
    let valid = verifier::verify_presentation(
        &presentation,
        &pres_request,
        &schemas,
        &cred_defs,
        Some(&rev_reg_def_map),
        Some(rev_status_list.clone()),
        None,
    )
    .expect("Error verifying presentation");
    assert!(valid);

    //  ===================== Issuer revokes credential ================
    let time_revoke_cred = time_after_creating_cred + 1;
    let revoked_status_list = issuer::update_revocation_status_list(
        Some(time_revoke_cred),
        None,
        Some(BTreeSet::from([fixtures::GVT_REV_IDX])),
        &gvt_rev_reg_def,
        &issued_rev_status_list,
    )
    .unwrap();

    // update rev_status_lists
    rev_status_list.push(&revoked_status_list);

    let rev_state = prover::create_or_update_revocation_state(
        &gvt_rev_reg_def.value.tails_location,
        &gvt_rev_reg_def,
        &gvt_revocation_status_list,
        fixtures::GVT_REV_IDX,
        Some(&rev_state),
        Some(&issued_rev_status_list),
    )
    .unwrap();

    // Prover creates presentation
    let presentation = fixtures::create_presentation(
        &schemas,
        &cred_defs,
        &pres_request,
        &prover_wallet,
        Some(time_revoke_cred),
        Some(&rev_state),
    );

    let valid = verifier::verify_presentation(
        &presentation,
        &pres_request,
        &schemas,
        &cred_defs,
        Some(&rev_reg_def_map),
        Some(rev_status_list),
        None,
    )
    .expect("Error verifying presentation");
    assert!(!valid);
}

#[test]
fn anoncreds_demo_works_for_multiple_issuer_single_prover() {
    let mut prover_wallet = ProverWallet::default();

    // Issuer 1 creates Schema - would be published to the ledger
    let (gvt_schema, gvt_schema_id) = fixtures::create_schema("GVT");

    // Issuer 1 create credential definition
    let ((gvt_cred_def, gvt_cred_def_priv, gvt_cred_key_correctness_proof), gvt_cred_def_id) =
        fixtures::create_cred_def(&gvt_schema, false);

    // Issuer 2 creates Schema - would be published to the ledger
    let (emp_schema, emp_schema_id) = fixtures::create_schema("EMP");

    // Issuer 1 create credential definition
    let ((emp_cred_def, emp_cred_def_priv, emp_cred_key_correctness_proof), emp_cred_def_id) =
        fixtures::create_cred_def(&emp_schema, false);

    let gvt_cred_offer = issuer::create_credential_offer(
        gvt_schema_id,
        gvt_cred_def_id,
        &gvt_cred_key_correctness_proof,
    )
    .expect("Unable to create credential offer");

    let (gvt_cred_request, gvt_cred_request_metadata) = prover::create_credential_request(
        Some("entropy"),
        None,
        &gvt_cred_def,
        &prover_wallet.link_secret,
        "default",
        &gvt_cred_offer,
    )
    .expect("Error creating credential request");

    // Issuer creates a credential
    let gvt_cred_values = fixtures::credential_values("GVT");

    let gvt_issue_cred = issuer::create_credential(
        &gvt_cred_def,
        &gvt_cred_def_priv,
        &gvt_cred_offer,
        &gvt_cred_request,
        gvt_cred_values.into(),
        None,
        None,
        None,
    )
    .expect("Error creating credential");

    let mut gvt_recv_cred = gvt_issue_cred;
    prover::process_credential(
        &mut gvt_recv_cred,
        &gvt_cred_request_metadata,
        &prover_wallet.link_secret,
        &gvt_cred_def,
        None,
    )
    .expect("Error processing credential");
    prover_wallet.credentials.push(gvt_recv_cred);

    let emp_cred_offer = issuer::create_credential_offer(
        emp_schema_id,
        emp_cred_def_id,
        &emp_cred_key_correctness_proof,
    )
    .expect("Unable to create credential offer");

    let (emp_cred_request, emp_cred_request_metadata) = prover::create_credential_request(
        Some("entropy"),
        None,
        &emp_cred_def,
        &prover_wallet.link_secret,
        "default",
        &emp_cred_offer,
    )
    .expect("Error creating credential request");

    let emp_cred_values = fixtures::credential_values("EMP");

    let emp_issue_cred = issuer::create_credential(
        &emp_cred_def,
        &emp_cred_def_priv,
        &emp_cred_offer,
        &emp_cred_request,
        emp_cred_values.into(),
        None,
        None,
        None,
    )
    .expect("Error creating credential");

    let mut emp_recv_cred = emp_issue_cred;
    prover::process_credential(
        &mut emp_recv_cred,
        &emp_cred_request_metadata,
        &prover_wallet.link_secret,
        &emp_cred_def,
        None,
    )
    .expect("Error processing credential");
    prover_wallet.credentials.push(emp_recv_cred);

    let nonce = verifier::generate_nonce().expect("Error generating presentation request nonce");

    //9. Proof request
    let pres_request = serde_json::from_value(json!({
        "nonce": nonce,
        "name":"proof_req_1",
        "version":"0.1",
        "requested_attributes": {
            "attr1_referent": {
                "name":"name",
                "restrictions": { "cred_def_id": gvt_cred_def_id, "attr::name::value": "Alex" }
            }   ,
            "attr2_referent": {
                "name":"role",
                "restrictions": { "cred_def_id": emp_cred_def_id }
            },
            "attr3_referent": {
                "name": "height",
                "restrictions": { "cred_def_id": gvt_cred_def_id, "attr::height::value": "175" },
            }
        },
        "requested_predicates": {
            "predicate1_referent": {
                "name":"age", "p_type":">=", "p_value":18,
                "restrictions": { "cred_def_id": gvt_cred_def_id, "attr::name::value": "Alex", "attr::height::value": "175" }
                },
        },
    }))
    .expect("Error creating proof request");

    let mut schemas = HashMap::new();
    let gvt_schema_id = SchemaId::new_unchecked(gvt_schema_id);
    let emp_schema_id = SchemaId::new_unchecked(emp_schema_id);
    schemas.insert(&gvt_schema_id, &gvt_schema);
    schemas.insert(&emp_schema_id, &emp_schema);

    let mut cred_defs = HashMap::new();
    let gvt_cred_def_id = CredentialDefinitionId::new_unchecked(gvt_cred_def_id);
    let emp_cred_def_id = CredentialDefinitionId::new_unchecked(emp_cred_def_id);
    cred_defs.insert(&gvt_cred_def_id, &gvt_cred_def);
    cred_defs.insert(&emp_cred_def_id, &emp_cred_def);

    let mut present = PresentCredentials::default();
    let mut gvt_cred = present.add_credential(&prover_wallet.credentials[0], None, None);
    gvt_cred.add_requested_attribute("attr1_referent", true);
    gvt_cred.add_requested_attribute("attr3_referent", true);
    gvt_cred.add_requested_predicate("predicate1_referent");

    let mut emp_cred = present.add_credential(&prover_wallet.credentials[1], None, None);
    emp_cred.add_requested_attribute("attr2_referent", true);

    let presentation = prover::create_presentation(
        &pres_request,
        present,
        None,
        &prover_wallet.link_secret,
        &schemas,
        &cred_defs,
    )
    .expect("Error creating presentation");

    let valid = verifier::verify_presentation(
        &presentation,
        &pres_request,
        &schemas,
        &cred_defs,
        None,
        None,
        None,
    )
    .expect("Error verifying presentation");
    assert!(valid);
}

#[test]
fn anoncreds_demo_proof_does_not_verify_with_wrong_attr_and_predicates() {
    // Create Prover pseudo wallet and link secret
    let mut prover_wallet = ProverWallet::default();

    // Create schema
    let (gvt_schema, gvt_schema_id) = fixtures::create_schema("GVT");

    // Create credential definition
    let ((gvt_cred_def, gvt_cred_def_priv, gvt_cred_key_correctness_proof), gvt_cred_def_id) =
        fixtures::create_cred_def(&gvt_schema, false);

    // Issuer creates a Credential Offer
    let cred_offer = issuer::create_credential_offer(
        gvt_schema_id,
        gvt_cred_def_id,
        &gvt_cred_key_correctness_proof,
    )
    .expect("Error creating credential offer");

    // Prover creates a Credential Request
    let (cred_request, cred_request_metadata) = prover::create_credential_request(
        Some("entropy"),
        None,
        &gvt_cred_def,
        &prover_wallet.link_secret,
        "default",
        &cred_offer,
    )
    .expect("Error creating credential request");

    // Issuer creates a credential
    let cred_values = fixtures::credential_values("GVT");
    let issue_cred = issuer::create_credential(
        &gvt_cred_def,
        &gvt_cred_def_priv,
        &cred_offer,
        &cred_request,
        cred_values.into(),
        None,
        None,
        None,
    )
    .expect("Error creating credential");

    // Prover receives the credential and processes it
    let mut recv_cred = issue_cred;
    prover::process_credential(
        &mut recv_cred,
        &cred_request_metadata,
        &prover_wallet.link_secret,
        &gvt_cred_def,
        None,
    )
    .expect("Error processing credential");
    prover_wallet.credentials.push(recv_cred);

    // Verifier creates a presentation request
    let nonce = verifier::generate_nonce().expect("Error generating presentation request nonce");
    let pres_request = serde_json::from_value(json!({
        "nonce": nonce,
        "name":"pres_req_1",
        "version":"0.1",
        "requested_attributes":{
            "attr1_referent":{
                "name":"name"
            },
            "attr2_referent":{
                "name":"sex"
            },
            "attr3_referent":{"name":"phone"},
            "attr4_referent":{
                "names": ["name", "height"]
            }
        },
        "requested_predicates":{
            "predicate1_referent":{"name":"age","p_type":">=","p_value":18}
        }
    }))
    .expect("Error creating proof request");

    // Prover creates presentation
    let mut present = PresentCredentials::default();
    {
        // We do not add `attr2_referent` here
        let mut cred1 = present.add_credential(&prover_wallet.credentials[0], None, None);
        cred1.add_requested_attribute("attr1_referent", true);
        cred1.add_requested_attribute("attr4_referent", true);
        cred1.add_requested_predicate("predicate1_referent");
    }

    let mut self_attested = HashMap::new();
    let self_attested_phone = "8-800-300";
    self_attested.insert(
        "attr3_referent".to_string(),
        self_attested_phone.to_string(),
    );

    let mut schemas = HashMap::new();
    let gvt_schema_id = SchemaId::new_unchecked(gvt_schema_id);
    schemas.insert(&gvt_schema_id, &gvt_schema);

    let mut cred_defs = HashMap::new();
    let gvt_cred_def_id = CredentialDefinitionId::new_unchecked(gvt_cred_def_id);
    cred_defs.insert(&gvt_cred_def_id, &gvt_cred_def);

    let presentation = prover::create_presentation(
        &pres_request,
        present,
        Some(self_attested),
        &prover_wallet.link_secret,
        &schemas,
        &cred_defs,
    )
    .expect("Error creating presentation");

    let valid = verifier::verify_presentation(
        &presentation,
        &pres_request,
        &schemas,
        &cred_defs,
        None,
        None,
        None,
    );

    assert!(valid.is_err())
}

#[test]
fn anoncreds_demo_works_for_requested_attribute_in_upper_case() {
    // Create Prover pseudo wallet and link secret
    let mut prover_wallet = ProverWallet::default();

    // Create schema
    let (gvt_schema, gvt_schema_id) = fixtures::create_schema("GVT");

    // Create credential definition
    let ((gvt_cred_def, gvt_cred_def_priv, gvt_cred_key_correctness_proof), gvt_cred_def_id) =
        fixtures::create_cred_def(&gvt_schema, false);

    // Issuer creates a Credential Offer
    let cred_offer = issuer::create_credential_offer(
        gvt_schema_id,
        gvt_cred_def_id,
        &gvt_cred_key_correctness_proof,
    )
    .expect("Error creating credential offer");

    // Prover creates a Credential Request
    let (cred_request, cred_request_metadata) = prover::create_credential_request(
        Some("entropy"),
        None,
        &gvt_cred_def,
        &prover_wallet.link_secret,
        "default",
        &cred_offer,
    )
    .expect("Error creating credential request");

    // Issuer creates a credential
    let cred_values = fixtures::credential_values("GVT");
    let issue_cred = issuer::create_credential(
        &gvt_cred_def,
        &gvt_cred_def_priv,
        &cred_offer,
        &cred_request,
        cred_values.into(),
        None,
        None,
        None,
    )
    .expect("Error creating credential");

    // Prover receives the credential and processes it
    let mut recv_cred = issue_cred;
    prover::process_credential(
        &mut recv_cred,
        &cred_request_metadata,
        &prover_wallet.link_secret,
        &gvt_cred_def,
        None,
    )
    .expect("Error processing credential");
    prover_wallet.credentials.push(recv_cred);

    // Verifier creates a presentation request
    let nonce = verifier::generate_nonce().expect("Error generating presentation request nonce");
    let pres_request = serde_json::from_value(json!({
        "nonce": nonce,
        "name":"pres_req_1",
        "version":"0.1",
        "requested_attributes":{
            "attr1_referent":{
                "name":"NAME"
            },
            "attr2_referent":{
                "name":"SEX"
            },
            "attr3_referent":{"name":"phone"},
            "attr4_referent":{
                "names": ["NAME", "HEIGHT"]
            }
        },
        "requested_predicates":{
            "predicate1_referent":{"name":"age","p_type":">=","p_value":18}
        }
    }))
    .expect("Error creating proof request");

    // Prover creates presentation
    let mut present = PresentCredentials::default();
    {
        let mut cred1 = present.add_credential(&prover_wallet.credentials[0], None, None);
        cred1.add_requested_attribute("attr1_referent", true);
        cred1.add_requested_attribute("attr2_referent", false);
        cred1.add_requested_attribute("attr4_referent", true);
        cred1.add_requested_predicate("predicate1_referent");
    }

    let mut self_attested = HashMap::new();
    let self_attested_phone = "8-800-300";
    self_attested.insert(
        "attr3_referent".to_string(),
        self_attested_phone.to_string(),
    );

    let mut schemas = HashMap::new();
    let gvt_schema_id = SchemaId::new_unchecked(gvt_schema_id);
    schemas.insert(&gvt_schema_id, &gvt_schema);

    let mut cred_defs = HashMap::new();
    let gvt_cred_def_id = CredentialDefinitionId::new_unchecked(gvt_cred_def_id);
    cred_defs.insert(&gvt_cred_def_id, &gvt_cred_def);

    let presentation = prover::create_presentation(
        &pres_request,
        present,
        Some(self_attested),
        &prover_wallet.link_secret,
        &schemas,
        &cred_defs,
    )
    .expect("Error creating presentation");

    // Verifier verifies presentation
    assert_eq!(
        "Alex",
        presentation
            .requested_proof
            .revealed_attrs
            .get("attr1_referent")
            .unwrap()
            .raw
    );

    assert_eq!(
        0,
        presentation
            .requested_proof
            .unrevealed_attrs
            .get("attr2_referent")
            .unwrap()
            .sub_proof_index
    );

    assert_eq!(
        self_attested_phone,
        presentation
            .requested_proof
            .self_attested_attrs
            .get("attr3_referent")
            .unwrap()
    );

    let revealed_attr_groups = presentation
        .requested_proof
        .revealed_attr_groups
        .get("attr4_referent")
        .unwrap();

    assert_eq!("Alex", revealed_attr_groups.values.get("NAME").unwrap().raw);

    assert_eq!(
        "175",
        revealed_attr_groups.values.get("HEIGHT").unwrap().raw
    );

    let valid = verifier::verify_presentation(
        &presentation,
        &pres_request,
        &schemas,
        &cred_defs,
        None,
        None,
        None,
    )
    .expect("Error verifying presentation");

    assert!(valid);
}

#[test]
fn anoncreds_demo_works_for_twice_entry_of_attribute_from_different_credential() {
    let mut prover_wallet = ProverWallet::default();

    // Issuer 1 creates Schema - would be published to the ledger
    let (gvt_schema, gvt_schema_id) = fixtures::create_schema("GVT");

    // Issuer 1 create credential definition
    let ((gvt_cred_def, gvt_cred_def_priv, gvt_cred_key_correctness_proof), gvt_cred_def_id) =
        fixtures::create_cred_def(&gvt_schema, false);

    // Issuer 2 creates Schema - would be published to the ledger
    let (emp_schema, emp_schema_id) = fixtures::create_schema("EMP");

    // Issuer 1 create credential definition
    let ((emp_cred_def, emp_cred_def_priv, emp_cred_key_correctness_proof), emp_cred_def_id) =
        fixtures::create_cred_def(&emp_schema, false);

    let gvt_cred_offer = issuer::create_credential_offer(
        gvt_schema_id,
        gvt_cred_def_id,
        &gvt_cred_key_correctness_proof,
    )
    .expect("Unable to create credential offer");

    let (gvt_cred_request, gvt_cred_request_metadata) = prover::create_credential_request(
        Some("entropy"),
        None,
        &gvt_cred_def,
        &prover_wallet.link_secret,
        "default",
        &gvt_cred_offer,
    )
    .expect("Error creating credential request");

    // Issuer creates a credential
    let gvt_cred_values = fixtures::credential_values("GVT");

    let gvt_issue_cred = issuer::create_credential(
        &gvt_cred_def,
        &gvt_cred_def_priv,
        &gvt_cred_offer,
        &gvt_cred_request,
        gvt_cred_values.into(),
        None,
        None,
        None,
    )
    .expect("Error creating credential");

    let mut gvt_recv_cred = gvt_issue_cred;
    prover::process_credential(
        &mut gvt_recv_cred,
        &gvt_cred_request_metadata,
        &prover_wallet.link_secret,
        &gvt_cred_def,
        None,
    )
    .expect("Error processing credential");
    prover_wallet.credentials.push(gvt_recv_cred);

    let emp_cred_offer = issuer::create_credential_offer(
        emp_schema_id,
        emp_cred_def_id,
        &emp_cred_key_correctness_proof,
    )
    .expect("Unable to create credential offer");

    let (emp_cred_request, emp_cred_request_metadata) = prover::create_credential_request(
        Some("entropy"),
        None,
        &emp_cred_def,
        &prover_wallet.link_secret,
        "default",
        &emp_cred_offer,
    )
    .expect("Error creating credential request");

    let emp_cred_values = fixtures::credential_values("EMP");

    let emp_issue_cred = issuer::create_credential(
        &emp_cred_def,
        &emp_cred_def_priv,
        &emp_cred_offer,
        &emp_cred_request,
        emp_cred_values.into(),
        None,
        None,
        None,
    )
    .expect("Error creating credential");

    let mut emp_recv_cred = emp_issue_cred;
    prover::process_credential(
        &mut emp_recv_cred,
        &emp_cred_request_metadata,
        &prover_wallet.link_secret,
        &emp_cred_def,
        None,
    )
    .expect("Error processing credential");
    prover_wallet.credentials.push(emp_recv_cred);

    let nonce = verifier::generate_nonce().expect("Error generating presentation request nonce");

    //9. Proof request
    let pres_request = serde_json::from_value(json!({
        "nonce": nonce,
        "name":"proof_req_1",
        "version":"0.1",
        "requested_attributes": {
            "attr1_referent": {
                "name":"name",
                "restrictions": { "cred_def_id": gvt_cred_def_id, "attr::name::value": "Alex" }
            }   ,
            "attr2_referent": {
                "name":"role",
                "restrictions": { "cred_def_id": emp_cred_def_id }
            },
            "attr3_referent": {
                "name":"name",
                "restrictions": { "cred_def_id": emp_cred_def_id }
            },
            "attr4_referent": {
                "name": "height",
                "restrictions": { "cred_def_id": gvt_cred_def_id, "attr::height::value": "175" },
            }
        },
        "requested_predicates": {
            "predicate1_referent": {
                "name":"age", "p_type":">=", "p_value":18,
                "restrictions": { "cred_def_id": gvt_cred_def_id, "attr::name::value": "Alex", "attr::height::value": "175" }
                },
        },
    }))
    .expect("Error creating proof request");

    let mut schemas = HashMap::new();
    let gvt_schema_id = SchemaId::new_unchecked(gvt_schema_id);
    let emp_schema_id = SchemaId::new_unchecked(emp_schema_id);
    schemas.insert(&gvt_schema_id, &gvt_schema);
    schemas.insert(&emp_schema_id, &emp_schema);

    let mut cred_defs = HashMap::new();
    let gvt_cred_def_id = CredentialDefinitionId::new_unchecked(gvt_cred_def_id);
    let emp_cred_def_id = CredentialDefinitionId::new_unchecked(emp_cred_def_id);
    cred_defs.insert(&gvt_cred_def_id, &gvt_cred_def);
    cred_defs.insert(&emp_cred_def_id, &emp_cred_def);

    let mut present = PresentCredentials::default();
    let mut gvt_cred = present.add_credential(&prover_wallet.credentials[0], None, None);
    gvt_cred.add_requested_attribute("attr1_referent", true);
    gvt_cred.add_requested_attribute("attr4_referent", true);
    gvt_cred.add_requested_predicate("predicate1_referent");

    let mut emp_cred = present.add_credential(&prover_wallet.credentials[1], None, None);
    emp_cred.add_requested_attribute("attr2_referent", true);
    emp_cred.add_requested_attribute("attr3_referent", true);

    let presentation = prover::create_presentation(
        &pres_request,
        present,
        None,
        &prover_wallet.link_secret,
        &schemas,
        &cred_defs,
    )
    .expect("Error creating presentation");

    let valid = verifier::verify_presentation(
        &presentation,
        &pres_request,
        &schemas,
        &cred_defs,
        None,
        None,
        None,
    )
    .expect("Error verifying presentation");
    assert!(valid);
}

/*
#[test]
fn anoncreds_works_for_twice_entry_of_credential_for_different_witness() {
    Setup::empty();

    // Issuer creates wallet, gets wallet handle
    let (issuer_wallet_handle, issuer_wallet_config) = wallet::create_and_open_default_wallet(
        "anoncreds_works_for_twice_entry_of_credential_for_different_witness",
    )
    .unwrap();

    // Prover1 creates wallet, gets wallet handle
    let (prover1_wallet_handle, prover1_wallet_config) = wallet::create_and_open_default_wallet(
        "anoncreds_works_for_twice_entry_of_credential_for_different_witness",
    )
    .unwrap();

    // Prover2 creates wallet, gets wallet handle
    let (prover2_wallet_handle, prover2_wallet_config) = wallet::create_and_open_default_wallet(
        "anoncreds_works_for_twice_entry_of_credential_for_different_witness",
    )
    .unwrap();

    // Issuer creates Schema, Credential Definition and Revocation Registry
    let (
        schema_id,
        schema_json,
        cred_def_id,
        cred_def_json,
        rev_reg_id,
        revoc_reg_def_json,
        _,
        blob_storage_reader_handle,
    ) = anoncreds::multi_steps_issuer_revocation_preparation(
        issuer_wallet_handle,
        ISSUER_DID,
        GVT_SCHEMA_NAME,
        GVT_SCHEMA_ATTRIBUTES,
        r#"{"max_cred_num":5, "issuance_type":"ISSUANCE_ON_DEMAND"}"#,
    );

    // ISSUANCE CREDENTIAL FOR PROVER1

    // Prover1 creates Link Secret
    let prover1_link_secret_id = "prover1_link_secret";
    anoncreds::prover_create_link_secret(prover1_wallet_handle, prover1_link_secret_id)
        .unwrap();

    let timestamp1 = time::get_time().sec as u64;

    let (prover1_cred_rev_id, revoc_reg_delta1_json) =
        anoncreds::multi_steps_create_revocation_credential(
            prover1_link_secret_id,
            prover1_wallet_handle,
            issuer_wallet_handle,
            CREDENTIAL1_ID,
            &anoncreds::gvt_credential_values_json(),
            &cred_def_id,
            &cred_def_json,
            &rev_reg_id,
            &revoc_reg_def_json,
            blob_storage_reader_handle,
        );
    let revoc_reg_delta1_json = revoc_reg_delta1_json.unwrap();

    // ISSUANCE CREDENTIAL FOR PROVER2
    // Prover2 creates Link Secret
    let prover2_link_secret_id = "prover2_link_secret";
    anoncreds::prover_create_link_secret(prover2_wallet_handle, prover2_link_secret_id)
        .unwrap();

    let timestamp2 = time::get_time().sec as u64 + 100;

    let (_, revoc_reg_delta2_json) = anoncreds::multi_steps_create_revocation_credential(
        prover2_link_secret_id,
        prover2_wallet_handle,
        issuer_wallet_handle,
        CREDENTIAL2_ID,
        &anoncreds::gvt2_credential_values_json(),
        &cred_def_id,
        &cred_def_json,
        &rev_reg_id,
        &revoc_reg_def_json,
        blob_storage_reader_handle,
    );
    let revoc_reg_delta2_json = revoc_reg_delta2_json.unwrap();

    // Issuer merge Revocation Registry Deltas
    let revoc_reg_delta_json = anoncreds::issuer_merge_revocation_registry_deltas(
        &revoc_reg_delta1_json,
        &revoc_reg_delta2_json,
    )
    .unwrap();

    //PROVER1 PROVING REQUEST
    let proof_request = json!({
        "nonce":"123432421212",
        "name":"proof_req_1",
        "version":"0.1",
        "requested_attributes": json!({
            "attr1_referent": json!({
                "name":"name",
                "non_revoked": json!({ "to":timestamp1 + 1 })
            }),
            "attr2_referent": json!({
                "name":"name",
                "non_revoked": json!({  "from":timestamp1, "to":timestamp2 + 1 })
            })
        }),
        "requested_predicates": json!({
            "predicate1_referent": json!({ "name":"age", "p_type":">=", "p_value":18 })
        }),
        "non_revoked": json!({ "from":timestamp1, "to":timestamp2 })
    })
    .to_string();

    // Prover1 gets Credentials for Proof Request
    let prover1_credentials_json =
        anoncreds::prover_get_credentials_for_proof_req(prover1_wallet_handle, &proof_request)
            .unwrap();
    let credentials: CredentialsForProofRequest =
        serde_json::from_str(&prover1_credentials_json).unwrap();

    let prover1_credential = credentials.attrs.get("attr1_referent").unwrap()[0].clone();
    let prover2_credential = credentials.attrs.get("attr2_referent").unwrap()[0].clone();

    assert_ne!(prover1_credential.interval, prover2_credential.interval);

    // Prover1 creates RevocationState for Timestamp 1
    let prover1_rev_state_1_json = anoncreds::create_revocation_state(
        blob_storage_reader_handle,
        &revoc_reg_def_json,
        &revoc_reg_delta1_json,
        timestamp1,
        &prover1_cred_rev_id,
    )
    .unwrap();

    // Prover1 creates RevocationState for Timestamp 2
    let prover1_rev_state_2_json = anoncreds::update_revocation_state(
        blob_storage_reader_handle,
        &prover1_rev_state_1_json,
        &revoc_reg_def_json,
        &revoc_reg_delta_json,
        timestamp2,
        &prover1_cred_rev_id,
    )
    .unwrap();

    // Prover1 creates Proof
    let requested_credentials_json = json!({
            "self_attested_attributes": json!({}),
            "requested_attributes": json!({
            "attr1_referent": json!({ "cred_id": prover1_credential.cred_info.referent, "timestamp": timestamp1, "revealed":true }),
            "attr2_referent": json!({ "cred_id": prover2_credential.cred_info.referent, "timestamp": timestamp2, "revealed":true })
            }),
            "requested_predicates": json!({
            "predicate1_referent": json!({ "cred_id": prover2_credential.cred_info.referent, "timestamp": timestamp2 })
            })
    }).to_string();

    let schemas_json = json!({
        schema_id.clone(): serde_json::from_str::<Schema>(&schema_json).unwrap()
    })
    .to_string();

    let credential_defs_json = json!({
        cred_def_id.clone(): serde_json::from_str::<CredentialDefinition>(&cred_def_json).unwrap()
    })
    .to_string();

    let rev_states_json = json!({
        rev_reg_id.clone(): json!({
            timestamp1.to_string(): serde_json::from_str::<RevocationState>(&prover1_rev_state_1_json).unwrap(),
            timestamp2.to_string(): serde_json::from_str::<RevocationState>(&prover1_rev_state_2_json).unwrap()
        })
    }).to_string();

    let proof1_json = anoncreds::prover_create_proof(
        prover1_wallet_handle,
        &proof_request,
        &requested_credentials_json,
        prover1_link_secret_id,
        &schemas_json,
        &credential_defs_json,
        &rev_states_json,
    )
    .unwrap();

    // Verifier verifies proof from Prover1
    let proof: Proof = serde_json::from_str(&proof1_json).unwrap();
    assert_eq!(2, proof.requested_proof.revealed_attrs.len());
    assert_eq!(2, proof.identifiers.len());

    assert_eq!(
        "Alex",
        proof
            .requested_proof
            .revealed_attrs
            .get("attr1_referent")
            .unwrap()
            .raw
    );
    assert_eq!(
        "Alex",
        proof
            .requested_proof
            .revealed_attrs
            .get("attr2_referent")
            .unwrap()
            .raw
    );

    let rev_reg_defs_json = json!({
        rev_reg_id.clone(): serde_json::from_str::<RevocationRegistryDefinition>(&revoc_reg_def_json).unwrap()
    }).to_string();

    let rev_regs_json = json!({
        rev_reg_id.clone(): json!({
            timestamp1.to_string(): serde_json::from_str::<RevocationRegistry>(&revoc_reg_delta1_json).unwrap(),
            timestamp2.to_string(): serde_json::from_str::<RevocationRegistry>(&revoc_reg_delta_json).unwrap()
        })
    }).to_string();

    let valid = anoncreds::verifier_verify_proof(
        &proof_request,
        &proof1_json,
        &schemas_json,
        &credential_defs_json,
        &rev_reg_defs_json,
        &rev_regs_json,
    )
    .unwrap();
    assert!(valid);

    wallet::close_and_delete_wallet(issuer_wallet_handle, &issuer_wallet_config).unwrap();
    wallet::close_and_delete_wallet(prover1_wallet_handle, &prover1_wallet_config).unwrap();
    wallet::close_and_delete_wallet(prover2_wallet_handle, &prover2_wallet_config).unwrap();
}

#[test]
#[ignore] //FIXME
fn anoncreds_works_for_misused_witness() {
    //???
    // ignore requested timestamp in proof request
    // - provide valid proof for invalid time
    // - provide hacked proof: specify requested timestamp, actually use invalid TS
    unimplemented!();
}

#[test]
fn anoncreds_works_for_multiple_requested_predicates_from_one_credential() {
    Setup::empty();

    //1. Create Issuer wallet, gets wallet handle
    let (issuer_wallet_handle, issuer_wallet_config) = wallet::create_and_open_default_wallet(
        "anoncreds_works_for_multiple_requested_predicates_from_one_credential",
    )
    .unwrap();

    //2. Create Prover wallet, gets wallet handle
    let (prover_wallet_handle, prover_wallet_config) = wallet::create_and_open_default_wallet(
        "anoncreds_works_for_multiple_requested_predicates_from_one_credential",
    )
    .unwrap();

    //3. Issuer creates Schema and Credential Definition
    let attr_names = r#"["task1",
                                "task2",
                                "task3",
                                "task4",
                                "task5",
                                "6*_task",
                                "7*_task",
                                "bonus",
                                "average",
                                "aggregated",
                                "total"]"#;
    let (schema_id, schema_json, cred_def_id, cred_def_json) =
        anoncreds::multi_steps_issuer_preparation(
            issuer_wallet_handle,
            ISSUER_DID,
            "test",
            attr_names,
        );

    //4. Prover creates Link Secret
    anoncreds::prover_create_link_secret(prover_wallet_handle, COMMON_LINK_SECRET).unwrap();

    //5. Issuance credential for Prover
    let cred_values = r#"{
        "task1": {"raw":"8", "encoded": "8"},
        "task2": {"raw":"8", "encoded": "8"},
        "task3": {"raw":"10", "encoded": "10"},
        "task4": {"raw":"9", "encoded": "9"},
        "task5": {"raw":"7", "encoded": "7"},
        "6*_task": {"raw":"8", "encoded": "8"},
        "7*_task": {"raw":"9", "encoded": "9"},
        "bonus": {"raw":"5", "encoded": "5"},
        "average": {"raw":"9", "encoded": "9"},
        "aggregated": {"raw":"9", "encoded": "9"},
        "total": {"raw":"77", "encoded": "77"}
    }"#;

    anoncreds::multi_steps_create_credential(
        COMMON_LINK_SECRET,
        prover_wallet_handle,
        issuer_wallet_handle,
        CREDENTIAL1_ID,
        cred_values,
        &cred_def_id,
        &cred_def_json,
    );

    //6. Proof request
    let proof_req_json = r#"{
                                    "nonce":"123432421212",
                                    "name":"proof_req_1",
                                    "version":"0.1",
                                    "requested_attributes":{},
                                    "requested_predicates":{
                                        "predicate1_referent":{"name":"task1","p_type":">=","p_value":5},
                                        "predicate2_referent":{"name":"task2","p_type":">=","p_value":7},
                                        "predicate3_referent":{"name":"task3","p_type":">=","p_value":7},
                                        "predicate4_referent":{"name":"task4","p_type":">=","p_value":8},
                                        "predicate5_referent":{"name":"task5","p_type":">=","p_value":5},
                                        "predicate6_referent":{"name":"6*_task","p_type":">=","p_value":7},
                                        "predicate7_referent":{"name":"7*_task","p_type":">=","p_value":7},
                                        "predicate8_referent":{"name":"bonus","p_type":">=","p_value":3},
                                        "predicate9_referent":{"name":"average","p_type":">=","p_value":8},
                                        "predicate10_referent":{"name":"aggregated","p_type":">=","p_value":7},
                                        "predicate11_referent":{"name":"total","p_type":">=","p_value":70}
                                    }
                                }"#;

    //7. Prover gets Credentials for Proof Request
    let credentials_json =
        anoncreds::prover_get_credentials_for_proof_req(prover_wallet_handle, &proof_req_json)
            .unwrap();
    let credential =
        anoncreds::get_credential_for_predicate_referent(&credentials_json, "predicate1_referent");

    //8. Prover creates Proof
    let requested_credentials_json = format!(
        r#"{{
                                                "self_attested_attributes":{{}},
                                                "requested_attributes":{{}},
                                                "requested_predicates":{{
                                                    "predicate1_referent":{{ "cred_id":"{}" }},
                                                    "predicate2_referent":{{ "cred_id":"{}" }},
                                                    "predicate3_referent":{{ "cred_id":"{}" }},
                                                    "predicate4_referent":{{ "cred_id":"{}" }},
                                                    "predicate5_referent":{{ "cred_id":"{}" }},
                                                    "predicate6_referent":{{ "cred_id":"{}" }},
                                                    "predicate7_referent":{{ "cred_id":"{}" }},
                                                    "predicate8_referent":{{ "cred_id":"{}" }},
                                                    "predicate9_referent":{{ "cred_id":"{}" }},
                                                    "predicate10_referent":{{ "cred_id":"{}" }},
                                                    "predicate11_referent":{{ "cred_id":"{}" }}
                                                }}
                                            }}"#,
        credential.referent,
        credential.referent,
        credential.referent,
        credential.referent,
        credential.referent,
        credential.referent,
        credential.referent,
        credential.referent,
        credential.referent,
        credential.referent,
        credential.referent
    );

    let schemas_json =
        json!({schema_id: serde_json::from_str::<Schema>(&schema_json).unwrap()}).to_string();
    let cred_defs_json =
        json!({cred_def_id: serde_json::from_str::<CredentialDefinition>(&cred_def_json).unwrap()})
            .to_string();
    let rev_states_json = json!({}).to_string();

    let proof_json = anoncreds::prover_create_proof(
        prover_wallet_handle,
        &proof_req_json,
        &requested_credentials_json,
        COMMON_LINK_SECRET,
        &schemas_json,
        &cred_defs_json,
        &rev_states_json,
    )
    .unwrap();

    let _proof: Proof = serde_json::from_str(&proof_json).unwrap();

    //9. Verifier verifies proof
    let rev_reg_defs_json = json!({}).to_string();
    let rev_regs_json = json!({}).to_string();

    let valid = anoncreds::verifier_verify_proof(
        &proof_req_json,
        &proof_json,
        &schemas_json,
        &cred_defs_json,
        &rev_reg_defs_json,
        &rev_regs_json,
    )
    .unwrap();
    assert!(valid);

    wallet::close_and_delete_wallet(issuer_wallet_handle, &issuer_wallet_config).unwrap();
    wallet::close_and_delete_wallet(prover_wallet_handle, &prover_wallet_config).unwrap();
}

// #[test]
// fn anoncreds_works_for_cred_def_rotation() {
//     Setup::empty();

//     //1. Create Issuer wallet, gets wallet handle
//     let (issuer_wallet_handle, issuer_wallet_config) =
//         wallet::create_and_open_default_wallet("anoncreds_works_for_cred_def_rotation_issuer")
//             .unwrap();

//     //2. Create Prover wallet, gets wallet handle
//     let (prover_wallet_handle, prover_wallet_config) =
//         wallet::create_and_open_default_wallet("anoncreds_works_for_cred_def_rotation_prover")
//             .unwrap();

//     //3. Issuer creates Schema and Credential Definition
//     let (schema_id, schema_json, cred_def_id, cred_def_json) =
//         anoncreds::multi_steps_issuer_preparation(
//             issuer_wallet_handle,
//             ISSUER_DID,
//             GVT_SCHEMA_NAME,
//             GVT_SCHEMA_ATTRIBUTES,
//         );

//     //4. Prover creates Link Secret
//     anoncreds::prover_create_link_secret(prover_wallet_handle, COMMON_LINK_SECRET).unwrap();

//     //5. Issuance credential for Prover
//     anoncreds::multi_steps_create_credential(
//         COMMON_LINK_SECRET,
//         prover_wallet_handle,
//         issuer_wallet_handle,
//         CREDENTIAL1_ID,
//         &anoncreds::gvt_credential_values_json(),
//         &cred_def_id,
//         &cred_def_json,
//     );

//     //6. Proof request
//     let nonce = anoncreds::generate_nonce().unwrap();
//     let proof_req_json = json!({
//         "nonce": nonce,
//         "name":"proof_req_1",
//         "version":"0.1",
//         "requested_attributes":{
//             "attr1_referent":{
//                 "name":"name"
//             }
//         },
//         "requested_predicates":{
//             "predicate1_referent":{"name":"age","p_type":">=","p_value":18}
//         }
//     })
//     .to_string();

//     //7. Prover gets Credentials for Proof Request
//     let credentials_json =
//         anoncreds::prover_get_credentials_for_proof_req(prover_wallet_handle, &proof_req_json)
//             .unwrap();
//     let credential =
//         anoncreds::get_credential_for_attr_referent(&credentials_json, "attr1_referent");

//     //8. Prover creates Proof
//     let requested_credentials_json = json!({
//         "self_attested_attributes": {},
//         "requested_attributes": {
//             "attr1_referent": { "cred_id": credential.referent, "revealed":true }
//         },
//         "requested_predicates": {
//             "predicate1_referent": { "cred_id": credential.referent }
//         },
//     })
//     .to_string();

//     let schemas_json =
//         json!({schema_id.as_str(): serde_json::from_str::<Schema>(&schema_json).unwrap()})
//             .to_string();
//     let cred_defs_json = json!({cred_def_id.as_str(): serde_json::from_str::<CredentialDefinition>(&cred_def_json).unwrap()}).to_string();
//     let rev_states_json = json!({}).to_string();

//     let proof_json = anoncreds::prover_create_proof(
//         prover_wallet_handle,
//         &proof_req_json,
//         &requested_credentials_json,
//         COMMON_LINK_SECRET,
//         &schemas_json,
//         &cred_defs_json,
//         &rev_states_json,
//     )
//     .unwrap();

//     //9. Verifier verifies proof
//     let rev_reg_defs_json = json!({}).to_string();
//     let rev_regs_json = json!({}).to_string();

//     let valid = anoncreds::verifier_verify_proof(
//         &proof_req_json,
//         &proof_json,
//         &schemas_json,
//         &cred_defs_json,
//         &rev_reg_defs_json,
//         &rev_regs_json,
//     )
//     .unwrap();
//     assert!(valid);

//     //10. Issuer rotate cred def
//     let new_cred_def_json =
//         anoncreds::issuer_rotate_credential_def_start(issuer_wallet_handle, &cred_def_id, None)
//             .unwrap();
//     anoncreds::issuer_rotate_credential_def_apply(issuer_wallet_handle, &cred_def_id).unwrap();

//     //11. Prover generate proof wit rotated cred def but old credential
//     let schemas_json =
//         json!({schema_id.as_str(): serde_json::from_str::<Schema>(&schema_json).unwrap()})
//             .to_string();
//     let cred_defs_json = json!({cred_def_id.as_str(): serde_json::from_str::<CredentialDefinition>(&new_cred_def_json).unwrap()}).to_string();

//     let proof_json = anoncreds::prover_create_proof(
//         prover_wallet_handle,
//         &proof_req_json,
//         &requested_credentials_json,
//         COMMON_LINK_SECRET,
//         &schemas_json,
//         &cred_defs_json,
//         &rev_states_json,
//     )
//     .unwrap();

//     //12. Verifier verifies proof
//     let valid = anoncreds::verifier_verify_proof(
//         &proof_req_json,
//         &proof_json,
//         &schemas_json,
//         &cred_defs_json,
//         &rev_reg_defs_json,
//         &rev_regs_json,
//     )
//     .unwrap();
//     assert!(!valid);

//     wallet::close_and_delete_wallet(issuer_wallet_handle, &issuer_wallet_config).unwrap();
//     wallet::close_and_delete_wallet(prover_wallet_handle, &prover_wallet_config).unwrap();
// }

#[test]
fn anoncreds_works_for_different_predicate_types() {
    Setup::empty();

    //1. Create Issuer wallet, gets wallet handle
    let (issuer_wallet_handle, issuer_wallet_config) =
        wallet::create_and_open_default_wallet("anoncreds_works_for_single_issuer_single_prover")
            .unwrap();

    //2. Create Prover wallet, gets wallet handle
    let (prover_wallet_handle, prover_wallet_config) =
        wallet::create_and_open_default_wallet("anoncreds_works_for_single_issuer_single_prover")
            .unwrap();

    let schema_attributes = r#"["age", "height", "weight", "salary"]"#;

    //3. Issuer creates Schema and Credential Definition
    let (schema_id, schema_json, cred_def_id, cred_def_json) =
        anoncreds::multi_steps_issuer_preparation(
            issuer_wallet_handle,
            ISSUER_DID,
            GVT_SCHEMA_NAME,
            schema_attributes,
        );

    //4. Prover creates Link Secret
    anoncreds::prover_create_link_secret(prover_wallet_handle, COMMON_LINK_SECRET).unwrap();

    let cred_values = json!({
        "age": {"raw": "28", "encoded": "28"},
        "height": {"raw": "175", "encoded": "175"},
        "weight": {"raw": "78", "encoded": "78"},
        "salary": {"raw": "2000", "encoded": "2000"}
    })
    .to_string();

    //5. Issuance credential for Prover
    anoncreds::multi_steps_create_credential(
        COMMON_LINK_SECRET,
        prover_wallet_handle,
        issuer_wallet_handle,
        CREDENTIAL1_ID,
        &cred_values,
        &cred_def_id,
        &cred_def_json,
    );

    //6. Proof request
    let nonce = anoncreds::generate_nonce().unwrap();
    let proof_req_json = json!({
        "nonce": nonce,
        "name":"proof_req_1",
        "version":"0.1",
        "requested_attributes":{},
        "requested_predicates":{
            "predicate1_referent":{
                "name":"age","p_type":">=","p_value":18
            },
            "predicate2_referent":{
                "name":"height","p_type":">","p_value":170
            },
            "predicate3_referent":{
                "name":"weight","p_type":"<","p_value":90
            },
            "predicate4_referent":{
                "name":"salary","p_type":"<=","p_value":2000
            }
        }
    })
    .to_string();

    //7. Prover gets Credentials for Proof Request
    let credentials_json =
        anoncreds::prover_get_credentials_for_proof_req(prover_wallet_handle, &proof_req_json)
            .unwrap();
    let credential =
        anoncreds::get_credential_for_predicate_referent(&credentials_json, "predicate1_referent");

    //8. Prover creates Proof
    let requested_credentials_json = json!({
        "self_attested_attributes": {},
        "requested_attributes": {},
        "requested_predicates": {
            "predicate1_referent": {"cred_id": credential.referent},
            "predicate2_referent": {"cred_id": credential.referent},
            "predicate3_referent": {"cred_id": credential.referent},
            "predicate4_referent": {"cred_id": credential.referent}
        },
    })
    .to_string();

    let schemas_json =
        json!({schema_id: serde_json::from_str::<Schema>(&schema_json).unwrap()}).to_string();
    let cred_defs_json =
        json!({cred_def_id: serde_json::from_str::<CredentialDefinition>(&cred_def_json).unwrap()})
            .to_string();
    let rev_states_json = json!({}).to_string();

    let proof_json = anoncreds::prover_create_proof(
        prover_wallet_handle,
        &proof_req_json,
        &requested_credentials_json,
        COMMON_LINK_SECRET,
        &schemas_json,
        &cred_defs_json,
        &rev_states_json,
    )
    .unwrap();

    //9. Verifier verifies proof
    let rev_reg_defs_json = json!({}).to_string();
    let rev_regs_json = json!({}).to_string();

    let valid = anoncreds::verifier_verify_proof(
        &proof_req_json,
        &proof_json,
        &schemas_json,
        &cred_defs_json,
        &rev_reg_defs_json,
        &rev_regs_json,
    )
    .unwrap();
    assert!(valid);

    wallet::close_and_delete_wallet(issuer_wallet_handle, &issuer_wallet_config).unwrap();
    wallet::close_and_delete_wallet(prover_wallet_handle, &prover_wallet_config).unwrap();
}

#[test] // IS-1363 attr::<attribute_name>::value restriction
fn anoncreds_works_for_attr_value_restriction() {
    Setup::empty();

    //1. Create Issuer wallet, gets wallet handle
    let (issuer_wallet_handle, issuer_wallet_config) =
        wallet::create_and_open_default_wallet("anoncreds_works_for_attr_value_restriction")
            .unwrap();

    //2. Create Prover wallet, gets wallet handle
    let (prover_wallet_handle, prover_wallet_config) =
        wallet::create_and_open_default_wallet("anoncreds_works_for_attr_value_restriction")
            .unwrap();

    //3. Issuer creates Schema and Credential Definition
    let (schema_id, schema_json, cred_def_id, cred_def_json) =
        anoncreds::multi_steps_issuer_preparation(
            issuer_wallet_handle,
            ISSUER_DID,
            GVT_SCHEMA_NAME,
            GVT_SCHEMA_ATTRIBUTES,
        );

    //4. Prover creates Master Secret
    anoncreds::prover_create_link_secret(prover_wallet_handle, COMMON_LINK_SECRET).unwrap();

    //5. Issuance credential for Prover
    anoncreds::multi_steps_create_credential(
        COMMON_LINK_SECRET,
        prover_wallet_handle,
        issuer_wallet_handle,
        CREDENTIAL1_ID,
        &anoncreds::gvt_credential_values_json(),
        &cred_def_id,
        &cred_def_json,
    );

    //6. Proof request
    let nonce = anoncreds::generate_nonce().unwrap();
    let proof_req_json = json!({
        "nonce": nonce,
        "name":"proof_req_1",
        "version":"0.1",
        "requested_attributes":{
            "attr1_referent":{
                "name":"name",
                "restrictions": json!({ "attr::name::value": "Alex" })
            }
        },
        "requested_predicates":{
        }
    })
    .to_string();

    //7. Prover gets Credentials for Proof Request
    let credentials_json =
        anoncreds::prover_get_credentials_for_proof_req(prover_wallet_handle, &proof_req_json)
            .unwrap();
    let credential =
        anoncreds::get_credential_for_attr_referent(&credentials_json, "attr1_referent");

    //8. Prover creates Proof
    let requested_credentials_json = json!({
        "self_attested_attributes": {},
        "requested_attributes": {
            "attr1_referent": {"cred_id": credential.referent, "revealed":true}
        },
        "requested_predicates": {}
    })
    .to_string();

    let schemas_json =
        json!({schema_id: serde_json::from_str::<Schema>(&schema_json).unwrap()}).to_string();
    let cred_defs_json =
        json!({cred_def_id: serde_json::from_str::<CredentialDefinition>(&cred_def_json).unwrap()})
            .to_string();
    let rev_states_json = json!({}).to_string();

    let proof_json = anoncreds::prover_create_proof(
        prover_wallet_handle,
        &proof_req_json,
        &requested_credentials_json,
        COMMON_LINK_SECRET,
        &schemas_json,
        &cred_defs_json,
        &rev_states_json,
    )
    .unwrap();

    let proof: Proof = serde_json::from_str(&proof_json).unwrap();

    //9. Verifier verifies proof
    assert_eq!(
        "Alex",
        proof
            .requested_proof
            .revealed_attrs
            .get("attr1_referent")
            .unwrap()
            .raw
    );

    let rev_reg_defs_json = json!({}).to_string();
    let rev_regs_json = json!({}).to_string();

    let valid = anoncreds::verifier_verify_proof(
        &proof_req_json,
        &proof_json,
        &schemas_json,
        &cred_defs_json,
        &rev_reg_defs_json,
        &rev_regs_json,
    )
    .unwrap();
    assert!(valid);

    wallet::close_and_delete_wallet(issuer_wallet_handle, &issuer_wallet_config).unwrap();
    wallet::close_and_delete_wallet(prover_wallet_handle, &prover_wallet_config).unwrap();
}

#[test] // IS-1380
fn anoncreds_fails_for_unmet_attr_value_restrictions() {
    Setup::empty();

    //1. Create Issuer wallet, gets wallet handle
    let (issuer_wallet_handle, issuer_wallet_config) =
        wallet::create_and_open_default_wallet("anoncreds_fails_for_unmet_attr_value_restrictions")
            .unwrap();

    //2. Create Prover wallet, gets wallet handle
    let (prover_wallet_handle, prover_wallet_config) =
        wallet::create_and_open_default_wallet("anoncreds_fails_for_unmet_attr_value_restrictions")
            .unwrap();

    //3. Issuer creates Schema and Credential Definition
    let (schema_id, schema_json, cred_def_id, cred_def_json) =
        anoncreds::multi_steps_issuer_preparation(
            issuer_wallet_handle,
            ISSUER_DID,
            GVT_SCHEMA_NAME,
            GVT_SCHEMA_ATTRIBUTES,
        );

    //4. Prover creates Master Secret
    anoncreds::prover_create_link_secret(prover_wallet_handle, COMMON_LINK_SECRET).unwrap();

    //5. Issuance 2 credentials for Prover
    anoncreds::multi_steps_create_credential(
        COMMON_LINK_SECRET,
        prover_wallet_handle,
        issuer_wallet_handle,
        CREDENTIAL1_ID,
        &anoncreds::gvt_credential_values_json(),
        &cred_def_id,
        &cred_def_json,
    );

    anoncreds::multi_steps_create_credential(
        COMMON_LINK_SECRET,
        prover_wallet_handle,
        issuer_wallet_handle,
        CREDENTIAL3_ID,
        &anoncreds::gvt2_credential_values_json(),
        &cred_def_id,
        &cred_def_json,
    );

    //6. Proof request restricting attr value to gvt_credential
    let nonce = anoncreds::generate_nonce().unwrap();
    let proof_req_json = json!({
        "nonce": nonce,
        "name":"proof_req_1",
        "version":"0.1",
        "requested_attributes":{
            "attr1_referent":{
                "name":"name",
                "restrictions": json!([{ "attr::name::value": "Alex", "cred_def_id": cred_def_id }])
            }
        },
        "requested_predicates":{
        }
    })
    .to_string();

    //8. Prover creates Proof containing gvt2_credential
    let requested_credentials_json = json!({
        "self_attested_attributes": {},
        "requested_attributes": {
            "attr1_referent": {"cred_id": CREDENTIAL3_ID, "revealed":true}
        },
        "requested_predicates": {}
    })
    .to_string();

    let schemas_json =
        json!({schema_id: serde_json::from_str::<Schema>(&schema_json).unwrap()}).to_string();
    let cred_defs_json =
        json!({cred_def_id: serde_json::from_str::<CredentialDefinition>(&cred_def_json).unwrap()})
            .to_string();
    let rev_states_json = json!({}).to_string();

    let proof_json = anoncreds::prover_create_proof(
        prover_wallet_handle,
        &proof_req_json,
        &requested_credentials_json,
        COMMON_LINK_SECRET,
        &schemas_json,
        &cred_defs_json,
        &rev_states_json,
    )
    .unwrap();

    let proof: Proof = serde_json::from_str(&proof_json).unwrap();

    //9. Verifier verifies proof
    assert_eq!(
        "Alexander",
        proof
            .requested_proof
            .revealed_attrs
            .get("attr1_referent")
            .unwrap()
            .raw
    );

    let rev_reg_defs_json = json!({}).to_string();
    let rev_regs_json = json!({}).to_string();

    let res = anoncreds::verifier_verify_proof(
        &proof_req_json,
        &proof_json,
        &schemas_json,
        &cred_defs_json,
        &rev_reg_defs_json,
        &rev_regs_json,
    );
    assert_code!(ErrorCode::AnoncredsProofRejected, res);

    wallet::close_and_delete_wallet(issuer_wallet_handle, &issuer_wallet_config).unwrap();
    wallet::close_and_delete_wallet(prover_wallet_handle, &prover_wallet_config).unwrap();
}

#[test]
fn anoncreds_works_for_single_issuer_single_prover_fully_qualified_ids() {
    Setup::empty();

    //1. Create Issuer wallet, gets wallet handle
    let (issuer_wallet_handle, issuer_wallet_config) =
        wallet::create_and_open_default_wallet("anoncreds_works_for_single_issuer_single_prover")
            .unwrap();

    //2. Create Prover wallet, gets wallet handle
    let (prover_wallet_handle, prover_wallet_config) =
        wallet::create_and_open_default_wallet("anoncreds_works_for_single_issuer_single_prover")
            .unwrap();

    //3. Issuer creates Schema and Credential Definition
    let (schema_id, schema_json, cred_def_id, cred_def_json) =
        anoncreds::multi_steps_issuer_preparation(
            issuer_wallet_handle,
            ISSUER_DID_V1,
            GVT_SCHEMA_NAME,
            GVT_SCHEMA_ATTRIBUTES,
        );

    //4. Prover creates Master Secret
    anoncreds::prover_create_link_secret(prover_wallet_handle, COMMON_LINK_SECRET).unwrap();

    //5. Issuance credential for Prover
    anoncreds::multi_steps_create_credential(
        COMMON_LINK_SECRET,
        prover_wallet_handle,
        issuer_wallet_handle,
        CREDENTIAL1_ID,
        &anoncreds::gvt_credential_values_json(),
        &cred_def_id,
        &cred_def_json,
    );

    //6. Proof request of version 2.0
    let nonce = anoncreds::generate_nonce().unwrap();
    let proof_req_json = json!({
        "nonce": nonce,
        "name":"proof_req_1",
        "version":"0.1",
        "requested_attributes":{
            "attr1_referent":{
                "name":"name",
                "restrictions": {
                    "$and": [
                        {"schema_id": schema_id},
                        {"cred_def_id": cred_def_id},
                    ]
                }
            }
        },
        "requested_predicates":{
            "predicate1_referent":{
                "name":"age",
                "p_type":">=",
                "p_value":18,
                "restrictions": {
                    "$and": [
                        {"issuer_did": ISSUER_DID_V1},
                        {"schema_id": schema_id},
                        {"cred_def_id": cred_def_id},
                    ]
                }
                }
        },
        "ver": "2.0"
    })
    .to_string();

    //7. Prover gets Credentials for Proof Request
    let credentials_json =
        anoncreds::prover_get_credentials_for_proof_req(prover_wallet_handle, &proof_req_json)
            .unwrap();
    let credential =
        anoncreds::get_credential_for_attr_referent(&credentials_json, "attr1_referent");
    let credential_1 =
        anoncreds::get_credential_for_predicate_referent(&credentials_json, "predicate1_referent");

    //8. Prover creates Proof
    let requested_credentials_json = json!({
        "self_attested_attributes": {},
        "requested_attributes": {
            "attr1_referent": {"cred_id": credential.referent, "revealed":true}
        },
        "requested_predicates": {
            "predicate1_referent": {"cred_id": credential_1.referent}
        }
    })
    .to_string();

    let schemas_json =
        json!({schema_id.clone(): serde_json::from_str::<Schema>(&schema_json).unwrap()})
            .to_string();
    let cred_defs_json = json!({cred_def_id.clone(): serde_json::from_str::<CredentialDefinition>(&cred_def_json).unwrap()}).to_string();
    let rev_states_json = json!({}).to_string();

    let proof_json = anoncreds::prover_create_proof(
        prover_wallet_handle,
        &proof_req_json,
        &requested_credentials_json,
        COMMON_LINK_SECRET,
        &schemas_json,
        &cred_defs_json,
        &rev_states_json,
    )
    .unwrap();

    let proof: Proof = serde_json::from_str(&proof_json).unwrap();

    //9. Verifier verifies proof
    assert_eq!(
        "Alex",
        proof
            .requested_proof
            .revealed_attrs
            .get("attr1_referent")
            .unwrap()
            .raw
    );

    let rev_reg_defs_json = json!({}).to_string();
    let rev_regs_json = json!({}).to_string();

    let valid = anoncreds::verifier_verify_proof(
        &proof_req_json,
        &proof_json,
        &schemas_json,
        &cred_defs_json,
        &rev_reg_defs_json,
        &rev_regs_json,
    )
    .unwrap();
    assert!(valid);

    //9. Proof request of old version
    let nonce = anoncreds::generate_nonce().unwrap();
    let proof_req_json = json!({
        "nonce": nonce,
        "name":"proof_req_2",
        "version":"0.1",
        "requested_attributes":{
            "attr1_referent":{
                "name":"name",
                "restrictions": {
                    "$and": [
                        {"schema_id": anoncreds::to_unqualified(&schema_id).unwrap()},
                        {"cred_def_id": anoncreds::to_unqualified(&cred_def_id).unwrap()},
                    ]
                }
            }
        },
        "requested_predicates":{
            "predicate1_referent":{
                "name":"age",
                "p_type":">=",
                "p_value":18,
                "restrictions": {
                    "$and": [
                        {"issuer_did": anoncreds::to_unqualified(&ISSUER_DID_V1).unwrap()},
                        {"schema_id": anoncreds::to_unqualified(&schema_id).unwrap()},
                        {"cred_def_id": anoncreds::to_unqualified(&cred_def_id).unwrap()},
                    ]
                }
                }
        }
    })
    .to_string();

    //10. Prover gets Credentials for Proof Request
    let credentials_json =
        anoncreds::prover_get_credentials_for_proof_req(prover_wallet_handle, &proof_req_json)
            .unwrap();
    let credential =
        anoncreds::get_credential_for_attr_referent(&credentials_json, "attr1_referent");
    let credential_1 =
        anoncreds::get_credential_for_predicate_referent(&credentials_json, "predicate1_referent");

    //11. Prover creates Proof
    let requested_credentials_json = json!({
        "self_attested_attributes": {},
        "requested_attributes": {
            "attr1_referent": {"cred_id": credential.referent, "revealed":true}
        },
        "requested_predicates": {
            "predicate1_referent": {"cred_id": credential_1.referent}
        }
    })
    .to_string();

    let schemas_json =
        json!({schema_id.clone(): serde_json::from_str::<Schema>(&schema_json).unwrap()})
            .to_string();
    let cred_defs_json = json!({cred_def_id.clone(): serde_json::from_str::<CredentialDefinition>(&cred_def_json).unwrap()}).to_string();
    let rev_states_json = json!({}).to_string();

    let proof_json = anoncreds::prover_create_proof(
        prover_wallet_handle,
        &proof_req_json,
        &requested_credentials_json,
        COMMON_LINK_SECRET,
        &schemas_json,
        &cred_defs_json,
        &rev_states_json,
    )
    .unwrap();

    let proof: Proof = serde_json::from_str(&proof_json).unwrap();

    //12. Verifier verifies proof
    assert_eq!(
        "Alex",
        proof
            .requested_proof
            .revealed_attrs
            .get("attr1_referent")
            .unwrap()
            .raw
    );

    let identifiers = proof.identifiers[0].clone();

    let schema_id_1 = identifiers.schema_id.0;
    let cred_def_id_1 = identifiers.cred_def_id.0;

    let schemas_json =
        json!({schema_id_1: serde_json::from_str::<Schema>(&schema_json).unwrap()}).to_string();
    let cred_defs_json = json!({cred_def_id_1: serde_json::from_str::<CredentialDefinition>(&cred_def_json).unwrap()}).to_string();
    let rev_reg_defs_json = json!({}).to_string();
    let rev_regs_json = json!({}).to_string();

    let valid = anoncreds::verifier_verify_proof(
        &proof_req_json,
        &proof_json,
        &schemas_json,
        &cred_defs_json,
        &rev_reg_defs_json,
        &rev_regs_json,
    )
    .unwrap();

    assert!(valid);

    // 13. Used incorrect identifiers for schamas and cred_defs
    let schemas_json =
        json!({schema_id: serde_json::from_str::<Schema>(&schema_json).unwrap()}).to_string();
    let cred_defs_json =
        json!({cred_def_id: serde_json::from_str::<CredentialDefinition>(&cred_def_json).unwrap()})
            .to_string();

    let res = anoncreds::verifier_verify_proof(
        &proof_req_json,
        &proof_json,
        &schemas_json,
        &cred_defs_json,
        &rev_reg_defs_json,
        &rev_regs_json,
    );
    assert_code!(ErrorCode::CommonInvalidStructure, res);

    wallet::close_and_delete_wallet(issuer_wallet_handle, &issuer_wallet_config).unwrap();
    wallet::close_and_delete_wallet(prover_wallet_handle, &prover_wallet_config).unwrap();
}

#[test]
fn anoncreds_works_for_single_fully_qualified_issuer_single_unqualified_prover() {
    Setup::empty();

    //1. Create Issuer wallet, gets wallet handle
    let (issuer_wallet_handle, issuer_wallet_config) = wallet::create_and_open_default_wallet(
        "anoncreds_works_for_single_fully_qualified_issuer_single_unqualified_prover",
    )
    .unwrap();

    //2. Create Prover wallet, gets wallet handle
    let (prover_wallet_handle, prover_wallet_config) = wallet::create_and_open_default_wallet(
        "anoncreds_works_for_single_fully_qualified_issuer_single_unqualified_prover",
    )
    .unwrap();

    //3. Issuer creates Schema and Credential Definition
    let (schema_id, schema_json, cred_def_id, cred_def_json) =
        anoncreds::multi_steps_issuer_preparation(
            issuer_wallet_handle,
            ISSUER_DID_V1,
            GVT_SCHEMA_NAME,
            GVT_SCHEMA_ATTRIBUTES,
        );
    assert_eq!(schema_id, anoncreds::gvt_schema_id_fully_qualified());
    assert_eq!(
        cred_def_id,
        anoncreds::local_gvt_cred_def_id_fully_qualified()
    );

    //4. Prover creates Master Secret
    anoncreds::prover_create_link_secret(prover_wallet_handle, COMMON_LINK_SECRET).unwrap();

    //5. Issuance unqualified credential for Prover
    // Issuer creates Credential Offer
    let cred_offer_json =
        anoncreds::issuer_create_credential_offer(issuer_wallet_handle, &cred_def_id).unwrap();

    // Issuer convert Credential Offer to unqualified form
    let cred_offer_json = anoncreds::to_unqualified(&cred_offer_json).unwrap();

    let cred_offer: CredentialOffer = serde_json::from_str(&cred_offer_json).unwrap();
    assert_eq!(cred_offer.schema_id.0, anoncreds::gvt_schema_id());
    assert_eq!(cred_offer.cred_def_id.0, anoncreds::local_gvt_cred_def_id());
    assert_eq!(cred_offer.method_name.unwrap(), DEFAULT_METHOD_NAME);

    // Prover creates Credential Request
    let (cred_req, cred_req_metadata) = anoncreds::prover_create_credential_req(
        prover_wallet_handle,
        DID_MY1,
        &cred_offer_json,
        &cred_def_json,
        COMMON_LINK_SECRET,
    )
    .unwrap();

    // Issuer creates Credential
    let (cred_json, _, _) = anoncreds::issuer_create_credential(
        issuer_wallet_handle,
        &cred_offer_json,
        &cred_req,
        &anoncreds::gvt_credential_values_json(),
        None,
        None,
    )
    .unwrap();

    // Prover stores received Credential
    anoncreds::prover_store_credential(
        prover_wallet_handle,
        CREDENTIAL1_ID,
        &cred_req_metadata,
        &cred_json,
        &cred_def_json,
        None,
    )
    .unwrap();

    //6. Proof request of version 2.0
    let nonce = anoncreds::generate_nonce().unwrap();
    let proof_req_json = json!({
        "nonce": nonce,
        "name":"proof_req_1",
        "version":"0.1",
        "requested_attributes":{
            "attr1_referent":{
                "name":"name",
                "restrictions": {
                    "$and": [
                        {"schema_id": anoncreds::to_unqualified(&schema_id).unwrap()},
                        {"cred_def_id": anoncreds::to_unqualified(&cred_def_id).unwrap()},
                    ]
                }
            }
        },
        "requested_predicates":{
            "predicate1_referent":{
                "name":"age",
                "p_type":">=",
                "p_value":18,
                "restrictions": {
                    "$and": [
                        {"issuer_did": anoncreds::to_unqualified(&ISSUER_DID_V1).unwrap()},
                        {"schema_id": anoncreds::to_unqualified(&schema_id).unwrap()},
                    ]
                }
                }
        }
    })
    .to_string();

    //7. Prover gets Credentials for Proof Request
    let credentials_json =
        anoncreds::prover_get_credentials_for_proof_req(prover_wallet_handle, &proof_req_json)
            .unwrap();
    let credential =
        anoncreds::get_credential_for_attr_referent(&credentials_json, "attr1_referent");

    //8. Prover creates Proof
    let requested_credentials_json = json!({
        "self_attested_attributes": {},
        "requested_attributes": {
            "attr1_referent": {"cred_id": credential.referent, "revealed":true}
        },
        "requested_predicates": {
            "predicate1_referent": {"cred_id": credential.referent}
        }
    })
    .to_string();

    let schema_id = credential.schema_id.0;
    let cred_def_id = credential.cred_def_id.0;

    let schemas_json =
        json!({schema_id.clone(): serde_json::from_str::<Schema>(&schema_json).unwrap()})
            .to_string();
    let cred_defs_json = json!({cred_def_id.clone(): serde_json::from_str::<CredentialDefinition>(&cred_def_json).unwrap()}).to_string();
    let rev_states_json = json!({}).to_string();

    let proof_json = anoncreds::prover_create_proof(
        prover_wallet_handle,
        &proof_req_json,
        &requested_credentials_json,
        COMMON_LINK_SECRET,
        &schemas_json,
        &cred_defs_json,
        &rev_states_json,
    )
    .unwrap();

    let proof: Proof = serde_json::from_str(&proof_json).unwrap();

    //9. Verifier verifies proof
    assert_eq!(
        "Alex",
        proof
            .requested_proof
            .revealed_attrs
            .get("attr1_referent")
            .unwrap()
            .raw
    );

    let identifiers = proof.identifiers[0].clone();

    let schema_id = identifiers.schema_id.0;
    let cred_def_id = identifiers.cred_def_id.0;

    let schemas_json =
        json!({schema_id: serde_json::from_str::<Schema>(&schema_json).unwrap()}).to_string();
    let cred_defs_json =
        json!({cred_def_id: serde_json::from_str::<CredentialDefinition>(&cred_def_json).unwrap()})
            .to_string();
    let rev_reg_defs_json = json!({}).to_string();
    let rev_regs_json = json!({}).to_string();

    let valid = anoncreds::verifier_verify_proof(
        &proof_req_json,
        &proof_json,
        &schemas_json,
        &cred_defs_json,
        &rev_reg_defs_json,
        &rev_regs_json,
    )
    .unwrap();
    assert!(valid);

    wallet::close_and_delete_wallet(issuer_wallet_handle, &issuer_wallet_config).unwrap();
    wallet::close_and_delete_wallet(prover_wallet_handle, &prover_wallet_config).unwrap();
}

#[test]
fn anoncreds_works_for_prover_hold_different_credentials_types() {
    Setup::empty();

    //1. Issuer1 creates wallet, gets wallet handles
    let (issuer_gvt_wallet_handle, issuer_gvt_wallet_config) =
        wallet::create_and_open_default_wallet("anoncreds_works_for_multiple_issuer_single_prover")
            .unwrap();

    //2. Issuer2 creates wallet, gets wallet handles
    let (issuer_xyz_wallet_handle, issuer_xyz_wallet_config) =
        wallet::create_and_open_default_wallet("anoncreds_works_for_multiple_issuer_single_prover")
            .unwrap();

    //3. Prover creates wallet, gets wallet handles
    let (prover_wallet_handle, prover_wallet_config) =
        wallet::create_and_open_default_wallet("anoncreds_works_for_multiple_issuer_single_prover")
            .unwrap();

    //4. Issuer1 creates fully qualified GVT Schema and Credential Definition
    let gvt_issuer_did = "did:sov:NcYxiDXkpYi6ov5FcYDi1e"; // fully qualified did
    let (gvt_schema_id, gvt_schema, gvt_cred_def_id, gvt_cred_def_json) =
        anoncreds::multi_steps_issuer_preparation(
            issuer_gvt_wallet_handle,
            gvt_issuer_did,
            GVT_SCHEMA_NAME,
            GVT_SCHEMA_ATTRIBUTES,
        );

    //5. Issuer2 creates simple XYZ Schema and Credential Definition
    let xyz_issuer_did = "2PRyVHmkXQnQzJQKxHxnXC"; // not fully qualified did
    let (xyz_schema_id, xyz_schema, xyz_cred_def_id, xyz_cred_def_json) =
        anoncreds::multi_steps_issuer_preparation(
            issuer_xyz_wallet_handle,
            xyz_issuer_did,
            XYZ_SCHEMA_NAME,
            XYZ_SCHEMA_ATTRIBUTES,
        );

    //6. Prover creates Master Secret
    anoncreds::prover_create_link_secret(prover_wallet_handle, COMMON_LINK_SECRET).unwrap();

    //7. Issuer1 issue GVT Credential for Prover
    anoncreds::multi_steps_create_credential(
        COMMON_LINK_SECRET,
        prover_wallet_handle,
        issuer_gvt_wallet_handle,
        CREDENTIAL1_ID,
        &anoncreds::gvt_credential_values_json(),
        &gvt_cred_def_id,
        &gvt_cred_def_json,
    );

    //8. Issuer2 issue XYZ Credential for Prover
    anoncreds::multi_steps_create_credential(
        COMMON_LINK_SECRET,
        prover_wallet_handle,
        issuer_xyz_wallet_handle,
        CREDENTIAL2_ID,
        &anoncreds::xyz_credential_values_json(),
        &xyz_cred_def_id,
        &xyz_cred_def_json,
    );

    //9. Proof request contains fields from both credentials: fully qualified and not
    let proof_req_json = json!({
        "nonce":"123432421212",
        "name":"proof_req_1",
        "version":"0.1",
        "requested_attributes": {
            "attr1_referent": {
                "name":"name",
                "restrictions": {  // from fully qualified credential
                    "$and": [
                        {"issuer_did": gvt_issuer_did},
                        {"cred_def_id": gvt_cred_def_id}
                    ]
                }
            },
            "attr2_referent": { // from NOT fully qualified credential
                "name":"status",
                "restrictions": {
                    "$and": [
                        {"issuer_did": xyz_issuer_did},
                        {"cred_def_id": xyz_cred_def_id}
                    ]
                }
            }
        },
        "requested_predicates": {
            "predicate1_referent": { // from fully qualified credential
                "name":"age",
                "p_type":">=",
                "p_value":18,
                "restrictions": { "cred_def_id": gvt_cred_def_id }
            },
            "predicate2_referent": {  // from NOT fully qualified credential
                "name":"period",
                "p_type":">=",
                "p_value":5
            },
        },
        "ver": "2.0"
    })
    .to_string();

    //10. Prover gets Credentials for Proof Request
    let credentials_json =
        anoncreds::prover_get_credentials_for_proof_req(prover_wallet_handle, &proof_req_json)
            .unwrap();

    let credential_for_attr_1 =
        anoncreds::get_credential_for_attr_referent(&credentials_json, "attr1_referent");
    let credential_for_attr_2 =
        anoncreds::get_credential_for_attr_referent(&credentials_json, "attr2_referent");
    let credential_for_predicate_1 =
        anoncreds::get_credential_for_predicate_referent(&credentials_json, "predicate1_referent");
    let credential_for_predicate_2 =
        anoncreds::get_credential_for_predicate_referent(&credentials_json, "predicate2_referent");

    //11. Prover creates Proof
    let requested_credentials_json = json!({
            "self_attested_attributes": json!({}),
            "requested_attributes": json!({
            "attr1_referent": json!({ "cred_id": credential_for_attr_1.referent, "revealed":true }),
            "attr2_referent": json!({ "cred_id": credential_for_attr_2.referent, "revealed":true })
            }),
            "requested_predicates": json!({
            "predicate1_referent": json!({ "cred_id": credential_for_predicate_1.referent }),
            "predicate2_referent": json!({ "cred_id": credential_for_predicate_2.referent })
            })
    })
    .to_string();

    let schemas_json = json!({
        gvt_schema_id: serde_json::from_str::<Schema>(&gvt_schema.clone()).unwrap(),
        xyz_schema_id: serde_json::from_str::<Schema>(&xyz_schema.clone()).unwrap()
    })
    .to_string();

    let credential_defs_json = json!({
        gvt_cred_def_id: serde_json::from_str::<CredentialDefinition>(&gvt_cred_def_json).unwrap(),
        xyz_cred_def_id: serde_json::from_str::<CredentialDefinition>(&xyz_cred_def_json).unwrap()
    })
    .to_string();
    let rev_states_json = json!({}).to_string();

    let proof_json = anoncreds::prover_create_proof(
        prover_wallet_handle,
        &proof_req_json,
        &requested_credentials_json,
        COMMON_LINK_SECRET,
        &schemas_json,
        &credential_defs_json,
        &rev_states_json,
    )
    .unwrap();
    let proof: Proof = serde_json::from_str(&proof_json).unwrap();

    //12. Verifier verifies proof
    assert_eq!(
        "Alex",
        proof
            .requested_proof
            .revealed_attrs
            .get("attr1_referent")
            .unwrap()
            .raw
    );
    assert_eq!(
        "partial",
        proof
            .requested_proof
            .revealed_attrs
            .get("attr2_referent")
            .unwrap()
            .raw
    );

    assert_eq!(2, proof.identifiers.len());
    let identifier_1 = proof.identifiers[0].clone();
    let identifier_2 = proof.identifiers[1].clone();

    let schema_id_1 = identifier_1.schema_id.0;
    let schema_id_2 = identifier_2.schema_id.0;

    let (schema_1, schema_2) = if schema_id_1.contains("gvt") {
        (gvt_schema, xyz_schema)
    } else {
        (xyz_schema, gvt_schema)
    };

    let cred_def_id_1 = identifier_1.cred_def_id.0;
    let cred_def_id_2 = identifier_2.cred_def_id.0;

    let (cred_def_1, cred_def_2) = if schema_id_1.contains("gvt") {
        (gvt_cred_def_json, xyz_cred_def_json)
    } else {
        (xyz_cred_def_json, gvt_cred_def_json)
    };

    let schemas_json = json!({
        schema_id_1: serde_json::from_str::<Schema>(&schema_1).unwrap(),
        schema_id_2: serde_json::from_str::<Schema>(&schema_2).unwrap()
    })
    .to_string();

    let credential_defs_json = json!({
        cred_def_id_1: serde_json::from_str::<CredentialDefinition>(&cred_def_1).unwrap(),
        cred_def_id_2: serde_json::from_str::<CredentialDefinition>(&cred_def_2).unwrap()
    })
    .to_string();

    let rev_reg_defs_json = json!({}).to_string();
    let rev_regs_json = json!({}).to_string();

    let valid = anoncreds::verifier_verify_proof(
        &proof_req_json,
        &proof_json,
        &schemas_json,
        &credential_defs_json,
        &rev_reg_defs_json,
        &rev_regs_json,
    )
    .unwrap();
    assert!(valid);

    wallet::close_and_delete_wallet(prover_wallet_handle, &prover_wallet_config).unwrap();
    wallet::close_and_delete_wallet(issuer_gvt_wallet_handle, &issuer_gvt_wallet_config).unwrap();
    wallet::close_and_delete_wallet(issuer_xyz_wallet_handle, &issuer_xyz_wallet_config).unwrap();
}

#[test] // IS-1522 restrictions: [], restrictions: {"$or": []}
fn anoncreds_works_for_restrictions_as_empty_array() {
    Setup::empty();

    //1. Create Issuer wallet, gets wallet handle
    let (issuer_wallet_handle, issuer_wallet_config) =
        wallet::create_and_open_default_wallet("anoncreds_works_for_attr_value_restriction")
            .unwrap();

    //2. Create Prover wallet, gets wallet handle
    let (prover_wallet_handle, prover_wallet_config) =
        wallet::create_and_open_default_wallet("anoncreds_works_for_attr_value_restriction")
            .unwrap();

    //3. Issuer creates Schema and Credential Definition
    let (schema_id, schema_json, cred_def_id, cred_def_json) =
        anoncreds::multi_steps_issuer_preparation(
            issuer_wallet_handle,
            ISSUER_DID,
            GVT_SCHEMA_NAME,
            GVT_SCHEMA_ATTRIBUTES,
        );

    //4. Prover creates Master Secret
    anoncreds::prover_create_link_secret(prover_wallet_handle, COMMON_LINK_SECRET).unwrap();

    //5. Issuance credential for Prover
    anoncreds::multi_steps_create_credential(
        COMMON_LINK_SECRET,
        prover_wallet_handle,
        issuer_wallet_handle,
        CREDENTIAL1_ID,
        &anoncreds::gvt_credential_values_json(),
        &cred_def_id,
        &cred_def_json,
    );

    //6. Proof request
    let nonce = anoncreds::generate_nonce().unwrap();
    let proof_req_json = json!({
        "nonce": nonce,
        "name":"proof_req_1",
        "version":"0.1",
        "requested_attributes":{
            "attr1_referent":{
                "name":"name",
                "restrictions": []
            },
            "attr2_referent":{
                "name":"age",
                "restrictions": {
                    "$or": []
                }
            },
            "attr3_referent":{
                "name":"sex",
                "restrictions": {
                    "$and": []
                }
            }
        },
        "requested_predicates":{
        }
    })
    .to_string();

    //7. Prover gets Credentials for Proof Request
    let credentials_json =
        anoncreds::prover_get_credentials_for_proof_req(prover_wallet_handle, &proof_req_json)
            .unwrap();
    let credential =
        anoncreds::get_credential_for_attr_referent(&credentials_json, "attr1_referent");
    let credential_2 =
        anoncreds::get_credential_for_attr_referent(&credentials_json, "attr2_referent");
    let credential_3 =
        anoncreds::get_credential_for_attr_referent(&credentials_json, "attr3_referent");

    //8. Prover creates Proof
    let requested_credentials_json = json!({
        "self_attested_attributes": {},
        "requested_attributes": {
            "attr1_referent": {"cred_id": credential.referent, "revealed":true},
            "attr2_referent": {"cred_id": credential_2.referent, "revealed":true},
            "attr3_referent": {"cred_id": credential_3.referent, "revealed":true},
        },
        "requested_predicates": {}
    })
    .to_string();

    let schemas_json =
        json!({schema_id: serde_json::from_str::<Schema>(&schema_json).unwrap()}).to_string();
    let cred_defs_json =
        json!({cred_def_id: serde_json::from_str::<CredentialDefinition>(&cred_def_json).unwrap()})
            .to_string();
    let rev_states_json = json!({}).to_string();

    let proof_json = anoncreds::prover_create_proof(
        prover_wallet_handle,
        &proof_req_json,
        &requested_credentials_json,
        COMMON_LINK_SECRET,
        &schemas_json,
        &cred_defs_json,
        &rev_states_json,
    )
    .unwrap();

    let proof: Proof = serde_json::from_str(&proof_json).unwrap();

    //9. Verifier verifies proof
    assert_eq!(
        "Alex",
        proof
            .requested_proof
            .revealed_attrs
            .get("attr1_referent")
            .unwrap()
            .raw
    );
    assert_eq!(
        "28",
        proof
            .requested_proof
            .revealed_attrs
            .get("attr2_referent")
            .unwrap()
            .raw
    );
    assert_eq!(
        "male",
        proof
            .requested_proof
            .revealed_attrs
            .get("attr3_referent")
            .unwrap()
            .raw
    );

    let rev_reg_defs_json = json!({}).to_string();
    let rev_regs_json = json!({}).to_string();

    let valid = anoncreds::verifier_verify_proof(
        &proof_req_json,
        &proof_json,
        &schemas_json,
        &cred_defs_json,
        &rev_reg_defs_json,
        &rev_regs_json,
    )
    .unwrap();
    assert!(valid);

    wallet::close_and_delete_wallet(issuer_wallet_handle, &issuer_wallet_config).unwrap();
    wallet::close_and_delete_wallet(prover_wallet_handle, &prover_wallet_config).unwrap();
}
*/
