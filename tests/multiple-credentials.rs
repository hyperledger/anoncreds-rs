use std::collections::HashMap;

use anoncreds::{
    data_types::{
        pres_request::{NonRevocedInterval, PresentationRequestPayload},
        schema::SchemaId,
    },
    types::PresentationRequest,
    verifier,
};

use serde_json::json;

mod utils;

pub static ISSUER_ID: &str = "mock:issuer_id/path&q=bar";
pub static PROVER_ID: &str = "mock:prover_id/path&q=bar";
pub static REV_IDX_1: u32 = 9;
pub static REV_IDX_2: u32 = 9;
pub static MAX_CRED_NUM: u32 = 10;
pub static TF_PATH: &str = "../.tmp";

// NonRevoked Interval consts
const GLOBAL_FROM: u64 = 5;
const GLOBAL_TO: u64 = 25;
const LOCAL_FROM: u64 = 10;
const OVERRIDE_LOCAL_FROM: u64 = 8;
const LOCAL_TO: u32 = 20;
const TS_WITHIN_LOCAL_OVERRIDE: u32 = 9;
const TS_WITHIN_GLOBAL_ONLY: u32 = 7;

const SCHEMA_ID_1: &str = "mock:uri:schema1";
const SCHEMA_ID_2: &str = "mock:uri:schema2";
const SCHEMA_1: &str = r#"{"name":"gvt","version":"1.0","attrNames":["name","sex","age","height"],"issuerId":"mock:issuer_id/path&q=bar"}"#;
const SCHEMA_2: &str = r#"{"name":"hogwarts","version":"1.0","attrNames":["wand","house","year"],"issuerId":"mock:issuer_id/path&q=hogwarts"}"#;
static CRED_DEF_ID_1: &'static str = "mock:uri:1";
static CRED_DEF_ID_2: &'static str = "mock:uri:2";
static REV_REG_ID_1: &'static str = "mock:uri:revregid1";
static REV_REG_ID_2: &'static str = "mock:uri:revregid2";

// This returns Presentation Requests with following nonrevoked intervals
// [0]: Global
// [1]: Local for attributes belonging to both credentials
// [2]: Global and Local, where local is more stringent
fn test_2_different_revoke_reqs() -> Vec<PresentationRequest> {
    let nonce_1 = verifier::generate_nonce().expect("Error generating presentation request nonce");
    let nonce_2 = verifier::generate_nonce().expect("Error generating presentation request nonce");
    let nonce_3 = verifier::generate_nonce().expect("Error generating presentation request nonce");

    let json = json!({
        "nonce": nonce_1,
        "name":"pres_req_1",
        "version":"0.1",
        "requested_attributes":{
            "attr1_referent":{
                "name":"name",
                "issuer_id": ISSUER_ID
            },
            "attr2_referent":{
                "name":"sex"
            },
            "attr3_referent":{"name":"phone"},
            "attr4_referent":{
                "names": ["height"],
            },
            "attr5_referent": {"names": ["wand", "house", "year"]},

        },
        "requested_predicates":{
            "predicate1_referent":{"name":"age","p_type":">=","p_value":18}
        },
    });

    let mut p1: PresentationRequestPayload = serde_json::from_value(json.clone()).unwrap();
    let mut p2: PresentationRequestPayload = serde_json::from_value(json.clone()).unwrap();
    let mut p3: PresentationRequestPayload = serde_json::from_value(json).unwrap();

    // Global non_revoked
    p1.non_revoked = Some(NonRevocedInterval::new(Some(5), Some(25)));
    p1.nonce = nonce_1;
    p2.nonce = nonce_2;
    p3.nonce = nonce_3;

    // Local non_revoked
    if let Some(at1) = p2.requested_attributes.get_mut("attr4_referent") {
        at1.non_revoked = Some(NonRevocedInterval::new(Some(10), Some(20)));
    } else {
        panic!("Cannot add non_revoke to attri");
    }
    if let Some(at2) = p2.requested_attributes.get_mut("attr5_referent") {
        at2.non_revoked = Some(NonRevocedInterval::new(Some(10), Some(20)));
    } else {
        panic!("Cannot add non_revoke to attri");
    }

    vec![
        PresentationRequest::PresentationRequestV1(p1),
        PresentationRequest::PresentationRequestV1(p2),
    ]
}

fn create_issuer_data<'a>() -> utils::IssuerValues<'a> {
    // These are what the issuer knows
    // Credential 1 is revocable
    // Credential 2 is non-revocable
    // There are 2 definitions, issued by 1 issuer
    let issuer1_creds: utils::IssuerValues = HashMap::from([
        (
            CRED_DEF_ID_1,
            (
                SCHEMA_ID_1,
                HashMap::from([
                    ("sex", "male"),
                    ("name", "Alex"),
                    ("height", "175"),
                    ("age", "28"),
                ]),
                true,
                REV_REG_ID_1,
                REV_IDX_1,
            ),
        ),
        (
            CRED_DEF_ID_2,
            (
                SCHEMA_ID_2,
                HashMap::from([
                    ("wand", "dragon-heart-string"),
                    ("house", "Hufflepuff"),
                    ("year", "1990"),
                ]),
                false,
                REV_REG_ID_2,
                REV_IDX_2,
            ),
        ),
    ]);
    issuer1_creds
}

#[test]
fn anoncreds_with_multiple_credentials_per_request() {
    let mut mock = utils::Mock::new(&[ISSUER_ID], &[PROVER_ID], TF_PATH, MAX_CRED_NUM);

    let issuer1_creds = create_issuer_data();

    let schemas = HashMap::from([
        (
            SchemaId::new_unchecked(SCHEMA_ID_1),
            serde_json::from_str(SCHEMA_1).unwrap(),
        ),
        (
            SchemaId::new_unchecked(SCHEMA_ID_2),
            serde_json::from_str(SCHEMA_2).unwrap(),
        ),
    ]);

    mock.ledger.schemas = schemas;

    // These are within interval
    let time_initial_rev_reg = 8u64;
    let time_after_credential = 10u64;
    let issuance_by_default = true;

    // To test:
    // pres_request_1: global interval; Tests verification for revocable credentials only
    // pres_request_2: local intervals for both credential; Tests verification for revocable credentials only
    // Verifier creates a presentation request for each
    let reqs = test_2_different_revoke_reqs();

    // 1: Issuer setup (credate cred defs, rev defs(optional), cred_offers)
    mock.issuer_setup(
        ISSUER_ID,
        PROVER_ID,
        &issuer1_creds,
        time_initial_rev_reg,
        issuance_by_default,
    );

    // 2: prover requests and gets credential stored in their wallets
    mock.issuer_create_credential_and_store_in_prover_wallet(
        ISSUER_ID,
        PROVER_ID,
        &issuer1_creds,
        time_initial_rev_reg,
        time_after_credential,
    );

    // 3. Prover creates revocation states for all credentials with ledger values
    // rev_states are stored in the prover wallet
    mock.prover_creates_revocation_states(PROVER_ID, time_after_credential);

    // 4. Prover create presentations
    let prover_values: utils::ProverValues = HashMap::from([
        (
            CRED_DEF_ID_1,
            (
                vec!["attr1_referent", "attr2_referent", "attr4_referent"],
                vec!["predicate1_referent"],
            ),
        ),
        (CRED_DEF_ID_2, (vec!["attr5_referent"], vec![])),
    ]);
    let self_attested = HashMap::from([("attr3_referent".to_string(), "8-800-300".to_string())]);

    let mut presentations = vec![];
    for req in &reqs {
        let p = mock.prover_creates_presentation(
            PROVER_ID,
            prover_values.clone(),
            self_attested.clone(),
            req,
        );
        presentations.push(p)
    }
    // 5. Verifier verifies one presentation per request
    let results = mock.verifer_verifies_presentations_for_requests(presentations, &reqs);

    assert!(results[0]);
    assert!(results[1]);
}
