use std::collections::HashMap;

use anoncreds::{
    data_types::{
        pres_request::{NonRevokedInterval, PresentationRequestPayload},
        rev_reg_def::RevocationRegistryDefinitionId,
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
const LOCAL_TO: u64 = 20;
const TS_WITHIN_LOCAL_OVERRIDE: u64 = 9;

const SCHEMA_ID_1: &str = "mock:uri:schema1";
const SCHEMA_ID_2: &str = "mock:uri:schema2";
const SCHEMA_1: &str = r#"{"name":"gvt","version":"1.0","attrNames":["name","sex","age","height"],"issuerId":"mock:issuer_id/path&q=bar"}"#;
const SCHEMA_2: &str = r#"{"name":"hogwarts","version":"1.0","attrNames":["wand","house","year"],"issuerId":"mock:issuer_id/path&q=hogwarts"}"#;
static CRED_DEF_ID_1: &'static str = "mock:uri:1";
static CRED_DEF_ID_2: &'static str = "mock:uri:2";
static REV_REG_ID_1: &'static str = "mock:uri:revregid1";
static REV_REG_ID_2: &'static str = "mock:uri:revregid2";

fn create_request(input: &ReqInput) -> PresentationRequest {
    let nonce = verifier::generate_nonce().unwrap();
    let json = json!({
        "nonce": nonce,
        "name":input.req_name ,
        "version":"0.1",
        "requested_attributes":{
            "attr1_referent":{
                "name":"name",
                "issuer_id": input.issuer,
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

    let mut presentation: PresentationRequestPayload = serde_json::from_value(json).unwrap();
    presentation.non_revoked = input.global_nonrevoke.clone();

    for ni in input.attr_nonrevoke.iter() {
        let at = presentation.requested_attributes.get_mut(ni.0).unwrap();
        at.non_revoked = Some(ni.1.clone());
    }

    for ni in input.pred_nonrevoke.iter() {
        let at = presentation.requested_predicates.get_mut(ni.0).unwrap();
        at.non_revoked = Some(ni.1.clone());
    }

    log::info!("\n Request: {:?}", presentation);
    PresentationRequest::PresentationRequestV1(presentation)
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

pub struct ReqInput<'a> {
    pub req_name: &'a str,
    pub issuer: &'a str,
    pub global_nonrevoke: Option<NonRevokedInterval>,
    pub attr_nonrevoke: Vec<(&'a str, NonRevokedInterval)>,
    pub pred_nonrevoke: Vec<(&'a str, NonRevokedInterval)>,
}

fn test_requests_generate<'a>() -> Vec<ReqInput<'a>> {
    let r0 = ReqInput {
        req_name: "global_rev",
        issuer: ISSUER_ID,
        global_nonrevoke: Some(NonRevokedInterval::new(Some(GLOBAL_FROM), Some(GLOBAL_TO))),
        attr_nonrevoke: vec![],
        pred_nonrevoke: vec![],
    };
    let r1 = ReqInput {
        req_name: "local_rev",
        issuer: ISSUER_ID,
        global_nonrevoke: None,
        attr_nonrevoke: vec![
            (
                "attr2_referent",
                NonRevokedInterval::new(Some(LOCAL_FROM), Some(LOCAL_TO)),
            ),
            (
                "attr5_referent",
                NonRevokedInterval::new(Some(LOCAL_FROM), Some(LOCAL_TO)),
            ),
        ],
        pred_nonrevoke: vec![],
    };
    let r2 = ReqInput {
        req_name: "both_rev_attr",
        issuer: ISSUER_ID,
        global_nonrevoke: Some(NonRevokedInterval::new(Some(GLOBAL_FROM), Some(GLOBAL_TO))),
        attr_nonrevoke: vec![
            (
                "attr2_referent",
                NonRevokedInterval::new(Some(LOCAL_FROM), Some(LOCAL_TO)),
            ),
            (
                "attr5_referent",
                NonRevokedInterval::new(Some(LOCAL_FROM), Some(LOCAL_TO)),
            ),
        ],
        pred_nonrevoke: vec![],
    };
    let r3 = ReqInput {
        req_name: "both_rev_pred",
        issuer: ISSUER_ID,
        global_nonrevoke: Some(NonRevokedInterval::new(Some(GLOBAL_FROM), Some(GLOBAL_TO))),
        attr_nonrevoke: vec![],
        pred_nonrevoke: vec![(
            "predicate1_referent",
            NonRevokedInterval::new(Some(LOCAL_FROM), Some(LOCAL_TO)),
        )],
    };
    let r4 = ReqInput {
        req_name: "no_rev",
        issuer: ISSUER_ID,
        global_nonrevoke: None,
        attr_nonrevoke: vec![],
        pred_nonrevoke: vec![],
    };

    vec![r0, r1, r2, r3, r4]
}

#[test]
fn anoncreds_with_multiple_credentials_per_request() {
    env_logger::init();
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
    let time_after_credential = TS_WITHIN_LOCAL_OVERRIDE;
    let issuance_by_default = true;

    // This returns Presentation Requests with following nonrevoked intervals
    // [0]: Global
    // [1]: Local for attributes belonging to both credentials
    // [2]: Global and Local attributes , where local is more stringent
    // [3]: Global and Local predeicate, where local is more stringent
    // [4]: no NRP required
    let reqs: Vec<PresentationRequest> = test_requests_generate()
        .iter()
        .map(|x| create_request(&x))
        .collect();

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
    //
    // Without override fails
    let overrides = vec![None; 5];
    let results =
        mock.verifer_verifies_presentations_for_requests(&presentations, &reqs, &overrides);
    assert!(results[0].is_ok());
    assert!(results[4].is_ok());
    assert!(results[1].is_err());
    assert!(results[2].is_err());
    assert!(results[3].is_err());

    // Create overrides for timestamps
    let id = RevocationRegistryDefinitionId::new_unchecked(REV_REG_ID_1);
    let override_rev1 = HashMap::from([(&id, HashMap::from([(LOCAL_FROM, OVERRIDE_LOCAL_FROM)]))]);
    let overrides = vec![
        None,
        Some(&override_rev1),
        Some(&override_rev1),
        Some(&override_rev1),
        None,
    ];
    let results =
        mock.verifer_verifies_presentations_for_requests(&presentations, &reqs, &overrides);
    assert!(results[1].is_ok());
    assert!(results[2].is_ok());
    assert!(results[3].is_ok());
}
