from time import time

from anoncreds import (
    generate_nonce,
    create_link_secret,
    Credential,
    CredentialDefinition,
    CredentialOffer,
    CredentialRequest,
    CredentialRevocationConfig,
    CredentialRevocationState,
    PresentationRequest,
    Presentation,
    PresentCredentials,
    RevocationRegistryDefinition,
    RevocationStatusList,
    NonrevokedIntervalOverride,
    Schema,
)

issuer_id   = "mock:uri"
schema_id   = "mock:uri"
cred_def_id = "mock:uri"
rev_reg_id  = "mock:uri:revregid"
entropy     = "entropy"
rev_idx = 1

schema = Schema.create("schema name", "schema version", issuer_id, ["name","age","sex","height"])

cred_def_pub, cred_def_priv, cred_def_correctness = CredentialDefinition.create(
    schema_id,
    schema,
    issuer_id,
    "tag",
    "CL",
    support_revocation=True
)

(rev_reg_def_pub, rev_reg_def_private) = RevocationRegistryDefinition.create(
    cred_def_id,
    cred_def_pub,
    issuer_id,
    "some_tag",
    "CL_ACCUM",
    10
)

time_create_rev_status_list = 12
revocation_status_list = RevocationStatusList.create(
    cred_def_pub,
    rev_reg_id,
    rev_reg_def_pub,
    rev_reg_def_private,
    issuer_id,
    True,
    time_create_rev_status_list,
)

link_secret = create_link_secret()
link_secret_id = "default"

cred_offer = CredentialOffer.create(
    schema_id,
    cred_def_id,
    cred_def_correctness
)

cred_request, cred_request_metadata = CredentialRequest.create(
    entropy,
    None,
    cred_def_pub,
    link_secret,
    link_secret_id,
    cred_offer
)

issue_cred = Credential.create(
    cred_def_pub,
    cred_def_priv,
    cred_offer,
    cred_request,
    {
        "sex": "male",
        "name": "Alex",
        "height": "175",
        "age": "28"
    },
    None,
    rev_reg_id,
    revocation_status_list,
    CredentialRevocationConfig(
        rev_reg_def_pub,
        rev_reg_def_private,
        rev_idx,
        rev_reg_def_pub.tails_location,
    ),
)

recv_cred = issue_cred.process(
    cred_request_metadata,
    link_secret,
    cred_def_pub,
    rev_reg_def_pub
)

time_after_creating_cred = time_create_rev_status_list + 1
issued_rev_status_list = revocation_status_list.update(
    cred_def_pub,
    rev_reg_def_pub,
    rev_reg_def_private,
    [rev_idx],
    None,
    time_after_creating_cred,
)

nonce = generate_nonce()
pres_req = PresentationRequest.load(
    {
        "nonce": nonce,
        "name":"pres_req_1",
        "version":"0.1",
        "requested_attributes":{
            "attr1_referent":{
                "name":"name",
                "issuer_id": issuer_id
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
    }
)

rev_state = CredentialRevocationState.create(
    rev_reg_def_pub,
    revocation_status_list,
    rev_idx,
    rev_reg_def_pub.tails_location,
)

schemas = { schema_id: schema }
cred_defs = { cred_def_id: cred_def_pub }
rev_reg_defs = { rev_reg_id: rev_reg_def_pub }
rev_status_lists = [issued_rev_status_list]

present = PresentCredentials()

present.add_attributes(
    recv_cred,
    "attr1_referent",
    reveal=True,
    timestamp=time_after_creating_cred,
    rev_state=rev_state
)

present.add_attributes(
    recv_cred,
    "attr2_referent",
    reveal=False,
    timestamp=time_after_creating_cred,
    rev_state=rev_state
)

present.add_attributes(
    recv_cred,
    "attr4_referent",
    reveal=True,
    timestamp=time_after_creating_cred,
    rev_state=rev_state
)

present.add_predicates(
    recv_cred,
    "predicate1_referent",
    timestamp=time_after_creating_cred,
    rev_state=rev_state
)

presentation = Presentation.create(
    pres_req,
    present,
    {"attr3_referent": "8-800-300"},
    link_secret,
    schemas,
    cred_defs,
)

verified = presentation.verify(
    pres_req,
    schemas,
    cred_defs,
    rev_reg_defs,
    rev_status_lists
)
assert verified

# Issuer revokes credential

time_revoke_cred = time_after_creating_cred + 1
revoked_status_list = issued_rev_status_list.update(
    cred_def_pub,
    rev_reg_def_pub,
    rev_reg_def_private,
    None,
    [rev_idx],
    time_revoke_cred,
)

rev_status_lists.append(revoked_status_list)

rev_state.update(
    rev_reg_def_pub,
    revocation_status_list,
    rev_idx,
    rev_reg_def_pub.tails_location,
    revoked_status_list,
)

present = PresentCredentials()
present.add_attributes(
    recv_cred,
    "attr1_referent",
    reveal=True,
    timestamp=time_revoke_cred,
    rev_state=rev_state
)

present.add_attributes(
    recv_cred,
    "attr2_referent",
    reveal=False,
    timestamp=time_revoke_cred,
    rev_state=rev_state
)

present.add_attributes(
    recv_cred,
    "attr4_referent",
    reveal=True,
    timestamp=time_revoke_cred,
    rev_state=rev_state
)

present.add_predicates(
    recv_cred,
    "predicate1_referent",
    timestamp=time_revoke_cred,
    rev_state=rev_state
)

presentation = Presentation.create(
    pres_req,
    present,
    {"attr3_referent": "8-800-300"},
    link_secret,
    schemas,
    cred_defs
)

verified = presentation.verify(
    pres_req,
    schemas,
    cred_defs,
    rev_reg_defs,
    rev_status_lists,
)
assert not verified

print("ok")
