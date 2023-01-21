from time import time

from anoncreds import (
    generate_nonce,
    Credential,
    CredentialDefinition,
    CredentialOffer,
    CredentialRequest,
    CredentialRevocationConfig,
    CredentialRevocationState,
    PresentationRequest,
    Presentation,
    PresentCredentials,
    MasterSecret,
    RevocationRegistryDefinition,
    Schema,
)

issuer_id   = "mock:uri"
schema_id   = "mock:uri"
cred_def_id = "mock:uri"
rev_reg_id  = "mock:uri"

schema = Schema.create("schema name", "schema version", issuer_id, ["attr"])
assert schema.to_dict() == {
    "name": "schema name",
    "version": "schema version",
    "issuerId": issuer_id,
    "attrNames": ["attr"],
}


cred_def, cred_def_pvt, key_proof = CredentialDefinition.create(
    schema_id, schema, issuer_id, "tag", "CL", support_revocation=True
)

(
    rev_reg_def,
    rev_reg_def_private,
    rev_reg,
    rev_reg_init_list,
) = RevocationRegistryDefinition.create(cred_def_id, cred_def, "default", "CL_ACCUM", 100)

master_secret = MasterSecret.create()
master_secret_id = "my id"

cred_offer = CredentialOffer.create(schema_id, cred_def_id, key_proof)

cred_req, cred_req_metadata = CredentialRequest.create(
    None, cred_def, master_secret, master_secret_id, cred_offer
)

issuer_rev_index = 1

cred, _rev_reg_updated, _rev_delta = Credential.create(
    cred_def,
    cred_def_pvt,
    cred_offer,
    cred_req,
    {"attr": "test"},
    None,
    rev_reg_id,
    CredentialRevocationConfig(
        rev_reg_def,
        rev_reg_def_private,
        rev_reg,
        issuer_rev_index,
        (),
        rev_reg_def.tails_location,
    ),
)

cred_received = cred.process(cred_req_metadata, master_secret, cred_def, rev_reg_def)

timestamp = int(time())
 
pres_req = PresentationRequest.load(
    {
        "name": "proof",
        "version": "1.0",
        "nonce": generate_nonce(),
        "requested_attributes": {
            "reft": {
                "name": "attr",
                "non_revoked": {"from": timestamp, "to": timestamp},
            }
        },
        "requested_predicates": {},
        "non_revoked": {"from": timestamp, "to": timestamp},
        "ver": "1.0",
    }
)

# rev_state = CredentialRevocationState.create(
#     rev_reg_def,
#     rev_reg_init_list,
#     cred.rev_reg_index,
#     rev_reg_def.tails_location,
# )
 
present_creds = PresentCredentials()

present_creds.add_attributes(
    # cred_received, "reft", reveal=True, timestamp=timestamp, rev_state=rev_state
    cred_received, "reft", reveal=True
)
 
presentation = Presentation.create(
    pres_req, present_creds, {}, master_secret, {schema_id: schema}, {cred_def_id: cred_def}
)

# verified = presentation.verify(
#     pres_req,
#     [schema],
#     [cred_def],
#     [rev_reg_def],
#     {rev_reg_def.id: {timestamp: rev_reg}},
# )
# assert verified
# 
# 
# # rev_delta_2 = rev_reg.revoke_credential(
# #     rev_reg_def, issuer_rev_index, rev_reg_def.tails_location
# # )
# rev_delta_2 = rev_reg.update(
#     rev_reg_def, [], [issuer_rev_index], rev_reg_def.tails_location
# )
# 
# rev_state.update(
#     rev_reg_def, rev_delta_2, issuer_rev_index, timestamp, rev_reg_def.tails_location
# )
# 
# present_creds = PresentCredentials()
# present_creds.add_attributes(
#     cred_received, "reft", reveal=True, timestamp=timestamp, rev_state=rev_state
# )
# presentation_2 = Presentation.create(
#     pres_req, present_creds, {}, master_secret, [schema], [cred_def]
# )
# 
# verified = presentation.verify(
#     pres_req,
#     [schema],
#     [cred_def],
#     [rev_reg_def],
#     {rev_reg_def.id: {timestamp: rev_reg}},
# )
# assert not verified
# 
print("ok")

