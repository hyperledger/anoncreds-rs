from time import time

from indy_credx import (
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


test_did = "55GkHamhTU1ZbTbV2ab9DE"

schema = Schema.create(test_did, "schema name", "schema version", ["attr"], seq_no=15)
assert schema.to_dict() == {
    "ver": "1.0",
    "id": f"{test_did}:2:schema name:schema version",
    "name": "schema name",
    "version": "schema version",
    "attrNames": ["attr"],
    "seqNo": 15,
}


cred_def, cred_def_pvt, key_proof = CredentialDefinition.create(
    test_did, schema, "CL", tag="tag", support_revocation=True
)
assert cred_def.id == f"{test_did}:3:CL:15:tag"

(
    rev_reg_def,
    rev_reg_def_private,
    rev_reg,
    rev_reg_init_delta,
) = RevocationRegistryDefinition.create(test_did, cred_def, "default", "CL_ACCUM", 100)
# print("Tails file hash:", rev_reg_def.tails_hash)

master_secret = MasterSecret.create()
master_secret_id = "my id"

cred_offer = CredentialOffer.create(schema.id, cred_def, key_proof)
# print("Credential offer:")
# print(cred_offer.to_json())

cred_req, cred_req_metadata = CredentialRequest.create(
    test_did, cred_def, master_secret, master_secret_id, cred_offer
)
# print("Credential request:")
# print(cred_req.to_json())

issuer_rev_index = 1

cred, _rev_reg_updated, _rev_delta = Credential.create(
    cred_def,
    cred_def_pvt,
    cred_offer,
    cred_req,
    {"attr": "test"},
    None,
    CredentialRevocationConfig(
        rev_reg_def,
        rev_reg_def_private,
        rev_reg,
        issuer_rev_index,
        (),
        rev_reg_def.tails_location,
    ),
)
# print("Issued credential:")
# print(cred.to_json())

cred_received = cred.process(cred_req_metadata, master_secret, cred_def, rev_reg_def)
# print("Processed credential:")
# print(cred_received.to_json())

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

rev_state = CredentialRevocationState.create(
    rev_reg_def,
    rev_reg_init_delta,
    cred.rev_reg_index,
    timestamp,
    rev_reg_def.tails_location,
)

present_creds = PresentCredentials()

present_creds.add_attributes(
    cred_received, "reft", reveal=True, timestamp=timestamp, rev_state=rev_state
)

presentation = Presentation.create(
    pres_req, present_creds, {}, master_secret, [schema], [cred_def]
)
# print(presentation.to_json())

verified = presentation.verify(
    pres_req,
    [schema],
    [cred_def],
    [rev_reg_def],
    {rev_reg_def.id: {timestamp: rev_reg}},
)
assert verified


# rev_delta_2 = rev_reg.revoke_credential(
#     rev_reg_def, issuer_rev_index, rev_reg_def.tails_location
# )
rev_delta_2 = rev_reg.update(
    rev_reg_def, [], [issuer_rev_index], rev_reg_def.tails_location
)

rev_state.update(
    rev_reg_def, rev_delta_2, issuer_rev_index, timestamp, rev_reg_def.tails_location
)

present_creds = PresentCredentials()
present_creds.add_attributes(
    cred_received, "reft", reveal=True, timestamp=timestamp, rev_state=rev_state
)
presentation_2 = Presentation.create(
    pres_req, present_creds, {}, master_secret, [schema], [cred_def]
)

verified = presentation.verify(
    pres_req,
    [schema],
    [cred_def],
    [rev_reg_def],
    {rev_reg_def.id: {timestamp: rev_reg}},
)
assert not verified

print("ok")
