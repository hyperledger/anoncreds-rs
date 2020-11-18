from indy_credx import (
    Credential,
    CredentialDefinition,
    CredentialOffer,
    CredentialRequest,
    MasterSecret,
    Schema,
)


test_did = "55GkHamhTU1ZbTbV2ab9DE"

schema = Schema.create(test_did, "schema name", "schema version", ["attr"], seq_no=15)
print("Schema:", schema)
print(schema.to_json())

print(Schema.from_json(schema.to_json()).to_json())

cred_def, cred_def_pvt, key_proof = CredentialDefinition.create(
    test_did, schema, "CL", tag="tag", support_revocation=True
)

print(cred_def.handle)

master_secret = MasterSecret.create()
master_secret_id = "my id"

cred_offer = CredentialOffer.create(schema.id, cred_def, key_proof)
print(cred_offer)

cred_req, cred_req_metadata = CredentialRequest.create(
    test_did, cred_def, master_secret, master_secret_id, cred_offer
)

print(cred_req.to_json())

cred = Credential.create(cred_def, cred_def_pvt, cred_offer, cred_req, {"attr": "test"})
print(cred)
print(cred.to_json())

cred2 = cred.process(cred_req_metadata, master_secret, cred_def)
print(cred2)
