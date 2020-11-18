from indy_credx import Schema

test_did = "55GkHamhTU1ZbTbV2ab9DE"

schema = Schema.create(test_did, "schema name", "schema version", ["attr"], 15)
print("Schema:", schema)
print(schema.to_json())
