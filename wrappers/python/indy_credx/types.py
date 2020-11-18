from typing import Mapping, Sequence

from . import bindings


class CredentialDefinition(bindings.IndyObject):
    @classmethod
    def create(
        cls,
        origin_did: str,
        schema: [str, "Schema"],
        signature_type: str,
        *,
        support_revocation: bool,
        tag: str = None,
    ) -> ("CredentialDefinition", "CredentialDefinitionPrivate", "KeyCorrectnessProof"):
        if isinstance(schema, str):
            schema = Schema.from_json(schema)
        cred_def, cred_def_pvt, key_proof = bindings.create_credential_definition(
            origin_did, schema.handle, tag, signature_type, support_revocation
        )
        return (
            CredentialDefinition(cred_def),
            CredentialDefinitionPrivate(cred_def_pvt),
            KeyCorrectnessProof(key_proof),
        )

    @classmethod
    def from_json(cls, value: str) -> "CredentialDefinition":
        return CredentialDefinition(bindings.credential_definition_from_json(value))

    @property
    def id(self) -> str:
        return str(bindings.credential_definition_get_id(self.handle))


class CredentialDefinitionPrivate(bindings.IndyObject):
    @classmethod
    def from_json(cls, value: str) -> "CredentialDefinitionPrivate":
        return CredentialDefinitionPrivate(
            bindings.credential_definition_private_from_json(value)
        )


class KeyCorrectnessProof(bindings.IndyObject):
    @classmethod
    def from_json(cls, value: str) -> "KeyCorrectnessProof":
        return KeyCorrectnessProof(bindings.key_correctness_proof_from_json(value))


class CredentialOffer(bindings.IndyObject):
    @classmethod
    def create(
        cls,
        schema_id: str,
        cred_def: [str, CredentialDefinition],
        key_proof: [str, KeyCorrectnessProof],
    ) -> "CredentialOffer":
        if isinstance(cred_def, str):
            cred_def = CredentialDefinition.from_json(cred_def)
        if isinstance(key_proof, str):
            key_proof = KeyCorrectnessProof.from_json(key_proof)
        return CredentialOffer(
            bindings.create_credential_offer(
                schema_id, cred_def.handle, key_proof.handle
            )
        )

    @classmethod
    def from_json(cls, value: str) -> "CredentialOffer":
        return CredentialOffer(bindings.credential_offer_from_json(value))


class CredentialRequest(bindings.IndyObject):
    @classmethod
    def create(
        cls,
        prover_did: str,
        cred_def: [str, CredentialDefinition],
        master_secret: [str, "MasterSecret"],
        master_secret_id: str,
        cred_offer: [str, CredentialOffer],
    ) -> ("CredentialRequest", "CredentialRequestMetadata"):
        if isinstance(cred_def, str):
            cred_def = CredentialDefinition.from_json(cred_def)
        if isinstance(master_secret, str):
            master_secret = MasterSecret.from_json(master_secret)
        if isinstance(cred_offer, str):
            cred_offer = CredentialOffer.from_json(cred_offer)
        cred_def, cred_def_metadata = bindings.create_credential_request(
            prover_did,
            cred_def.handle,
            master_secret.handle,
            master_secret_id,
            cred_offer.handle,
        )
        return CredentialRequest(cred_def), CredentialRequestMetadata(cred_def_metadata)

    @classmethod
    def from_json(cls, value: str) -> "CredentialRequest":
        return CredentialRequest(bindings.credential_request_from_json(value))


class CredentialRequestMetadata(bindings.IndyObject):
    @classmethod
    def from_json(cls, value: str) -> "CredentialRequestMetadata":
        return CredentialRequestMetadata(
            bindings.credential_request_metadata_from_json(value)
        )


class MasterSecret(bindings.IndyObject):
    @classmethod
    def create(cls) -> "MasterSecret":
        return MasterSecret(bindings.create_master_secret())

    @classmethod
    def from_json(cls, value: str) -> "MasterSecret":
        return MasterSecret(bindings.master_secret_from_json(value))


class Schema(bindings.IndyObject):
    @classmethod
    def create(
        cls,
        origin_did: str,
        name: str,
        version: str,
        attr_names: Sequence[str],
        *,
        seq_no: int = None,
    ) -> "Schema":
        return Schema(
            bindings.create_schema(origin_did, name, version, attr_names, seq_no)
        )

    @classmethod
    def from_json(cls, value: str) -> "Schema":
        return Schema(bindings.schema_from_json(value))

    @property
    def id(self) -> str:
        return str(bindings.schema_get_id(self.handle))


class Credential(bindings.IndyObject):
    @classmethod
    def create(
        cls,
        cred_def: [str, CredentialDefinition],
        cred_def_private: [str, CredentialDefinitionPrivate],
        cred_offer: [str, CredentialOffer],
        cred_request: [str, CredentialRequest],
        attr_raw_values: Mapping[str, str],
        attr_enc_values: Mapping[str, str] = None,
    ) -> "Credential":
        if isinstance(cred_def, str):
            cred_def = CredentialDefinition.from_json(cred_def)
        if isinstance(cred_def_private, str):
            cred_def_private = CredentialDefinitionPrivate.from_json(cred_def_private)
        if isinstance(cred_offer, str):
            cred_offer = CredentialOffer.from_json(cred_offer)
        if isinstance(cred_request, str):
            cred_request = CredentialRequest.from_json(cred_request)
        return Credential(
            bindings.create_credential(
                cred_def.handle,
                cred_def_private.handle,
                cred_offer.handle,
                cred_request.handle,
                attr_raw_values,
                attr_enc_values,
                None,
            )
        )

    def process(
        self,
        cred_req_metadata: [str, CredentialRequestMetadata],
        master_secret: [str, CredentialRequestMetadata],
        cred_def: [str, CredentialDefinition],
    ) -> "Credential":
        if isinstance(cred_req_metadata, str):
            cred_req_metadata = CredentialRequestMetadata.from_json(cred_req_metadata)
        if isinstance(master_secret, str):
            master_secret = MasterSecret.from_json(master_secret)
        if isinstance(cred_def, str):
            cred_def = CredentialDefinition.from_json(cred_def)
        return Credential(
            bindings.process_credential(
                self.handle,
                cred_req_metadata.handle,
                master_secret.handle,
                cred_def.handle,
                None,
            )
        )

    @classmethod
    def from_json(cls, value: str) -> "Credential":
        return CredentialDefinition(bindings.credential_from_json(value))
