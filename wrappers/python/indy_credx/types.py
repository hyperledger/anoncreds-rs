from typing import Mapping, Sequence, Union

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
        if not isinstance(schema, bindings.IndyObject):
            schema = Schema.load(schema)
        cred_def, cred_def_pvt, key_proof = bindings.create_credential_definition(
            origin_did, schema.handle, tag, signature_type, support_revocation
        )
        return (
            CredentialDefinition(cred_def),
            CredentialDefinitionPrivate(cred_def_pvt),
            KeyCorrectnessProof(key_proof),
        )

    @classmethod
    def load(cls, value: Union[dict, str, bytes, memoryview]) -> "CredentialDefinition":
        return CredentialDefinition(
            bindings._object_from_json("credx_credential_definition_from_json", value)
        )

    @property
    def id(self) -> str:
        return str(bindings.credential_definition_get_id(self.handle))


class CredentialDefinitionPrivate(bindings.IndyObject):
    @classmethod
    def load(
        cls, value: Union[dict, str, bytes, memoryview]
    ) -> "CredentialDefinitionPrivate":
        return CredentialDefinitionPrivate(
            bindings._object_from_json(
                "credx_credential_definition_private_from_json", value
            )
        )


class KeyCorrectnessProof(bindings.IndyObject):
    @classmethod
    def load(cls, value: Union[dict, str, bytes, memoryview]) -> "KeyCorrectnessProof":
        return KeyCorrectnessProof(
            bindings._object_from_json("credx_key_correctness_proof_from_json", value)
        )


class CredentialOffer(bindings.IndyObject):
    @classmethod
    def create(
        cls,
        schema_id: str,
        cred_def: [str, CredentialDefinition],
        key_proof: [str, KeyCorrectnessProof],
    ) -> "CredentialOffer":
        if not isinstance(cred_def, bindings.IndyObject):
            cred_def = CredentialDefinition.load(cred_def)
        if not isinstance(key_proof, bindings.IndyObject):
            key_proof = KeyCorrectnessProof.load(key_proof)
        return CredentialOffer(
            bindings.create_credential_offer(
                schema_id, cred_def.handle, key_proof.handle
            )
        )

    @classmethod
    def load(cls, value: Union[dict, str, bytes, memoryview]) -> "CredentialOffer":
        return CredentialOffer(
            bindings._object_from_json("credx_credential_offer_from_json", value)
        )


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
        if not isinstance(cred_def, bindings.IndyObject):
            cred_def = CredentialDefinition.load(cred_def)
        if not isinstance(master_secret, bindings.IndyObject):
            master_secret = MasterSecret.load(master_secret)
        if not isinstance(cred_offer, bindings.IndyObject):
            cred_offer = CredentialOffer.load(cred_offer)
        cred_def, cred_def_metadata = bindings.create_credential_request(
            prover_did,
            cred_def.handle,
            master_secret.handle,
            master_secret_id,
            cred_offer.handle,
        )
        return CredentialRequest(cred_def), CredentialRequestMetadata(cred_def_metadata)

    @classmethod
    def load(cls, value: Union[dict, str, bytes, memoryview]) -> "CredentialRequest":
        return CredentialRequest(
            bindings._object_from_json("credx_credential_request_from_json", value)
        )


class CredentialRequestMetadata(bindings.IndyObject):
    @classmethod
    def load(
        cls, value: Union[dict, str, bytes, memoryview]
    ) -> "CredentialRequestMetadata":
        return CredentialRequestMetadata(
            bindings._object_from_json(
                "credx_credential_request_metadata_from_json", value
            )
        )


class MasterSecret(bindings.IndyObject):
    @classmethod
    def create(cls) -> "MasterSecret":
        return MasterSecret(bindings.create_master_secret())

    @classmethod
    def load(cls, value: Union[dict, str, bytes, memoryview]) -> "MasterSecret":
        return MasterSecret(
            bindings._object_from_json("credx_master_secret_from_json", value)
        )


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
    def load(cls, value: Union[dict, str, bytes, memoryview]) -> "Schema":
        return Schema(bindings._object_from_json("credx_schema_from_json", value))

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
        if not isinstance(cred_def, bindings.IndyObject):
            cred_def = CredentialDefinition.load(cred_def)
        if not isinstance(cred_def_private, bindings.IndyObject):
            cred_def_private = CredentialDefinitionPrivate.load(cred_def_private)
        if not isinstance(cred_offer, bindings.IndyObject):
            cred_offer = CredentialOffer.load(cred_offer)
        if not isinstance(cred_request, bindings.IndyObject):
            cred_request = CredentialRequest.load(cred_request)
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
        if not isinstance(cred_req_metadata, bindings.IndyObject):
            cred_req_metadata = CredentialRequestMetadata.load(cred_req_metadata)
        if not isinstance(master_secret, bindings.IndyObject):
            master_secret = MasterSecret.load(master_secret)
        if not isinstance(cred_def, bindings.IndyObject):
            cred_def = CredentialDefinition.load(cred_def)
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
    def load(cls, value: Union[dict, str, bytes, memoryview]) -> "Credential":
        return Credential(
            bindings._object_from_json("credx_credential_from_json", value)
        )


class PresentationRequest(bindings.IndyObject):
    @classmethod
    def load(cls, value: Union[dict, str, bytes, memoryview]) -> "PresentationRequest":
        return PresentationRequest(
            bindings._object_from_json("credx_presentation_request_from_json", value)
        )


class PresentCredentials:
    def __init__(self):
        self.creds = {}
        self.self_attest = {}

    def add_self_attested(self, attest: Mapping[str, str]):
        if attest:
            self.self_attest.update(attest)

    def add_attributes(
        self,
        cred: Credential,
        *referents: Sequence[str],
        reveal: bool = True,
        timestamp: int = None,
    ):
        if not referents:
            return
        if cred not in self.creds:
            self.creds[cred] = ({}, {})
        for reft in referents:
            self.creds[cred][0][reft] = (reveal, timestamp)

    def add_predicates(
        self,
        cred: Credential,
        *referents: Sequence[str],
        timestamp: int = None,
    ):
        if not referents:
            return
        if cred not in self.creds:
            self.creds[cred] = ({}, {})
        for reft in referents:
            self.creds[cred][1][reft] = timestamp


class Presentation(bindings.IndyObject):
    @classmethod
    def create(
        cls,
        pres_req: [str, PresentationRequest],
        present_creds: PresentCredentials,
        master_secret: [str, MasterSecret],
        schemas: Sequence[Union[str, Schema]],
        cred_defs: Sequence[Union[str, CredentialDefinition]],
    ) -> "Presentation":
        if not isinstance(pres_req, bindings.IndyObject):
            pres_req = PresentationRequest.load(pres_req)
        if not isinstance(master_secret, bindings.IndyObject):
            master_secret = MasterSecret.load(master_secret)
        schemas = [
            (Schema.load(s) if not isinstance(s, bindings.IndyObject) else s).handle
            for s in schemas
        ]
        cred_defs = [
            (
                CredentialDefinition.load(c)
                if not isinstance(c, bindings.IndyObject)
                else c
            ).handle
            for c in cred_defs
        ]
        creds = []
        creds_prove = []
        for (cred, (attrs, preds)) in present_creds.creds.items():
            idx = len(creds)
            creds.append(cred.handle)
            for (reft, (reveal, timestamp)) in attrs.items():
                creds_prove.append(
                    bindings.CredentialProve.attribute(idx, reft, reveal, timestamp)
                )
            for (reft, timestamp) in preds.items():
                creds_prove.append(
                    bindings.CredentialProve.predicate(idx, reft, timestamp)
                )
        return Presentation(
            bindings.create_presentation(
                pres_req.handle,
                present_creds.self_attest,
                creds,
                creds_prove,
                master_secret.handle,
                schemas,
                cred_defs,
            )
        )

    @classmethod
    def load(cls, value: Union[dict, str, bytes, memoryview]) -> "Presentation":
        return Presentation(
            bindings._object_from_json("credx_presentation_from_json", value)
        )

    def verify(
        self,
        pres_req: [str, PresentationRequest],
        schemas: Sequence[Union[str, Schema]],
        cred_defs: Sequence[Union[str, CredentialDefinition]],
    ) -> bool:
        if not isinstance(pres_req, bindings.IndyObject):
            pres_req = PresentationRequest.load(pres_req)
        schemas = [
            (Schema.load(s) if not isinstance(s, bindings.IndyObject) else s).handle
            for s in schemas
        ]
        cred_defs = [
            (
                CredentialDefinition.load(c)
                if not isinstance(c, bindings.IndyObject)
                else c
            ).handle
            for c in cred_defs
        ]
        return bindings.verify_presentation(
            self.handle, pres_req.handle, schemas, cred_defs
        )


class RevocationRegistryDefinition(bindings.IndyObject):
    @classmethod
    def create(
        cls,
        origin_did: str,
        cred_def: [str, CredentialDefinition],
        tag: str,
        registry_type: str,
        max_cred_num: int,
        *,
        issuance_type: str = None,
        tails_dir_path: str = None,
    ) -> "RevocationRegistryDefinition":
        if not isinstance(cred_def, bindings.IndyObject):
            cred_def = CredentialDefinition.load(cred_def)
        reg_def, reg_def_private, reg_entry = bindings.create_revocation_registry(
            origin_did,
            cred_def.handle,
            tag,
            registry_type,
            issuance_type,
            max_cred_num,
            tails_dir_path,
        )
        return (
            RevocationRegistryDefinition(reg_def),
            RevocationRegistryDefinitionPrivate(reg_def_private),
            RevocationRegistry(reg_entry),
        )

    @classmethod
    def load(
        cls, value: Union[dict, str, bytes, memoryview]
    ) -> "RevocationRegistryDefinition":
        return RevocationRegistryDefinition(
            bindings._object_from_json(
                "credx_revocation_registry_definition_from_json", value
            )
        )


class RevocationRegistryDefinitionPrivate(bindings.IndyObject):
    @classmethod
    def load(
        cls, value: Union[dict, str, bytes, memoryview]
    ) -> "RevocationRegistryDefinitionPrivate":
        return RevocationRegistryDefinitionPrivate(
            bindings._object_from_json(
                "credx_revocation_registry_definition_private_from_json", value
            )
        )


class RevocationRegistry(bindings.IndyObject):
    @classmethod
    def load(cls, value: Union[dict, str, bytes, memoryview]) -> "RevocationRegistry":
        return RevocationRegistry(
            bindings._object_from_json("credx_revocation_registry_from_json", value)
        )
