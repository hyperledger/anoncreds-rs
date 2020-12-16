from typing import Mapping, Optional, Sequence, Union

from . import bindings


class CredentialDefinition(bindings.IndyObject):
    GET_ATTR = "credx_credential_definition_get_attribute"

    @classmethod
    def create(
        cls,
        origin_did: str,
        schema: [str, "Schema"],
        signature_type: str,
        tag: str,
        *,
        support_revocation: bool = False,
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
        return str(
            bindings._object_get_attribute(
                self.GET_ATTR,
                self.handle,
                "id",
            )
        )

    @property
    def schema_id(self) -> str:
        return str(
            bindings._object_get_attribute(
                self.GET_ATTR,
                self.handle,
                "schema_id",
            )
        )


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
    GET_ATTR = "credx_schema_get_attribute"

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
        return str(
            bindings._object_get_attribute(
                self.GET_ATTR,
                self.handle,
                "id",
            )
        )


class Credential(bindings.IndyObject):
    GET_ATTR = "credx_credential_get_attribute"

    @classmethod
    def create(
        cls,
        cred_def: [str, CredentialDefinition],
        cred_def_private: [str, CredentialDefinitionPrivate],
        cred_offer: [str, CredentialOffer],
        cred_request: [str, CredentialRequest],
        attr_raw_values: Mapping[str, str],
        attr_enc_values: Mapping[str, str] = None,
        revocation_config: "CredentialRevocationConfig" = None,
    ) -> (
        "Credential",
        Optional["RevocationRegistry"],
        Optional["RevocationRegistryDelta"],
    ):
        if not isinstance(cred_def, bindings.IndyObject):
            cred_def = CredentialDefinition.load(cred_def)
        if not isinstance(cred_def_private, bindings.IndyObject):
            cred_def_private = CredentialDefinitionPrivate.load(cred_def_private)
        if not isinstance(cred_offer, bindings.IndyObject):
            cred_offer = CredentialOffer.load(cred_offer)
        if not isinstance(cred_request, bindings.IndyObject):
            cred_request = CredentialRequest.load(cred_request)
        cred, rev_reg, rev_delta = bindings.create_credential(
            cred_def.handle,
            cred_def_private.handle,
            cred_offer.handle,
            cred_request.handle,
            attr_raw_values,
            attr_enc_values,
            revocation_config._native if revocation_config else None,
        )
        return (
            Credential(cred),
            RevocationRegistry(rev_reg) if rev_reg else None,
            RevocationRegistryDelta(rev_delta) if rev_delta else None,
        )

    def process(
        self,
        cred_req_metadata: [str, CredentialRequestMetadata],
        master_secret: [str, MasterSecret],
        cred_def: [str, CredentialDefinition],
        rev_reg_def: Optional[Union[str, "RevocationRegistryDefinition"]] = None,
    ) -> "Credential":
        if not isinstance(cred_req_metadata, bindings.IndyObject):
            cred_req_metadata = CredentialRequestMetadata.load(cred_req_metadata)
        if not isinstance(master_secret, bindings.IndyObject):
            master_secret = MasterSecret.load(master_secret)
        if not isinstance(cred_def, bindings.IndyObject):
            cred_def = CredentialDefinition.load(cred_def)
        if rev_reg_def and not isinstance(rev_reg_def, bindings.IndyObject):
            rev_reg_def = RevocationRegistryDefinition.load(rev_reg_def)
        return Credential(
            bindings.process_credential(
                self.handle,
                cred_req_metadata.handle,
                master_secret.handle,
                cred_def.handle,
                rev_reg_def.handle if rev_reg_def else None,
            )
        )

    @classmethod
    def load(cls, value: Union[dict, str, bytes, memoryview]) -> "Credential":
        return Credential(
            bindings._object_from_json("credx_credential_from_json", value)
        )

    @property
    def schema_id(self) -> str:
        return str(
            bindings._object_get_attribute(
                self.GET_ATTR,
                self.handle,
                "schema_id",
            )
        )

    @property
    def cred_def_id(self) -> str:
        return str(
            bindings._object_get_attribute(
                self.GET_ATTR,
                self.handle,
                "cred_def_id",
            )
        )

    @property
    def rev_reg_id(self) -> str:
        return str(
            bindings._object_get_attribute(
                self.GET_ATTR,
                self.handle,
                "rev_reg_id",
            )
        )

    @property
    def rev_reg_index(self) -> Optional[int]:
        sval = bindings._object_get_attribute(
            self.GET_ATTR,
            self.handle,
            "rev_reg_index",
        )
        return int(str(sval)) if sval is not None else None


class PresentationRequest(bindings.IndyObject):
    @classmethod
    def load(cls, value: Union[dict, str, bytes, memoryview]) -> "PresentationRequest":
        return PresentationRequest(
            bindings._object_from_json("credx_presentation_request_from_json", value)
        )


class PresentCredentials:
    def __init__(self):
        self.entries = {}
        self.self_attest = {}

    def add_self_attested(self, attest: Mapping[str, str]):
        if attest:
            self.self_attest.update(attest)

    def _get_entry(
        self,
        cred: Credential,
        timestamp: int = None,
        rev_state: "CredentialRevocationState" = None,
    ):
        if cred not in self.entries:
            self.entries[cred] = {}
        if rev_state and not isinstance(rev_state, bindings.IndyObject):
            rev_state = CredentialRevocationState.load(rev_state)
        if timestamp not in self.entries[cred]:
            self.entries[cred][timestamp] = [set(), set(), rev_state]
        elif rev_state:
            self.entries[cred][timestamp][2] = rev_state
        return self.entries[cred][timestamp]

    def add_attributes(
        self,
        cred: Credential,
        *referents: Sequence[str],
        reveal: bool = True,
        timestamp: int = None,
        rev_state: [str, "CredentialRevocationState"] = None,
    ):
        if not referents:
            return
        entry = self._get_entry(cred, timestamp, rev_state)
        for reft in referents:
            entry[0].add((reft, reveal))

    def add_predicates(
        self,
        cred: Credential,
        *referents: Sequence[str],
        timestamp: int = None,
        rev_state: [str, "CredentialRevocationState"] = None,
    ):
        if not referents:
            return
        entry = self._get_entry(cred, timestamp, rev_state)
        for reft in referents:
            entry[1].add(reft)


class Presentation(bindings.IndyObject):
    @classmethod
    def create(
        cls,
        pres_req: [str, PresentationRequest],
        present_creds: PresentCredentials,
        self_attest: Optional[Mapping[str, str]],
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
        for (cred, cred_ts) in present_creds.entries.items():
            for (timestamp, (attrs, preds, rev_state)) in cred_ts.items():
                entry_idx = len(creds)
                creds.append(
                    bindings.CredentialEntry.create(
                        cred.handle, timestamp, rev_state and rev_state.handle
                    )
                )
                for (reft, reveal) in attrs:
                    creds_prove.append(
                        bindings.CredentialProve.attribute(entry_idx, reft, reveal)
                    )
                for reft in preds:
                    creds_prove.append(
                        bindings.CredentialProve.predicate(entry_idx, reft)
                    )
        return Presentation(
            bindings.create_presentation(
                pres_req.handle,
                creds,
                creds_prove,
                self_attest,
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
        rev_reg_defs: Sequence[Union[str, "RevocationRegistryDefinition"]] = None,
        rev_reg_entries: Mapping[
            str, Mapping[int, Union[str, "RevocationRegistry"]]
        ] = None,
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
        reg_defs = []
        reg_entries = []
        for reg_def in rev_reg_defs:
            if not isinstance(reg_def, bindings.IndyObject):
                reg_def = RevocationRegistryDefinition.load(reg_def)
            reg_def_id = reg_def.id
            if rev_reg_entries and reg_def_id in rev_reg_entries:
                for timestamp, entry in rev_reg_entries[reg_def_id].items():
                    if not isinstance(entry, bindings.IndyObject):
                        entry = RevocationRegistry.load(entry)
                    reg_entries.append(
                        bindings.RevocationEntry.create(
                            len(reg_defs), entry.handle, timestamp
                        )
                    )
            reg_defs.append(reg_def.handle)

        return bindings.verify_presentation(
            self.handle,
            pres_req.handle,
            schemas,
            cred_defs,
            reg_defs,
            reg_entries or None,
        )


class RevocationRegistryDefinition(bindings.IndyObject):
    GET_ATTR = "credx_revocation_registry_definition_get_attribute"

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
    ) -> (
        "RevocationRegistryDefinition",
        "RevocationRegistryDefinitionPrivate",
        "RevocationRegistry",
        "RevocationRegistryDelta",
    ):
        if not isinstance(cred_def, bindings.IndyObject):
            cred_def = CredentialDefinition.load(cred_def)
        (
            reg_def,
            reg_def_private,
            reg_entry,
            reg_init_delta,
        ) = bindings.create_revocation_registry(
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
            RevocationRegistryDelta(reg_init_delta),
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

    @property
    def id(self) -> str:
        return str(
            bindings._object_get_attribute(
                self.GET_ATTR,
                self.handle,
                "id",
            )
        )

    @property
    def max_cred_num(self) -> int:
        return int(
            str(
                bindings._object_get_attribute(
                    self.GET_ATTR,
                    self.handle,
                    "max_cred_num",
                )
            )
        )

    @property
    def tails_hash(self) -> str:
        return str(
            bindings._object_get_attribute(
                self.GET_ATTR,
                self.handle,
                "tails_hash",
            )
        )

    @property
    def tails_location(self) -> str:
        return str(
            bindings._object_get_attribute(
                self.GET_ATTR,
                self.handle,
                "tails_location",
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

    def revoke_credential(
        self,
        rev_reg_def: [str, RevocationRegistryDefinition],
        cred_rev_idx: int,
        tails_path: str,
    ) -> "RevocationRegistryDelta":
        if not isinstance(rev_reg_def, bindings.IndyObject):
            rev_reg_def = RevocationRegistryDefinition.load(rev_reg_def)
        self.handle, rev_delta = bindings.revoke_credential(
            rev_reg_def.handle, self.handle, cred_rev_idx, tails_path
        )
        return RevocationRegistryDelta(rev_delta)

    def update(
        self,
        rev_reg_def: [str, RevocationRegistryDefinition],
        issued: Sequence[int],
        revoked: Sequence[int],
        tails_path: str,
    ) -> "RevocationRegistryDelta":
        if not isinstance(rev_reg_def, bindings.IndyObject):
            rev_reg_def = RevocationRegistryDefinition.load(rev_reg_def)
        self.handle, rev_delta = bindings.update_revocation_registry(
            rev_reg_def.handle, self.handle, issued, revoked, tails_path
        )
        return RevocationRegistryDelta(rev_delta)


class RevocationRegistryDelta(bindings.IndyObject):
    @classmethod
    def load(
        cls, value: Union[dict, str, bytes, memoryview]
    ) -> "RevocationRegistryDelta":
        return RevocationRegistryDelta(
            bindings._object_from_json(
                "credx_revocation_registry_delta_from_json", value
            )
        )

    def update_with(
        self, next_delta: [str, "RevocationRegistryDelta"]
    ) -> "RevocationRegistryDelta":
        if not isinstance(next_delta, bindings.IndyObject):
            next_delta = RevocationRegistryDelta.load(next_delta)
        self.handle = bindings.merge_revocation_registry_deltas(
            self.handle, next_delta.handle
        )


class CredentialRevocationConfig:
    def __init__(
        self,
        rev_reg_def: [str, "RevocationRegistryDefinition"] = None,
        rev_reg_def_private: [str, "RevocationRegistryDefinitionPrivate"] = None,
        rev_reg: [str, "RevocationRegistry"] = None,
        rev_reg_index: int = None,
        rev_reg_used: Sequence[int] = None,
        tails_path: str = None,
    ):
        if not isinstance(rev_reg_def, bindings.IndyObject):
            rev_reg_def = RevocationRegistryDefinition.load(rev_reg_def)
        self.rev_reg_def = rev_reg_def
        if not isinstance(rev_reg_def_private, bindings.IndyObject):
            rev_reg_def_private = RevocationRegistryDefinitionPrivate.load(
                rev_reg_def_private
            )
        self.rev_reg_def_private = rev_reg_def_private
        if not isinstance(rev_reg, bindings.IndyObject):
            rev_reg = RevocationRegistry.load(rev_reg)
        self.rev_reg = rev_reg
        self.rev_reg_index = rev_reg_index
        self.rev_reg_used = rev_reg_used
        self.tails_path = tails_path

    @property
    def _native(self) -> bindings.RevocationConfig:
        return bindings.RevocationConfig.create(
            self.rev_reg_def.handle,
            self.rev_reg_def_private.handle,
            self.rev_reg.handle,
            self.rev_reg_index,
            self.rev_reg_used,
            self.tails_path,
        )


class CredentialRevocationState(bindings.IndyObject):
    @classmethod
    def create(
        cls,
        rev_reg_def: [str, RevocationRegistryDefinition],
        rev_reg_delta: [str, RevocationRegistryDelta],
        cred_rev_id: int,
        timestamp: int,
        tails_path: str,
    ) -> "CredentialRevocationState":
        if not isinstance(rev_reg_def, bindings.IndyObject):
            rev_reg_def = RevocationRegistryDefinition.load(rev_reg_def)
        if not isinstance(rev_reg_delta, bindings.IndyObject):
            rev_reg_delta = RevocationRegistryDelta.load(rev_reg_delta)
        return CredentialRevocationState(
            bindings.create_or_update_revocation_state(
                rev_reg_def.handle,
                rev_reg_delta.handle,
                cred_rev_id,
                timestamp,
                tails_path,
                None,
            )
        )

    @classmethod
    def load(
        cls, value: Union[dict, str, bytes, memoryview]
    ) -> "CredentialRevocationState":
        return CredentialRevocationState(
            bindings._object_from_json("credx_revocation_state_from_json", value)
        )

    def update(
        self,
        rev_reg_def: [str, RevocationRegistryDefinition],
        rev_reg_delta: [str, RevocationRegistryDelta],
        rev_reg_index: int,
        timestamp: int,
        tails_path: str,
    ):
        if not isinstance(rev_reg_def, bindings.IndyObject):
            rev_reg_def = RevocationRegistryDefinition.load(rev_reg_def)
        if not isinstance(rev_reg_delta, bindings.IndyObject):
            rev_reg_delta = RevocationRegistryDelta.load(rev_reg_delta)
        self.handle = bindings.create_or_update_revocation_state(
            rev_reg_def.handle,
            rev_reg_delta.handle,
            rev_reg_index,
            timestamp,
            tails_path,
            self.handle,
        )
