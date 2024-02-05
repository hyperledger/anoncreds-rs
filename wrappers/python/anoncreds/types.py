import json
from typing import Mapping, Optional, Sequence, Tuple, Union

from . import bindings


class CredentialDefinition(bindings.AnoncredsObject):
    GET_ATTR = "anoncreds_credential_definition_get_attribute"

    @classmethod
    def create(
        cls,
        schema_id: str,
        schema: Union[dict, str, "Schema"],
        issuer_id: str,
        tag: str,
        signature_type: str,
        *,
        support_revocation: bool = False,
    ) -> Tuple[
        "CredentialDefinition", "CredentialDefinitionPrivate", "KeyCorrectnessProof"
    ]:
        if not isinstance(schema, bindings.AnoncredsObject):
            schema = Schema.load(schema)
        cred_def, cred_def_pvt, key_proof = bindings.create_credential_definition(
            schema_id, schema.handle, tag, issuer_id, signature_type, support_revocation
        )
        return (
            CredentialDefinition(cred_def),
            CredentialDefinitionPrivate(cred_def_pvt),
            KeyCorrectnessProof(key_proof),
        )

    @classmethod
    def load(cls, value: Union[dict, str, bytes, memoryview]) -> "CredentialDefinition":
        return CredentialDefinition(
            bindings._object_from_json(
                "anoncreds_credential_definition_from_json", value
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
    def schema_id(self) -> str:
        return str(
            bindings._object_get_attribute(
                self.GET_ATTR,
                self.handle,
                "schema_id",
            )
        )


class CredentialDefinitionPrivate(bindings.AnoncredsObject):
    @classmethod
    def load(
        cls, value: Union[dict, str, bytes, memoryview]
    ) -> "CredentialDefinitionPrivate":
        return CredentialDefinitionPrivate(
            bindings._object_from_json(
                "anoncreds_credential_definition_private_from_json", value
            )
        )


class KeyCorrectnessProof(bindings.AnoncredsObject):
    @classmethod
    def load(cls, value: Union[dict, str, bytes, memoryview]) -> "KeyCorrectnessProof":
        return KeyCorrectnessProof(
            bindings._object_from_json(
                "anoncreds_key_correctness_proof_from_json", value
            )
        )


class CredentialOffer(bindings.AnoncredsObject):
    @classmethod
    def create(
        cls,
        schema_id: str,
        cred_def_id: str,
        key_proof: Union[str, KeyCorrectnessProof],
    ) -> "CredentialOffer":
        if not isinstance(key_proof, bindings.AnoncredsObject):
            key_proof = KeyCorrectnessProof.load(key_proof)
        return CredentialOffer(
            bindings.create_credential_offer(schema_id, cred_def_id, key_proof.handle)
        )

    @classmethod
    def load(cls, value: Union[dict, str, bytes, memoryview]) -> "CredentialOffer":
        return CredentialOffer(
            bindings._object_from_json("anoncreds_credential_offer_from_json", value)
        )


class CredentialRequest(bindings.AnoncredsObject):
    @classmethod
    def create(
        cls,
        entropy: Optional[str],
        prover_did: Optional[str],
        cred_def: Union[str, CredentialDefinition],
        link_secret: str,
        link_secret_id: str,
        cred_offer: Union[str, CredentialOffer],
    ) -> Tuple["CredentialRequest", "CredentialRequestMetadata"]:
        if not isinstance(cred_def, bindings.AnoncredsObject):
            cred_def = CredentialDefinition.load(cred_def)
        if not isinstance(cred_offer, bindings.AnoncredsObject):
            cred_offer = CredentialOffer.load(cred_offer)
        cred_def_handle, cred_def_metadata = bindings.create_credential_request(
            entropy,
            prover_did,
            cred_def.handle,
            link_secret,
            link_secret_id,
            cred_offer.handle,
        )
        return CredentialRequest(cred_def_handle), CredentialRequestMetadata(
            cred_def_metadata
        )

    @classmethod
    def load(cls, value: Union[dict, str, bytes, memoryview]) -> "CredentialRequest":
        return CredentialRequest(
            bindings._object_from_json("anoncreds_credential_request_from_json", value)
        )


class CredentialRequestMetadata(bindings.AnoncredsObject):
    @classmethod
    def load(
        cls, value: Union[dict, str, bytes, memoryview]
    ) -> "CredentialRequestMetadata":
        return CredentialRequestMetadata(
            bindings._object_from_json(
                "anoncreds_credential_request_metadata_from_json", value
            )
        )


class RevocationRegistryDefinition(bindings.AnoncredsObject):
    GET_ATTR = "anoncreds_revocation_registry_definition_get_attribute"

    @classmethod
    def create(
        cls,
        cred_def_id: str,
        cred_def: Union[str, CredentialDefinition],
        issuer_id: str,
        tag: str,
        registry_type: str,
        max_cred_num: int,
        *,
        tails_dir_path: str = None,
    ) -> Tuple["RevocationRegistryDefinition", "RevocationRegistryDefinitionPrivate",]:
        if not isinstance(cred_def, bindings.AnoncredsObject):
            cred_def = CredentialDefinition.load(cred_def)
        (
            reg_def,
            reg_def_private,
        ) = bindings.create_revocation_registry_definition(
            cred_def.handle,
            cred_def_id,
            issuer_id,
            tag,
            registry_type,
            max_cred_num,
            tails_dir_path,
        )
        return (
            RevocationRegistryDefinition(reg_def),
            RevocationRegistryDefinitionPrivate(reg_def_private),
        )

    @classmethod
    def load(
        cls, value: Union[dict, str, bytes, memoryview]
    ) -> "RevocationRegistryDefinition":
        return RevocationRegistryDefinition(
            bindings._object_from_json(
                "anoncreds_revocation_registry_definition_from_json", value
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


class Schema(bindings.AnoncredsObject):
    @classmethod
    def create(
        cls,
        name: str,
        version: str,
        issuer_id: str,
        attr_names: Sequence[str],
    ) -> "Schema":
        return Schema(bindings.create_schema(name, version, issuer_id, attr_names))

    @classmethod
    def load(cls, value: Union[dict, str, bytes, memoryview]) -> "Schema":
        return Schema(bindings._object_from_json("anoncreds_schema_from_json", value))


class Credential(bindings.AnoncredsObject):
    GET_ATTR = "anoncreds_credential_get_attribute"

    @classmethod
    def create(
        cls,
        cred_def: Union[str, CredentialDefinition],
        cred_def_private: Union[str, CredentialDefinitionPrivate],
        cred_offer: Union[str, CredentialOffer],
        cred_request: Union[str, CredentialRequest],
        attr_raw_values: Mapping[str, str],
        attr_enc_values: Optional[Mapping[str, str]] = None,
        revocation_config: Optional["CredentialRevocationConfig"] = None,
    ) -> "Credential":
        if not isinstance(cred_def, bindings.AnoncredsObject):
            cred_def = CredentialDefinition.load(cred_def)
        if not isinstance(cred_def_private, bindings.AnoncredsObject):
            cred_def_private = CredentialDefinitionPrivate.load(cred_def_private)
        if not isinstance(cred_offer, bindings.AnoncredsObject):
            cred_offer = CredentialOffer.load(cred_offer)
        if not isinstance(cred_request, bindings.AnoncredsObject):
            cred_request = CredentialRequest.load(cred_request)
        cred = bindings.create_credential(
            cred_def.handle,
            cred_def_private.handle,
            cred_offer.handle,
            cred_request.handle,
            attr_raw_values,
            attr_enc_values,
            revocation_config._native if revocation_config else None,
        )
        return Credential(cred)

    def process(
        self,
        cred_req_metadata: Union[str, CredentialRequestMetadata],
        link_secret: str,
        cred_def: Union[str, CredentialDefinition],
        rev_reg_def: Optional[Union[str, "RevocationRegistryDefinition"]] = None,
    ) -> "Credential":
        if not isinstance(cred_req_metadata, bindings.AnoncredsObject):
            cred_req_metadata = CredentialRequestMetadata.load(cred_req_metadata)
        if not isinstance(cred_def, bindings.AnoncredsObject):
            cred_def = CredentialDefinition.load(cred_def)
        if rev_reg_def and not isinstance(rev_reg_def, bindings.AnoncredsObject):
            rev_reg_def = RevocationRegistryDefinition.load(rev_reg_def)
        return Credential(
            bindings.process_credential(
                self.handle,
                cred_req_metadata.handle,
                link_secret,
                cred_def.handle,
                rev_reg_def.handle if rev_reg_def else None,
            )
        )

    @classmethod
    def load(cls, value: Union[dict, str, bytes, memoryview]) -> "Credential":
        return Credential(
            bindings._object_from_json("anoncreds_credential_from_json", value)
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

    def to_w3c(
        self,
        issuer_id: str,
        w3c_version: Optional[str] = None,
    ) -> "W3cCredential":
        return W3cCredential(
            bindings.credential_to_w3c(
                self.handle,
                issuer_id,
                w3c_version
            )
        )

    @classmethod
    def from_w3c(cls, cred: "W3cCredential") -> "Credential":
        return Credential(
            bindings.credential_from_w3c(
                cred.handle
            )
        )


class W3cCredential(bindings.AnoncredsObject):
    GET_ATTR = "anoncreds_w3c_credential_proof_get_attribute"
    _proof_details = None

    @classmethod
    def create(
        cls,
        cred_def: Union[str, CredentialDefinition],
        cred_def_private: Union[str, CredentialDefinitionPrivate],
        cred_offer: Union[str, CredentialOffer],
        cred_request: Union[str, CredentialRequest],
        attr_raw_values: Mapping[str, str],
        revocation_config: Optional["CredentialRevocationConfig"] = None,
        w3c_version: Optional[str] = None,
    ) -> "W3cCredential":
        if not isinstance(cred_def, bindings.AnoncredsObject):
            cred_def = CredentialDefinition.load(cred_def)
        if not isinstance(cred_def_private, bindings.AnoncredsObject):
            cred_def_private = CredentialDefinitionPrivate.load(cred_def_private)
        if not isinstance(cred_offer, bindings.AnoncredsObject):
            cred_offer = CredentialOffer.load(cred_offer)
        if not isinstance(cred_request, bindings.AnoncredsObject):
            cred_request = CredentialRequest.load(cred_request)
        cred = bindings.create_w3c_credential(
            cred_def.handle,
            cred_def_private.handle,
            cred_offer.handle,
            cred_request.handle,
            attr_raw_values,
            revocation_config._native if revocation_config else None,
            w3c_version,
        )
        return W3cCredential(cred)

    def process(
        self,
        cred_req_metadata: Union[str, CredentialRequestMetadata],
        link_secret: str,
        cred_def: Union[str, CredentialDefinition],
        rev_reg_def: Optional[Union[str, "RevocationRegistryDefinition"]] = None,
    ) -> "W3cCredential":
        if not isinstance(cred_req_metadata, bindings.AnoncredsObject):
            cred_req_metadata = CredentialRequestMetadata.load(cred_req_metadata)
        if not isinstance(cred_def, bindings.AnoncredsObject):
            cred_def = CredentialDefinition.load(cred_def)
        if rev_reg_def and not isinstance(rev_reg_def, bindings.AnoncredsObject):
            rev_reg_def = RevocationRegistryDefinition.load(rev_reg_def)
        return W3cCredential(
            bindings.process_w3c_credential(
                self.handle,
                cred_req_metadata.handle,
                link_secret,
                cred_def.handle,
                rev_reg_def.handle if rev_reg_def else None,
            )
        )

    @classmethod
    def load(cls, value: Union[dict, str, bytes, memoryview]) -> "W3cCredential":
        return W3cCredential(
            bindings._object_from_json("anoncreds_w3c_credential_from_json", value)
        )

    def to_legacy(
        self
    ) -> "Credential":
        return Credential.from_w3c(self)

    @classmethod
    def from_legacy(
        cls,
        cred: "Credential",
        issuer_id: str,
        w3c_version: Optional[str] = None
    ) -> "W3cCredential":
        return cred.to_w3c(issuer_id, w3c_version)

    def _get_proof_details(self) -> bindings.ObjectHandle:
        if self._proof_details is None:
            self._proof_details = bindings.w3c_credential_get_integrity_proof_details(self.handle)
        return self._proof_details


    @property
    def schema_id(self) -> str:
        proof_details = self._get_proof_details()
        return str(
            bindings._object_get_attribute(
                self.GET_ATTR,
                proof_details,
                "schema_id",
            )
        )

    @property
    def cred_def_id(self) -> str:
        proof_details = self._get_proof_details()
        return str(
            bindings._object_get_attribute(
                self.GET_ATTR,
                proof_details,
                "cred_def_id",
            )
        )

    @property
    def rev_reg_id(self) -> str:
        proof_details = self._get_proof_details()
        return str(
            bindings._object_get_attribute(
                self.GET_ATTR,
                proof_details,
                "rev_reg_id",
            )
        )

    @property
    def rev_reg_index(self) -> Optional[int]:
        proof_details = self._get_proof_details()
        sval = bindings._object_get_attribute(
            self.GET_ATTR,
            proof_details,
            "rev_reg_index",
        )
        return int(str(sval)) if sval is not None else None

    @property
    def timestamp(self) -> Optional[int]:
        proof_details = self._get_proof_details()
        sval = bindings._object_get_attribute(
            self.GET_ATTR,
            proof_details,
            "timestamp",
        )
        return int(str(sval)) if sval is not None else None


class PresentationRequest(bindings.AnoncredsObject):
    @classmethod
    def load(cls, value: Union[dict, str, bytes, memoryview]) -> "PresentationRequest":
        return PresentationRequest(
            bindings._object_from_json(
                "anoncreds_presentation_request_from_json", value
            )
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
        cred: Union[Credential, W3cCredential],
        timestamp: Optional[int] = None,
        rev_state: Union[None, str, "CredentialRevocationState"] = None,
    ):
        if cred not in self.entries:
            self.entries[cred] = {}
        if rev_state and not isinstance(rev_state, bindings.AnoncredsObject):
            rev_state = CredentialRevocationState.load(rev_state)
        if timestamp not in self.entries[cred]:
            self.entries[cred][timestamp] = [set(), set(), rev_state]
        elif rev_state:
            self.entries[cred][timestamp][2] = rev_state
        return self.entries[cred][timestamp]

    def add_attributes(
        self,
        cred: Union[Credential, W3cCredential],
        *referents: Sequence[str],
        reveal: bool = True,
        timestamp: Optional[int] = None,
        rev_state: Union[None, str, "CredentialRevocationState"] = None,
    ):
        if not referents:
            return
        entry = self._get_entry(cred, timestamp, rev_state)
        for reft in referents:
            entry[0].add((reft, reveal))

    def add_predicates(
        self,
        cred: Union[Credential, W3cCredential],
        *referents: Sequence[str],
        timestamp: Optional[int] = None,
        rev_state: Union[None, str, "CredentialRevocationState"] = None,
    ):
        if not referents:
            return
        entry = self._get_entry(cred, timestamp, rev_state)
        for reft in referents:
            entry[1].add(reft)


class Presentation(bindings.AnoncredsObject):
    @classmethod
    def create(
        cls,
        pres_req: Union[str, PresentationRequest],
        present_creds: PresentCredentials,
        self_attest: Optional[Mapping[str, str]],
        link_secret: str,
        schemas: Mapping[str, Union[str, Schema]],
        cred_defs: Mapping[str, Union[str, CredentialDefinition]],
    ) -> "Presentation":
        if not isinstance(pres_req, bindings.AnoncredsObject):
            pres_req = PresentationRequest.load(pres_req)
        schema_ids = list(schemas.keys())
        cred_def_ids = list(cred_defs.keys())
        schema_handles = [
            (
                Schema.load(s) if not isinstance(s, bindings.AnoncredsObject) else s
            ).handle
            for s in schemas.values()
        ]
        cred_def_handles = [
            (
                CredentialDefinition.load(c)
                if not isinstance(c, bindings.AnoncredsObject)
                else c
            ).handle
            for c in cred_defs.values()
        ]
        creds = []
        creds_prove = []
        for cred, cred_ts in present_creds.entries.items():
            for timestamp, (attrs, preds, rev_state) in cred_ts.items():
                entry_idx = len(creds)
                creds.append(
                    bindings.CredentialEntry.create(
                        cred, timestamp, rev_state and rev_state
                    )
                )
                for reft, reveal in attrs:
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
                self_attest or {},
                link_secret,
                schema_handles,
                schema_ids,
                cred_def_handles,
                cred_def_ids,
            )
        )

    @classmethod
    def load(cls, value: Union[dict, str, bytes, memoryview]) -> "Presentation":
        return Presentation(
            bindings._object_from_json("anoncreds_presentation_from_json", value)
        )

    def verify(
        self,
        pres_req: Union[str, PresentationRequest],
        schemas: Mapping[str, Union[str, Schema]],
        cred_defs: Mapping[str, Union[str, CredentialDefinition]],
        rev_reg_defs: Optional[
            Mapping[str, Union[str, "RevocationRegistryDefinition"]]
        ] = None,
        rev_status_lists: Optional[Sequence[Union[str, "RevocationStatusList"]]] = None,
        nonrevoked_interval_overrides: Optional[
            Sequence["NonrevokedIntervalOverride"]
        ] = None,
    ) -> bool:
        if not isinstance(pres_req, bindings.AnoncredsObject):
            pres_req = PresentationRequest.load(pres_req)

        schema_ids = list(schemas.keys())
        schema_handles = [
            (
                Schema.load(s) if not isinstance(s, bindings.AnoncredsObject) else s
            ).handle
            for s in schemas.values()
        ]

        cred_def_ids = list(cred_defs.keys())
        cred_def_handles = [
            (
                CredentialDefinition.load(c)
                if not isinstance(c, bindings.AnoncredsObject)
                else c
            ).handle
            for c in cred_defs.values()
        ]

        if rev_reg_defs:
            rev_reg_def_ids = list(rev_reg_defs.keys())
            rev_reg_def_handles = [
                (
                    RevocationRegistryDefinition.load(r)
                    if not isinstance(r, bindings.AnoncredsObject)
                    else r
                ).handle
                for r in rev_reg_defs.values()
            ]
        else:
            rev_reg_def_ids = None
            rev_reg_def_handles = None

        if rev_status_lists:
            rev_status_list_handles = [
                (
                    RevocationStatusList.load(r)
                    if not isinstance(r, bindings.AnoncredsObject)
                    else r
                ).handle
                for r in rev_status_lists
            ]
        else:
            rev_status_list_handles = None

        nonrevoked_interval_overrides_native = []
        if nonrevoked_interval_overrides:
            for o in nonrevoked_interval_overrides:
                nonrevoked_interval_overrides_native.append(o._native)

        return bindings.verify_presentation(
            self.handle,
            pres_req.handle,
            schema_ids,
            schema_handles,
            cred_def_ids,
            cred_def_handles,
            rev_reg_def_ids,
            rev_reg_def_handles,
            rev_status_list_handles,
            nonrevoked_interval_overrides_native,
        )


class W3cPresentation(bindings.AnoncredsObject):
    @classmethod
    def create(
        cls,
        pres_req: Union[str, PresentationRequest],
        present_creds: PresentCredentials,
        link_secret: str,
        schemas: Mapping[str, Union[str, Schema]],
        cred_defs: Mapping[str, Union[str, CredentialDefinition]],
        w3c_version: Optional[str] = None,
    ) -> "W3cPresentation":
        if not isinstance(pres_req, bindings.AnoncredsObject):
            pres_req = PresentationRequest.load(pres_req)
        schema_ids = list(schemas.keys())
        cred_def_ids = list(cred_defs.keys())
        schema_handles = [
            (
                Schema.load(s) if not isinstance(s, bindings.AnoncredsObject) else s
            ).handle
            for s in schemas.values()
        ]
        cred_def_handles = [
            (
                CredentialDefinition.load(c)
                if not isinstance(c, bindings.AnoncredsObject)
                else c
            ).handle
            for c in cred_defs.values()
        ]
        creds = []
        creds_prove = []
        for cred, cred_ts in present_creds.entries.items():
            for timestamp, (attrs, preds, rev_state) in cred_ts.items():
                entry_idx = len(creds)
                creds.append(
                    bindings.CredentialEntry.create(
                        cred, timestamp, rev_state and rev_state
                    )
                )
                for reft, reveal in attrs:
                    creds_prove.append(
                        bindings.CredentialProve.attribute(entry_idx, reft, reveal)
                    )
                for reft in preds:
                    creds_prove.append(
                        bindings.CredentialProve.predicate(entry_idx, reft)
                    )
        return W3cPresentation(
            bindings.create_w3c_presentation(
                pres_req.handle,
                creds,
                creds_prove,
                link_secret,
                schema_handles,
                schema_ids,
                cred_def_handles,
                cred_def_ids,
                w3c_version,
            )
        )

    @classmethod
    def load(cls, value: Union[dict, str, bytes, memoryview]) -> "W3cPresentation":
        return W3cPresentation(
            bindings._object_from_json("anoncreds_w3c_presentation_from_json", value)
        )

    def verify(
        self,
        pres_req: Union[str, PresentationRequest],
        schemas: Mapping[str, Union[str, Schema]],
        cred_defs: Mapping[str, Union[str, CredentialDefinition]],
        rev_reg_defs: Optional[
            Mapping[str, Union[str, "RevocationRegistryDefinition"]]
        ] = None,
        rev_status_lists: Optional[Sequence[Union[str, "RevocationStatusList"]]] = None,
        nonrevoked_interval_overrides: Optional[
            Sequence["NonrevokedIntervalOverride"]
        ] = None,
    ) -> bool:
        if not isinstance(pres_req, bindings.AnoncredsObject):
            pres_req = PresentationRequest.load(pres_req)

        schema_ids = list(schemas.keys())
        schema_handles = [
            (
                Schema.load(s) if not isinstance(s, bindings.AnoncredsObject) else s
            ).handle
            for s in schemas.values()
        ]

        cred_def_ids = list(cred_defs.keys())
        cred_def_handles = [
            (
                CredentialDefinition.load(c)
                if not isinstance(c, bindings.AnoncredsObject)
                else c
            ).handle
            for c in cred_defs.values()
        ]

        if rev_reg_defs:
            rev_reg_def_ids = list(rev_reg_defs.keys())
            rev_reg_def_handles = [
                (
                    RevocationRegistryDefinition.load(r)
                    if not isinstance(r, bindings.AnoncredsObject)
                    else r
                ).handle
                for r in rev_reg_defs.values()
            ]
        else:
            rev_reg_def_ids = None
            rev_reg_def_handles = None

        if rev_status_lists:
            rev_status_list_handles = [
                (
                    RevocationStatusList.load(r)
                    if not isinstance(r, bindings.AnoncredsObject)
                    else r
                ).handle
                for r in rev_status_lists
            ]
        else:
            rev_status_list_handles = None

        nonrevoked_interval_overrides_native = []
        if nonrevoked_interval_overrides:
            for o in nonrevoked_interval_overrides:
                nonrevoked_interval_overrides_native.append(o._native)

        return bindings.verify_w3c_presentation(
            self.handle,
            pres_req.handle,
            schema_ids,
            schema_handles,
            cred_def_ids,
            cred_def_handles,
            rev_reg_def_ids,
            rev_reg_def_handles,
            rev_status_list_handles,
            nonrevoked_interval_overrides_native,
        )


class RevocationRegistryDefinitionPrivate(bindings.AnoncredsObject):
    @classmethod
    def load(
        cls, value: Union[dict, str, bytes, memoryview]
    ) -> "RevocationRegistryDefinitionPrivate":
        return RevocationRegistryDefinitionPrivate(
            bindings._object_from_json(
                "anoncreds_revocation_registry_definition_private_from_json", value
            )
        )


class RevocationStatusList(bindings.AnoncredsObject):
    @classmethod
    def create(
        self,
        cred_def: Union[dict, str, bytes, CredentialDefinition],
        rev_reg_def_id: str,
        rev_reg_def: Union[dict, str, bytes, RevocationRegistryDefinition],
        rev_reg_def_private: Union[
            dict, str, bytes, RevocationRegistryDefinitionPrivate
        ],
        issuer_id: str,
        issuance_by_default: bool = True,
        timestamp: Optional[int] = None,
    ) -> "RevocationStatusList":
        if not isinstance(rev_reg_def, bindings.AnoncredsObject):
            rev_reg_def = RevocationRegistryDefinition.load(rev_reg_def)

        return RevocationStatusList(
            bindings.create_revocation_status_list(
                cred_def.handle,
                rev_reg_def_id,
                rev_reg_def.handle,
                rev_reg_def_private.handle,
                issuer_id,
                issuance_by_default,
                timestamp,
            )
        )

    @classmethod
    def load(
        self, value: Union[dict, str, bytes, memoryview]
    ) -> "RevocationStatusList":
        return RevocationStatusList(
            bindings._object_from_json(
                "anoncreds_revocation_status_list_from_json", value
            )
        )

    def update_timestamp_only(self, timestamp: int):
        self.handle = bindings.update_revocation_status_list_timestamp_only(
            timestamp, self.handle
        )

    def update(
        self,
        cred_def: Union[dict, str, bytes, CredentialDefinition],
        rev_reg_def: Union[dict, str, bytes, RevocationRegistryDefinition],
        rev_reg_def_private: Union[
            dict, str, bytes, RevocationRegistryDefinitionPrivate
        ],
        issued: Optional[Sequence[int]],
        revoked: Optional[Sequence[int]],
        timestamp: Optional[int],
    ):
        if not isinstance(rev_reg_def, bindings.AnoncredsObject):
            rev_reg_def = RevocationRegistryDefinition.load(rev_reg_def)

        new_list = bindings.update_revocation_status_list(
            cred_def.handle,
            rev_reg_def.handle,
            rev_reg_def_private.handle,
            self.handle,
            issued,
            revoked,
            timestamp,
        )
        return RevocationStatusList(new_list)


class RevocationRegistry(bindings.AnoncredsObject):
    @classmethod
    def load(cls, value: Union[dict, str, bytes, memoryview]) -> "RevocationRegistry":
        return RevocationRegistry(
            bindings._object_from_json("anoncreds_revocation_registry_from_json", value)
        )


class CredentialRevocationConfig:
    def __init__(
        self,
        rev_reg_def: Union[str, "RevocationRegistryDefinition"],
        rev_reg_def_private: Union[str, "RevocationRegistryDefinitionPrivate"],
        rev_status_list: Union[str, "RevocationStatusList"],
        rev_reg_index: int,
    ):
        if not isinstance(rev_reg_def, bindings.AnoncredsObject):
            rev_reg_def = RevocationRegistryDefinition.load(rev_reg_def)
        self.rev_reg_def = rev_reg_def
        if not isinstance(rev_reg_def_private, bindings.AnoncredsObject):
            rev_reg_def_private = RevocationRegistryDefinitionPrivate.load(
                rev_reg_def_private
            )
        if not isinstance(rev_status_list, bindings.AnoncredsObject):
            rev_status_list = RevocationStatusList.load(rev_status_list)
        self.rev_reg_def_private = rev_reg_def_private
        self.rev_status_list = rev_status_list
        self.rev_reg_index = rev_reg_index

    @property
    def _native(self) -> bindings.RevocationConfig:
        return bindings.RevocationConfig.create(
            self.rev_reg_def,
            self.rev_reg_def_private,
            self.rev_status_list,
            self.rev_reg_index,
        )


class NonrevokedIntervalOverride:
    def __init__(
        self,
        rev_reg_def_id: str,
        requested_from_ts: int,
        override_rev_status_list_ts: int,
    ):
        self.rev_reg_def_id = rev_reg_def_id
        self.requested_from_ts = requested_from_ts
        self.override_rev_status_list_ts = override_rev_status_list_ts

    @property
    def _native(self) -> bindings.NonrevokedIntervalOverride:
        return bindings.NonrevokedIntervalOverride.create(
            self.rev_reg_def_id,
            self.requested_from_ts,
            self.override_rev_status_list_ts,
        )


class CredentialRevocationState(bindings.AnoncredsObject):
    @classmethod
    def create(
        cls,
        rev_reg_def: Union[str, RevocationRegistryDefinition],
        rev_status_list: Union[str, RevocationStatusList],
        rev_reg_idx: int,
        tails_path: str,
        rev_state: Optional[Union[str, "CredentialRevocationState"]] = None,
        old_rev_status_list: Optional[Union[str, RevocationStatusList]] = None,
    ) -> "CredentialRevocationState":
        if not isinstance(rev_reg_def, bindings.AnoncredsObject):
            rev_reg_def = RevocationRegistryDefinition.load(rev_reg_def)

        if not isinstance(rev_status_list, bindings.AnoncredsObject):
            rev_status_list = RevocationStatusList.load(rev_status_list)

        if rev_state and not isinstance(rev_state, bindings.AnoncredsObject):
            rev_state = CredentialRevocationState.load(rev_state)

        if old_rev_status_list and not isinstance(
            old_rev_status_list, bindings.AnoncredsObject
        ):
            old_rev_status_list = RevocationStatusList.load(old_rev_status_list)

        return CredentialRevocationState(
            bindings.create_or_update_revocation_state(
                rev_reg_def.handle,
                rev_status_list.handle,
                rev_reg_idx,
                tails_path,
                rev_state.handle if rev_state else None,
                old_rev_status_list.handle if old_rev_status_list else None,
            )
        )

    @classmethod
    def load(
        cls, value: Union[dict, str, bytes, memoryview]
    ) -> "CredentialRevocationState":
        return CredentialRevocationState(
            bindings._object_from_json("anoncreds_revocation_state_from_json", value)
        )

    def update(
        self,
        rev_reg_def: Union[str, RevocationRegistryDefinition],
        rev_status_list: Union[str, RevocationStatusList],
        rev_reg_index: int,
        tails_path: str,
        old_rev_status_list: Optional[Union[str, RevocationStatusList]] = None,
    ):
        if not isinstance(rev_reg_def, bindings.AnoncredsObject):
            rev_reg_def = RevocationRegistryDefinition.load(rev_reg_def)
        if not isinstance(rev_status_list, bindings.AnoncredsObject):
            rev_status_list = RevocationStatusList.load(rev_status_list)
        if old_rev_status_list and not isinstance(
            old_rev_status_list, bindings.AnoncredsObject
        ):
            old_rev_status_list = RevocationStatusList.load(old_rev_status_list)

        self.handle = bindings.create_or_update_revocation_state(
            rev_reg_def.handle,
            rev_status_list.handle,
            rev_reg_index,
            tails_path,
            self.handle,
            old_rev_status_list.handle if old_rev_status_list else None,
        )
