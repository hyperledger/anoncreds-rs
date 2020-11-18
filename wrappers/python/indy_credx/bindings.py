"""Low-level interaction with the indy-credx library."""

import json
import logging
import os
import sys
from ctypes import (
    POINTER,
    CDLL,
    byref,
    c_char_p,
    c_int8,
    c_int64,
    c_size_t,
    c_void_p,
    Structure,
)
from ctypes.util import find_library
from typing import Optional, Mapping, Sequence, Union

from .error import CredxError, CredxErrorCode


CALLBACKS = {}
LIB: CDLL = None
LOGGER = logging.getLogger(__name__)


class ObjectHandle(c_int64):
    """Index of an active IndyObject instance."""

    @property
    def type_name(self) -> str:
        return object_get_type_name(self)

    def __repr__(self) -> str:
        """Format object handle as a string."""
        return f'{self.__class__.__name__}("{self.type_name}", {self.value})'

    def __del__(self):
        object_free(self)


class IndyObject:
    """A generic Indy object allocated by the library."""

    def __init__(self, handle: ObjectHandle) -> "IndyObject":
        self.handle = handle

    def __repr__(self) -> str:
        """Format object as a string."""
        return f"{self.__class__.__name__}({self.handle.value})"

    def to_json(self) -> str:
        return str(object_get_json(self.handle))


class lib_string(c_char_p):
    """A string allocated by the library."""

    @classmethod
    def from_param(cls):
        """Returns the type ctypes should use for loading the result."""
        return c_void_p

    def opt_str(self) -> Optional[str]:
        return self.value.decode("utf-8") if self.value is not None else None

    def __bytes__(self):
        """Convert to bytes."""
        return self.value

    def __str__(self):
        """Convert to str."""
        # not allowed to return None
        return self.value.decode("utf-8") if self.value is not None else ""

    def __del__(self):
        """Call the string destructor when this instance is released."""
        get_library().credx_string_free(self)


class object_handle_list(Structure):
    _fields_ = [
        ("count", c_size_t),
        ("data", POINTER(ObjectHandle)),
    ]

    @classmethod
    def create(cls, values: Optional[Sequence[ObjectHandle]]) -> "object_handle_list":
        inst = object_handle_list()
        if values is not None:
            values = list(values)
            inst.count = len(values)
            inst.data = (ObjectHandle * inst.count)(*values)
        return inst


class str_list(Structure):
    _fields_ = [
        ("count", c_size_t),
        ("data", POINTER(c_char_p)),
    ]

    @classmethod
    def create(cls, values: Optional[Sequence[str]]) -> "str_list":
        inst = str_list()
        if values is not None:
            values = [encode_str(v) for v in values]
            inst.count = len(values)
            inst.data = (c_char_p * inst.count)(*values)
        return inst


class CredentialProve(Structure):
    _fields_ = [
        ("cred_idx", c_int64),
        ("referent", c_char_p),
        ("is_predicate", c_int8),
        ("reveal", c_int8),
        ("timestamp", c_int64),
    ]

    @classmethod
    def attribute(
        cls, idx: int, referent: str, reveal: bool, timestamp: int = None
    ) -> "CredentialProve":
        return CredentialProve(
            cred_idx=idx,
            referent=encode_str(referent),
            is_predicate=False,
            reveal=reveal,
            timestamp=-1 if timestamp is None else timestamp,
        )

    @classmethod
    def predicate(
        cls, idx: int, referent: str, timestamp: int = None
    ) -> "CredentialProve":
        return CredentialProve(
            cred_idx=idx,
            referent=encode_str(referent),
            is_predicate=True,
            reveal=True,
            timestamp=-1 if timestamp is None else timestamp,
        )


class CredentialProveList(Structure):
    _fields_ = [
        ("count", c_int64),
        ("data", POINTER(CredentialProve)),
    ]


def get_library() -> CDLL:
    """Return the CDLL instance, loading it if necessary."""
    global LIB
    if LIB is None:
        LIB = _load_library("indy_credx")
        do_call("credx_set_default_logger")
    return LIB


def library_version() -> str:
    """Get the version of the installed aries-askar library."""
    lib = get_library()
    lib.credx_version.restype = c_void_p
    return str(lib_string(lib.credx_version()))


def _load_library(lib_name: str) -> CDLL:
    """Load the CDLL library.
    The python module directory is searched first, followed by the usual
    library resolution for the current system.
    """
    lib_prefix_mapping = {"win32": ""}
    lib_suffix_mapping = {"darwin": ".dylib", "win32": ".dll"}
    try:
        os_name = sys.platform
        lib_prefix = lib_prefix_mapping.get(os_name, "lib")
        lib_suffix = lib_suffix_mapping.get(os_name, ".so")
        lib_path = os.path.join(
            os.path.dirname(__file__), f"{lib_prefix}{lib_name}{lib_suffix}"
        )
        return CDLL(lib_path)
    except KeyError:
        LOGGER.debug("Unknown platform for shared library")
    except OSError:
        LOGGER.warning("Library not loaded from python package")

    lib_path = find_library(lib_name)
    if not lib_path:
        raise CredxError(CredxErrorCode.WRAPPER, f"Error loading library: {lib_name}")
    try:
        return CDLL(lib_path)
    except OSError as e:
        raise CredxError(
            CredxErrorCode.WRAPPER, f"Error loading library: {lib_name}"
        ) from e


def do_call(fn_name, *args):
    """Perform a synchronous library function call."""
    lib_fn = getattr(get_library(), fn_name)
    result = lib_fn(*args)
    if result:
        raise get_current_error(True)


def get_current_error(expect: bool = False) -> Optional[CredxError]:
    """
    Get the error result from the previous failed API method.

    Args:
        expect: Return a default error message if none is found
    """
    err_json = lib_string()
    if not get_library().credx_get_current_error(byref(err_json)):
        try:
            msg = json.loads(err_json.value)
        except json.JSONDecodeError:
            LOGGER.warning("JSON decode error for credx_get_current_error")
            msg = None
        if msg and "message" in msg and "code" in msg:
            return CredxError(
                CredxErrorCode(msg["code"]), msg["message"], msg.get("extra")
            )
        if not expect:
            return None
    return CredxError(CredxErrorCode.WRAPPER, "Unknown error")


def decode_str(value: c_char_p) -> str:
    return value.decode("utf-8")


def encode_str(arg: Optional[Union[str, bytes, memoryview]]) -> c_char_p:
    """
    Encode an optional input argument as a string.

    Returns: None if the argument is None, otherwise the value encoded utf-8.
    """
    if arg is None:
        return c_char_p()
    if isinstance(arg, str):
        return c_char_p(arg.encode("utf-8"))
    return c_char_p(arg)


def object_free(handle: ObjectHandle):
    get_library().credx_object_free(handle)


def object_get_json(handle: ObjectHandle) -> lib_string:
    result = lib_string()
    do_call("credx_object_get_json", handle, byref(result))
    return result


def object_get_type_name(handle: ObjectHandle) -> lib_string:
    result = lib_string()
    do_call("credx_object_get_type_name", handle, byref(result))
    return result


def _object_from_json(method: str, value: str) -> ObjectHandle:
    result = ObjectHandle()
    do_call(method, encode_str(value), byref(result))
    return result


def generate_nonce() -> str:
    result = lib_string()
    do_call("credx_generate_nonce", byref(result))
    return str(result)


def create_schema(
    origin_did: str,
    name: str,
    version: str,
    attr_names: Sequence[str],
    seq_no: int = None,
) -> ObjectHandle:
    result = ObjectHandle()
    attrs = str_list.create(attr_names)
    do_call(
        "credx_create_schema",
        encode_str(origin_did),
        encode_str(name),
        encode_str(version),
        attrs,
        c_int64(seq_no or -1),
        byref(result),
    )
    return result


def schema_get_id(handle: ObjectHandle) -> lib_string:
    result = lib_string()
    do_call(
        "credx_schema_get_id",
        handle,
        byref(result),
    )
    return result


def create_credential_definition(
    origin_did: str,
    schema: ObjectHandle,
    tag: Optional[str],
    signature_type: str,
    support_revocation: bool,
) -> (ObjectHandle, ObjectHandle, ObjectHandle):
    cred_def, cred_def_pvt, key_proof = ObjectHandle(), ObjectHandle(), ObjectHandle()
    do_call(
        "credx_create_credential_definition",
        encode_str(origin_did),
        schema,
        encode_str(tag),
        encode_str(signature_type),
        c_int8(support_revocation),
        byref(cred_def),
        byref(cred_def_pvt),
        byref(key_proof),
    )
    return (cred_def, cred_def_pvt, key_proof)


def credential_definition_get_id(handle: ObjectHandle) -> lib_string:
    result = lib_string()
    do_call(
        "credx_credential_definition_get_id",
        handle,
        byref(result),
    )
    return result


def create_credential(
    cred_def: ObjectHandle,
    cred_def_private: ObjectHandle,
    cred_offer: ObjectHandle,
    cred_request: ObjectHandle,
    attr_raw_values: Mapping[str, str],
    attr_enc_values: Optional[Mapping[str, str]],
    _revocation_config,
) -> ObjectHandle:
    cred = ObjectHandle()
    names_list = str_list.create(attr_raw_values.keys())
    raw_values_list = str_list.create(attr_raw_values.values())
    if attr_enc_values:
        enc_values_list = []
        for name in attr_raw_values:
            enc_values_list.append(attr_enc_values.get(name))
    else:
        enc_values_list = None
    enc_values_list = str_list().create(enc_values_list)
    do_call(
        "credx_create_credential",
        cred_def,
        cred_def_private,
        cred_offer,
        cred_request,
        names_list,
        raw_values_list,
        enc_values_list,
        byref(cred),
    )
    return cred


def process_credential(
    cred: ObjectHandle,
    cred_req_metadata: ObjectHandle,
    master_secret: ObjectHandle,
    cred_def: ObjectHandle,
    rev_reg_def: Optional[ObjectHandle],
) -> ObjectHandle:
    result = ObjectHandle()
    do_call(
        "credx_process_credential",
        cred,
        cred_req_metadata,
        master_secret,
        cred_def,
        byref(result),
    )
    return result


def create_credential_offer(
    schema_id: str, cred_def: ObjectHandle, key_proof: ObjectHandle
) -> ObjectHandle:
    cred_offer = ObjectHandle()
    do_call(
        "credx_create_credential_offer",
        encode_str(schema_id),
        cred_def,
        key_proof,
        byref(cred_offer),
    )
    return cred_offer


def create_credential_request(
    prover_did: str,
    cred_def: ObjectHandle,
    master_secret: ObjectHandle,
    master_secret_id: str,
    cred_offer: ObjectHandle,
) -> (ObjectHandle, ObjectHandle):
    cred_req, cred_req_metadata = ObjectHandle(), ObjectHandle()
    do_call(
        "credx_create_credential_request",
        encode_str(prover_did),
        cred_def,
        master_secret,
        encode_str(master_secret_id),
        cred_offer,
        byref(cred_req),
        byref(cred_req_metadata),
    )
    return (cred_req, cred_req_metadata)


def create_master_secret() -> ObjectHandle:
    secret = ObjectHandle()
    do_call(
        "credx_create_master_secret",
        byref(secret),
    )
    return secret


def create_presentation(
    proof_req: ObjectHandle,
    self_attest: Mapping[str, str],
    creds: Sequence[ObjectHandle],
    creds_prove: Sequence[CredentialProve],
    master_secret: ObjectHandle,
    schemas: Sequence[ObjectHandle],
    cred_defs: Sequence[ObjectHandle],
    # rev_states: Sequence[ObjectHandle],
) -> ObjectHandle:
    prove_list = CredentialProveList()
    prove_list.count = len(creds_prove)
    prove_list.data = (CredentialProve * prove_list.count)(*creds_prove)
    present = ObjectHandle()
    do_call(
        "credx_create_presentation",
        proof_req,
        str_list.create(self_attest.keys()),
        str_list.create(self_attest.values()),
        object_handle_list.create(creds),
        prove_list,
        master_secret,
        object_handle_list.create(schemas),
        object_handle_list.create(cred_defs),
        byref(present),
    )
    return present


def schema_from_json(json: str) -> ObjectHandle:
    return _object_from_json("credx_schema_from_json", json)


def credential_definition_from_json(json: str) -> ObjectHandle:
    return _object_from_json("credx_credential_definition_from_json", json)


def credential_definition_private_from_json(json: str) -> ObjectHandle:
    return _object_from_json("credx_credential_definition_private_from_json", json)


def key_correctness_proof_from_json(json: str) -> ObjectHandle:
    return _object_from_json("credx_key_correctness_proof_from_json", json)


def credential_offer_from_json(json: str) -> ObjectHandle:
    return _object_from_json("credx_credential_offer_from_json", json)


def credential_request_from_json(json: str) -> ObjectHandle:
    return _object_from_json("credx_credential_request_from_json", json)


def credential_request_metadata_from_json(json: str) -> ObjectHandle:
    return _object_from_json("credx_credential_request_metadata_from_json", json)


def credential_from_json(json: str) -> ObjectHandle:
    return _object_from_json("credx_credential_from_json", json)


def master_secret_from_json(json: str) -> ObjectHandle:
    return _object_from_json("credx_master_secret_from_json", json)


def presentation_request_from_json(json: str) -> ObjectHandle:
    return _object_from_json("credx_presentation_request_from_json", json)
