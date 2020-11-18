"""Error classes."""

from enum import IntEnum


class CredxErrorCode(IntEnum):
    SUCCESS = 0
    INPUT = 1
    IO_ERROR = 2
    INVALID_STATE = 3
    UNEXPECTED = 4
    CREDENTIAL_REVOKED = 5
    INVALID_USER_REVOC_ID = 6
    PROOF_REJECTED = 7
    REVOCATION_REGISTRY_FULL = 8
    WRAPPER = 99


class CredxError(Exception):
    def __init__(self, code: CredxErrorCode, message: str, extra: str = None):
        super().__init__(message)
        self.code = code
        self.extra = extra
