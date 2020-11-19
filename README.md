# indy-shared-rs

Shared Rust data types and utility functions for Hyperledger Indy.

- `indy-credx`: Indy verifiable credential issuance and presentation (aka Anoncreds)

- `indy-data-types`: Struct definitions for Schemas, Credential Definitions and other
  types related to credential issuance and processing

- `indy-test-utils`: Utilities for use in integration tests.

- `indy-utils`: Standard wrappers around binary data encodings and Ursa-provided
  cryptography functions. Includes support for representing WQL (wallet query
  language) expressions, normalizing transactions for signing, deriving DIDs and
  verification keys, and packing and unpacking agent messages using the DIDComm
  v1 envelope format.
