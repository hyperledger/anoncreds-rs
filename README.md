# indy-shared-rs

Shared Rust libraries for Hyperledger Indy.

- `indy-credx`: Indy verifiable credential issuance and presentation (aka Anoncreds)

- `indy-data-types`: Data type definitions for Schemas, Credential Definitions and other
  types related to credential issuance and processing

- `indy-test-utils`: Utilities for use in integration tests.

- `indy-utils`: Standard wrappers around binary data encodings and Ursa-provided
  cryptography functions. Includes support for representing WQL (wallet query
  language) expressions, normalizing transactions for signing, deriving DIDs and
  verification keys, and packing and unpacking agent messages using the DIDComm
  v1 envelope format.

## Credit

The initial implementation of `indy-shared-rs` was developed by the Verifiable Organizations Network (VON) team based at the Province of British Columbia, and derives largely from the implementations within [Hyperledger Indy-SDK](https://github.com/hyperledger/indy-sdk). To learn more about VON and what's happening with decentralized identity in British Columbia, please go to [https://vonx.io](https://vonx.io).

## Contributing

Pull requests are welcome! Please read our [contributions guide](https://github.com/hyperledger/indy-shared-rs/blob/master/CONTRIBUTING.md) and submit your PRs. We enforce [developer certificate of origin](https://developercertificate.org/) (DCO) commit signing. See guidance [here](https://github.com/apps/dco).

We also welcome issues submitted about problems you encounter in using `indy-shared-rs`.

## License

[Apache License Version 2.0](https://github.com/hyperledger/indy-shared-rs/blob/master/LICENSE)
