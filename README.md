# anoncreds-rs

Rust library and reference implementation of the [Anoncreds V1.0
specification](https://hyperledger.github.io/anoncreds-spec/).

The AnonCreds (Anonymous Credentials) specification is based on the open source
verifiable credential implementation of AnonCreds that has been in use since
2017, initially as part of the Hyperledger Indy open source project and now in
the Hyperledger AnonCreds project. The extensive use of AnonCreds around the
world has made it a de facto standard for ZKP-based verifiable credentials, and
this specification is the formalization of that implementation.

## Library

Anoncreds-rs exposes three main parts: [`issuer`](./src/services/issuer.rs),
[`prover`](./src/services/prover.rs) and
[`verifier`](./src/services/verifier.rs).

### Issuer

- Create a [schema](https://hyperledger.github.io/anoncreds-spec/#schema-publisher-publish-schema-object)
- Create a [credential definition](https://hyperledger.github.io/anoncreds-spec/#issuer-create-and-publish-credential-definition-object)
- Create a [revocation registry definition](https://hyperledger.github.io/anoncreds-spec/#issuer-create-and-publish-revocation-registry-objects)
- Create a [revocation status list](https://hyperledger.github.io/anoncreds-spec/#publishing-the-initial-initial-revocation-status-list-object)
- Update a [revocation status list](https://hyperledger.github.io/anoncreds-spec/#publishing-the-initial-initial-revocation-status-list-object)
- Update a [revocation status list](https://hyperledger.github.io/anoncreds-spec/#publishing-the-initial-initial-revocation-status-list-object)'s timestamp
- Create a [credential offer](https://hyperledger.github.io/anoncreds-spec/#credential-offer)
- Create a [credential](https://hyperledger.github.io/anoncreds-spec/#issue-credential)

### Prover / Holder

- Create a [credential request](https://hyperledger.github.io/anoncreds-spec/#credential-request)
- Process an incoming [credential](https://hyperledger.github.io/anoncreds-spec/#receiving-a-credential)
- Create a [presentation](https://hyperledger.github.io/anoncreds-spec/#generate-presentation)
- Create, and update, a revocation state
- Create, and update, a revocation state with a witness

### Verifier

- [Verify a presentation](https://hyperledger.github.io/anoncreds-spec/#verify-presentation)
- generate a nonce

## Wrappers

Anoncreds is, soon, available as a standalone library in Rust, but also via wrappers.

| Language     | Directory                                                                               | Status |
| ------------ | --------------------------------------------------------------------------------------- | ------ |
| Node.js      | [javascript](https://github.com/hyperledger/anoncreds-rs/tree/main/wrappers/javascript) | ✅     |
| React Native | [javascript](https://github.com/hyperledger/anoncreds-rs/tree/main/wrappers/javascript) | ✅     |
| Python       | [python](https://github.com/hyperledger/anoncreds-rs/tree/main/wrappers/python)         | 🚧     |


## Credit

The initial implementation of `anoncreds-rs` is derived from `indy-shared-rs`
that was developed by the Verifiable Organizations Network (VON) team based at
the Province of British Columbia, and derives largely from the implementations
within [Hyperledger Indy-SDK](https://github.com/hyperledger/indy-sdk). To
learn more about VON and what's happening with decentralized identity in
British Columbia, please go to [https://vonx.io](https://vonx.io).

## Contributing

Pull requests are welcome! Please read our [contributions
guide](https://github.com/hyperledger/anoncreds-rs/blob/main/CONTRIBUTING.md)
and submit your PRs. We enforce [developer certificate of
origin](https://developercertificate.org/) (DCO) commit signing. See guidance
[here](https://github.com/apps/dco).

We also welcome issues submitted about problems you encounter in using
`anoncreds-rs` or any of the wrappers.

## License

[Apache License Version
2.0](https://github.com/hyperledger/anoncreds-rs/blob/main/LICENSE)
