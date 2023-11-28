# AnonCred-KMP

[![Kotlin](https://img.shields.io/badge/kotlin-1.8.20-blue.svg?logo=kotlin)](http://kotlinlang.org)

![apple-silicon](https://camo.githubusercontent.com/a92c841ffd377756a144d5723ff04ecec886953d40ac03baa738590514714921/687474703a2f2f696d672e736869656c64732e696f2f62616467652f737570706f72742d2535424170706c6553696c69636f6e2535442d3433424246462e7376673f7374796c653d666c6174)
![ios](https://camo.githubusercontent.com/1fec6f0d044c5e1d73656bfceed9a78fd4121b17e82a2705d2a47f6fd1f0e3e5/687474703a2f2f696d672e736869656c64732e696f2f62616467652f706c6174666f726d2d696f732d4344434443442e7376673f7374796c653d666c6174)
![jvm](https://camo.githubusercontent.com/700f5dcd442fd835875568c038ae5cd53518c80ae5a0cf12c7c5cf4743b5225b/687474703a2f2f696d672e736869656c64732e696f2f62616467652f706c6174666f726d2d6a766d2d4442343133442e7376673f7374796c653d666c6174)
![macos](https://camo.githubusercontent.com/1b8313498db244646b38a4480186ae2b25464e5e8d71a1920c52b2be5212b909/687474703a2f2f696d672e736869656c64732e696f2f62616467652f706c6174666f726d2d6d61636f732d3131313131312e7376673f7374796c653d666c6174)

## Introduction

This is a Kotlin MultiPlatform (KMP) wrapper of a rust library and reference implementation of the [Anoncreds V1.0
specification](https://hyperledger.github.io/anoncreds-spec/).


The AnonCreds (Anonymous Credentials) specification is based on the open source verifiable credential implementation of AnonCreds that has been in use since 2017, initially as part of the Hyperledger Indy open source project and now in the Hyperledger AnonCreds project. The extensive use of AnonCreds around the world has made it a de facto standard for ZKP-based verifiable credentials, and this specification is the formalization of that implementation.

## Library

AnonCred-KMP exposes three main parts: [`issuer`](./anoncred-wrapper-rust/src/issuer/mod.rs),
[`prover`](./anoncred-wrapper-rust/src/prover/mod.rs) and
[`verifier`](./anoncred-wrapper-rust/src/verifier/mod.rs).

The library provides wrapper for the following operations

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

## Requirement

- Rust v1.72.0
- KMP v1.8.20
