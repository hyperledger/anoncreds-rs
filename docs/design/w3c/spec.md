## W3C Verifiable Credentials Representation

This section describes how Indy-styled AnonCreds credentials can be represented in the form of W3C Verifiable
Credentials standard.

### Credential

This section describes how [W3C credential concepts](https://www.w3.org/TR/vc-data-model/#basic-concepts) are applied to
AnonCreds W3C credential representation.

Example of an AnonCreds W3C formatted credential which will be explained in details:

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://github.io/anoncreds-w3c/context.json"
  ],
  "type": [
    "VerifiableCredential",
    "AnonCredsCredential"
  ],
  "issuer": "did:sov:3avoBCqDMFHFaKUHug9s8W",
  "issuanceDate": "2023-10-26T01:17:32Z",
  "credentialSchema": {
    "type": "AnonCredsDefinition",
    "definition": "did:sov:3avoBCqDMFHFaKUHug9s8W:3:CL:13:default",
    "schema": "did:sov:3avoBCqDMFHFaKUHug9s8W:2:basic_person:0.1.0",
    "encoding": "auto"
  },
  "credentialSubject": {
    "firstName": "Alice",
    "lastName": "Jones",
    "age": "18"
  },
  "proof": [
    {
      "type": "CLSignature2023",
      "signature": "AAAgf9w5.....8Z_x3FqdwRHoWruiF0FlM"
    },
    {
      "type": "Ed25519Signature2020",
      "created": "2021-11-13T18:19:39Z",
      "verificationMethod": "did:sov:3avoBCqDMFHFaKUHug9s8W#key-1",
      "proofPurpose": "assertionMethod",
      "proofValue": "z58DAdFfa9SkqZMVPxAQpic7ndSayn1PzZs6ZjWp1CktyGesjuTSwRdoWhAfGFCF5bppETSTojQCrfFPP2oumHKtz"
    }
  ]
}
```

#### Context

W3C [Context](https://www.w3.org/TR/vc-data-model/#contexts) section requires including of `@context` property to
verifiable credential.

The value of the `@context` property must be one or more resolvable [URI](https://www.w3.org/TR/vc-data-model/#dfn-uri)
that result in machine-readable [JSON-LD](https://www.w3.org/TR/vc-data-model/#json-ld) information about the object
format.

The **context** definition used for AnonCreds W3C credentials representation can be found [here](./context.json).

In the case of W3C AnonCreds credentials, the `@context` attribute includes an extra
entry `https://github.io/anoncreds-w3c/context.json`
which is required for the resolution of custom structure definitions and looks the following:

```
{
  ...  
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://github.io/anoncreds-w3c/context.json"
  ],
  ...
}
```

#### Identifiers

W3C [Identifiers](https://www.w3.org/TR/vc-data-model/#identifiers) section defines an optional capability to assign
some kind of identifier to the verifiable credential so that others can express statements about the same thing.

In the case of W3C AnonCreds credentials, the `id` attribute is not recommended to set.

#### Types

W3C [Types](https://www.w3.org/TR/vc-data-model/#types) section requires including of `type` property to verifiable
credential.
The value of the `type` property must be one or more [URI](https://www.w3.org/TR/vc-data-model/#dfn-uri) resolvable
through the defined `@context` to the information required for determining whether a verifiable credential or verifiable
presentation has a valid structure.

In the case of W3C AnonCreds credentials, the `type` attribute includes an extra entry `AnonCredsCredential`
pointing to the difference in a base credential structure and looks the following:

```
{
  ... 
  "type": [
    "VerifiableCredential",         // general verifiable credential definition
    "AnonCredsCredential",          // definition for AnonCreds credentials
  ]
  ...
}
```

#### Credential Subject

W3C [Credential Subject](https://www.w3.org/TR/vc-data-model/#credential-subject) section requires including
of `credentialSubject` property to verifiable credential.

Credential subject value contains [claims](https://www.w3.org/TR/vc-data-model/#claims) about one or more subjects.

In the context of W3C Announced credentials, credential subject property is compliant with the following statements:

- credentials will always include claims about only one subjects.
    - So that `credentialSubject` property will always be represented as an object entry, but not an array.
- credentials claims are always represented as key value pairs, where `value` is the `raw` value of CL credential
  attributes.
    - encoded CL credential values are not included in the credential subject

In the case of W3C AnonCreds credentials, the `credentialSubject` attribute looks the following:

```
{
  ... 
  "credentialSubject": {
    "name": "Alice Jones",
  }
  ...
}
```

* **TO DISCUSS**: W3C data model allows attributes to be represented not only as key/value string pairs but also as
  objects and arrays.
    * If we want to support more complex representations for the W3C AnonCreds credential attributes and their
      presentations, we need to design following things:
        * how encoding will work for such attributes
        * how selective disclosure will work on top level attribute itself
            ```
              "credentialSubject": {
                "address": {
                    "type": "Address",
                    "city": "Foo",
                    "street": "Main str."
                }
              }
            ```

#### Data Schemas

W3C [Credential Subject](https://www.w3.org/TR/vc-data-model/#data-schemas) section defines an optional capability to
include `credentialSchema` property to enforce a specific structure on a given verifiable credential and encoding used
to map the claims of a verifiable credential to an alternative representation format.

In the context of W3C AnonCreds credentials defined a custom `AnonCredsDefinition` data schema in order to include the
following information to credential:

In the case of W3C AnonCreds credentials, the `credentialSchema` attribute defines a custom `AnonCredsDefinition`
schema in order to include the information about Indy related definitions to credential and looks the following:

```
{
  ... 
  "credentialSchema": {
    "type": "AnonCredsDefinition",
    "definition": "did:sov:3avoBCqDMFHFaKUHug9s8W:3:CL:13:default",
    "schema": "did:sov:3avoBCqDMFHFaKUHug9s8W:2:fabername:0.1.0",
    "encoding": "auto"
  },
  ...
}
```

* `schema` - id of Indy Schema
* `definition` - id of Indy Credential Definition
* `revocation` - id of Indy Revocation Registry
* `encoding` - attributes encoding algorithm
    * encoded credential attribute values (binary representation required for doing CL signatures) are not included
      neither to `credentialSubject` or `signature`
    * `encoding: auto` implies using the algorithm defined
      at [Aries RFC 0592 Indy Attachments section](https://github.com/hyperledger/aries-rfcs/tree/main/features/0592-indy-attachments#encoding-claims)
      to generate encoded values under the hood during the signature generation and proof verification.

#### Issuer

W3C [Issuer](https://www.w3.org/TR/vc-data-model/#issuer) section requires including of `issuer` property to express the
issuer of a verifiable credential.

In the case of W3C AnonCreds credentials, the `issuer` attribute should be represented as a
resolvable [DID URL](https://w3c-ccg.github.io/did-resolution/) having either `indy` or `sov` DID method and looks the
following:

```
{
  ... 
  "issuer": "did:sov:3avoBCqDMFHFaKUHug9s8W",
  ...
}
```

#### Issuance Date

W3C [Issuance Date](https://www.w3.org/TR/vc-data-model/#issuance-date) section requires including of `issuanceDate`
property to express the date and time when a credential becomes valid.

In the case of W3C AnonCreds credentials, for the `issuanceDate` attribute recommended setting of a random time of the
day when credential was issued or transformed and looks the following:

```
{
  ... 
  "issuanceDate": "2010-01-01T19:23:24Z",
  ...
}
```

#### Proofs (Signatures)

W3C [Proofs (Signatures)](https://www.w3.org/TR/vc-data-model/#proofs-signatures) section requires including of `proof`
property to express confirmation of the credential's validity.

According to the specification, one or many proof objects can be added to verifiable credentials.
In the context of W3C AnonCreds credentials included at least two proof object entries: AnonCreds CL
and [Data Integrity](https://www.w3.org/TR/vc-data-model/#data-integrity-proofs).

##### AnonCreds CL proof

This proof entry derived from the CL signature of a verifiable credential.

The defined `@context` includes a definition for the `CLSignature2022` type describing the format of the proof
entry:

```
{
  ... 
  "proof": [
    {
      "type": "CLSignature2022",
      "signature": "AAAgf9w5lZg....RYp8Z_x3FqdwRHoWruiF0FlM"
    }
  ]  
  ...
}
```

**Credential proof signature**

* `type` - `CLSignature2022`
* `signature` - credential signature
    * signature received by building the following object from indy styled credential:
      ```
      {
        "signature": {..}, 
        "signature_correctness_proof": {..}
      }
      ```
    * encoded
      as [base64 attachment](https://github.com/hyperledger/aries-rfcs/tree/main/concepts/0017-attachments#base64url)


* **TO DISCUSS**: Signature/Proof encoding: Which approach to use for encoding?
    * Basic approach used in Aries attachments: Base 64 encoding of object serialized as JSON string
    * Compact encoding implementing in Python PoC: Using the fact that most fields of credential signature and proof are big numbers

##### Data Integrity proof

In order to better conform to the W3C specification AnonCreds based credential also requires including
of [Data Integrity Proof](https://www.w3.org/TR/vc-data-model/#data-integrity-proofs) which must be generated using one
of NIST-approved algorithms (RSA, ECDSA, EdDSA).

Including Data Integrity proof allows to use verifiable credential without access to a Ledger.

#### Expiration

W3C [Expiration](https://www.w3.org/TR/vc-data-model/#expiration) section defines an optional capability to include
credential expiration information.

Instead of including `expirationDate` property we recommend using a standard indy credentials revocation approach and
include a revocation registry id into the credential schema.

#### Status

W3C [Status](https://www.w3.org/TR/vc-data-model/#status) section defines an optional capability to include credential
status information.

Instead of including `credentialStatus` property we recommend using a standard indy credentials revocation approach and
include a revocation registry id into the credential schema.

### Presentation

This section describes how [W3C presentation concepts](https://www.w3.org/TR/vc-data-model/#contexts) are applied to
AnonCreds
W3C presentation representation.

Example of an AnonCreds W3C presentation which will be explained in details:

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://github.io/anoncreds-w3c/context.json"
  ],
  "type": [
    "VerifiablePresentation",
    "AnonCredsPresentation"
  ],
  "verifiableCredential": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://github.io/anoncreds-w3c/context.json"
      ],
      "type": [
        "VerifiableCredential",
        "AnonCredsPresentation"
      ],
      "issuer": "did:sov:3avoBCqDMFHFaKUHug9s8W",
      "issuanceDate": "2023-10-26T01:17:32Z",
      "credentialSchema": {
        "type": "AnonCredsDefinition",
        "definition": "did:sov:3avoBCqDMFHFaKUHug9s8W:3:CL:13:default",
        "schema": "did:sov:3avoBCqDMFHFaKUHug9s8W:2:basic_person:0.1.0",
        "encoding": "auto"
      },
      "credentialSubject": {
        "firstName": "Alice"
      },
      "proof": {
        "type": "AnonCredsPresentationProof2022",
        "credential": {
          "mapping": {
            "revealedAttributes": [
              {
                "name": "firstName",
                "referent": "attribute_0"
              }
            ],
            "unrevealedAttributes": [
              {
                "name": "lastName",
                "referent": "attribute_1"
              }
            ],
            "requestedPredicates": [
              {
                "name": "age",
                "p_type": "<",
                "value": 18,
                "referent": "predicate_1"
              }
            ]
          },
          "proofValue": "AAEBAnr2Ql...0UhJ-bIIdWFKVWxjU3ePxv_7HoY5pUw"
        }
      }
    }
  ],
  "proof": {
    "type": "AnonCredsPresentationProof2022",
    "challenge": "182453895158932070575246",
    "proofValue": "AAAgtMR4....J19l-agSA"
  }
}
```

#### Context

W3C [Context](https://www.w3.org/TR/vc-data-model/#contexts) section requires including of `@context` property to
verifiable presentation.
The value of the `@context` property must be one or more resolvable [URI](https://www.w3.org/TR/vc-data-model/#dfn-uri)
that result in machine-readable [JSON-LD](https://www.w3.org/TR/vc-data-model/#json-ld) information about the object
format.

The complete **context** containing definitions used for AnonCreds W3C credentials representation can be
found [here](./context.json).

In the case of W3C AnonCreds presentations, the `@context` attribute includes an extra
entry `https://github.io/anoncreds-w3c/context.json`
which is required for the resolution of custom structure definitions and looks the following:

```
{
  ... 
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://github.io/anoncreds-w3c/context.json"
  ],
  ...
}
```

#### Types

W3C [Types](https://www.w3.org/TR/vc-data-model/#types) section requires including of `type` property to verifiable
presentation.
The value of the `type` property must be one or more [URI](https://www.w3.org/TR/vc-data-model/#dfn-uri) resolvable
through the defined `@context` to the information required for determining whether a verifiable
presentation has a valid structure.

In the case of W3C AnonCreds presentations, the `type` attribute includes an extra entry `AnonCredsPresentation`
pointing to the difference in a base presentation structure and looks the following:

```
{
  ... 
  "type": [
    "VerifiablePresentation",         // general verifiable presentation definition
    "AnonCredsPresentation"           // definition for AnonCreds presentation
  ]
  ...
}
```

#### Verifiable Credential

W3C [Verifiable Credential](https://www.w3.org/TR/vc-data-model/#presentations-0)section requires including
of `verifiableCredential` property to a verifiable presentation constructed from one or more verifiable credentials.

The values of verifiable credentials are mostly constructed the same as described at
the [Credential Structure](#credential) section.
The only difference is the value of the `proof` property.

In the case of W3C AnonCreds presentations, the `proof` attribute uses defined `AnonCredsPresentationProof2022`
type pointing to the difference in a presentation structure and looks the following:

```
  "proof": {
    "type": "AnonCredsPresentationProof2022",
    "credential": {
      "mapping": {
        "revealedAttributes": [
          {
            "name": "firstName",
            "referent": "attribute_0"
          }
        ],
        "unrevealedAttributes": [
          {
            "name": "lastName",
            "referent": "attribute_1"
          }
        ],
        "requestedPredicates": [
          {
            "name": "age",
            "p_type": "<",
            "value": 18,
            "referent": "predicate_1"
          }
        ]
      },
      "proofValue": "AAEBAnr2Ql...0UhJ-bIIdWFKVWxjU3ePxv_7HoY5pUw"
    }
  }
```

**Verifiable Credential Proof structure**

* `proofValue` - encoded proof generated for each specific credential
    * object created from Indy styled credential sub proof
    ```
        {
            primaryProof: {..},
            nonRevocProof: {..}
        }
    ```
    * encoded
      as [base64 attachment](https://github.com/hyperledger/aries-rfcs/tree/main/concepts/0017-attachments#base64url).
* `mapping` - date requested in the proof request
    * data: attribute name and reference in the proof request
        * `revealedAttributes` - list of requested attributes revealed using the credential
        * `unrevealedAttributes` - list of requested attributes presented in the credential but left unrevealed
        * `requestedPredicates` - list of predicates resolved using the credential


* **TO DISCUSS**: Should we remove `mapping` completely or move under encoded `proofValue`?
    * Why `mapping` is bad: we make presentation tied to Indy styled Presentation Request
    * Mapping is something old indy-fashioned required for validation (not signature verification) that proof matches to
      the request itself on the verifier side
    * For doing crypto `proofValue` verification we only need the names of revealed attributes and predicated (with
      type)


* **TO DISCUSS**: Should we derive an attribute from a predicate and put them into credentialSubject like it demonstrated
  in the [specification](https://www.w3.org/TR/vc-data-model/#presentations-using-derived-credentials)
    * Example:
        * For Predicate: `{"name": "birthdate", "p_type": "<", "value":"20041012"}`
        * Derived attribute: `{"birthdate": "birthdate less 20041012"}`
    * During the `proofValue` crypto verification we can parse the phrase and restore predicate attributes

#### Proof

W3C [Proofs (Signatures)](https://www.w3.org/TR/vc-data-model/#proofs-signatures) section requires including of `proof`
property to express confirmation of the presentation's validity.

As we described in the above section verifiable credentials will contain two proof entries (CL AnonCreds of Data
Integrity).
Unlike verifiable credentials, a presentation can contain only one proof object.

It is verifier and holder responsibility to negotiate which proof must be used (CL AnonCreds of Data Integrity) in the
presentation:

* Generate an W3C AnonCreds presentation, with all it’s privacy-preserving power and predicates
* Present the VC using one of Integrity Proof Signatures

```
{
  ... 
  "proof": {
    "type": "AnonCredsPresentationProof2022",
    "challenge": "182453895158932070575246",
    "proofValue": "AAAgtMR4DrkY--ZVgKHmUANE04ET7TzUxZ0vZmVcNt4nCkwBABUACQJ69kJVIxHVAQAIAaJ19l-agSA"
  }
  ...
}
```

**Presentation Proof structure**

* `challenge` - nonce taken from the presentation request
* `aggregated` - encoded aggregated proof value
    * object created from Indy proof data
    ```
        {
            aggregated: {..},
        }
    ```
    * encoded
      as [base64 attachment](https://github.com/hyperledger/aries-rfcs/tree/main/concepts/0017-attachments#base64url).
