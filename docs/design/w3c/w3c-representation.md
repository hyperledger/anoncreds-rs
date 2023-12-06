## Design for W3C representation of AnonCreds credentials and presentation

Currently `anoncreds-rs` library only provides support for legacy Indy styled AnonCreds credentials matching to
the [specification](https://hyperledger.github.io/anoncreds-spec/).

This design document proposes extending of `anoncreds-rs` library to add support for AnonCreds W3C representation of
verifiable credential and presentation described in the [document]().

### Goals and ideas

* Use legacy styled credentials to generate W3C AnonCreds credentials and presentations
    * Credentials conversion:
        * Convert legacy styled AnonCreds credentials into W3C form
        * Convert W3C styled AnonCreds credentials into legacy form
    * Presentation conversion (Optional):
        * Convert legacy styled AnonCreds presentation into W3C form
        * Convert W3C styled AnonCreds presentation into legacy form
* Issue AnonCreds credentials in W3C form
* Create W3C presentations using W3C AnonCreds credentials
* Verify W3C presentations containing AnonCreds proof
* Extend W3C credentials:
    * Ability to set Data Integrity proof signatures for generated W3C credential objects:
        * W3C credentials may contain multiple signatures
        * AnonCreds-Rs only generates/handle AnonCreds signatures
    * Ability to add additional credential metadata

#### Out of scope

* Credentials: Verify validity of non-AnonCreds Data Integrity proof signatures
* Presentations: Create presentations using non-AnonCreds Data Integrity proof signature
* Presentations: Verify validity of presentations including non-AnonCreds Data Integrity proof signatures
* Presentations: Support different formats (for example DIF) of Presentation Request

### Question impacting the approach

* Q1: Do we need conversion for intermediate messages to make them W3C compliant: Credential Offer, Credential Request?
    * Q1.1: (Depends on answer for Q1) If no conversion: Do we want Credential Offer indicates what form of credential
      will be issued as the process execution result?
    * **Answer**: No conversion for Credential Offer, Credential Request objects. Existing types will be used.
* Q2: Do we want duplicate methods (like `sign` and `sign_w3c`) or only use single conversion method (
  like `credential.to_w3c`) doing extra step?
    * There are 6 methods in total. 4 of them we have to duplicate any way. Whether we want to
      duplicate `create_offer`, `create_request` methods if we do not change their format.
    * **Answer:**
        * All methods will be duplicated
        * According to the Q1 answer `w3c_create_offer`, `w3c_create_request` methods will be returning the same object as original methods
* Q3: Are we still tied to legacy styled presentation request?
    * Can we make interface completely independent of Presentation Request? So any form can be handled on top level and
      specific data passed to AnonCreds-rs.
    * **Answer**: API methods will keep using an existing AnonCreds Presentation Request format
* Q4: Do we want to provide general interfaces doing signing and verification of Non-AnonCreds Data Integrity proof signature?
    * Accept sign/verify callbacks into convert/create functions:
        * Issue with setting multiple signatures
        * Much easier just to expose methods to add signature proof itself
    * Provide methods to put ready data into a credential
    * **Answer:** No.
        * Third party libraries must be used for doing signing and verification of Non-AnonCreds Data Integrity proof signature
        * AnonCreds-rs only will only provide helper methods for setting attributes which can be needed for different Non-AnonCreds Data Integrity proof
* Q5: Signature/Proof encoding: Which approach to use for encoding?
    * Basic approach used in Aries attachments: [BaseURL safe 64 encoding of object serialized as JSON string](https://github.com/hyperledger/aries-rfcs/tree/main/concepts/0017-attachments#base64url)?
    * Compact encoding implemented in Python PoC: Using the fact that most fields of credential signature and proof are big numbers rather that strings.
        * For example: the length of encoded credential signature string is about 2.5 times less than in the basic approach
    * **Answer**:
        * Start from basic Aries encoding.
        * Experiment with other algorithms (CBOR, Message Pack, Protobuf, Custom) as a next step.
* Q6: W3C data model allows attributes to be represented not only as key/value string pairs but also as
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
    * **Answer**:
        * Only key/value string pairs will be supported for the current phase
* Q7: Should we care about back way conversion of credential issued in W3C form?
    * Assume that we issued W3C which cannot convert back into legacy form
    * For example supporting different attributes types can be used in credentialSubject (support nested objects, array,
      other features)
        * Need to decide on object encoding algorithm
    * **Answer**: Yes. Within the current design/effort credentials must be convertible back and forth
* Q8: Should we include Holder DID into credential subject as [`id` attribute](https://www.w3.org/TR/vc-data-model/#identifiers)?
    * This enables credential subject [validation](https://www.w3.org/TR/vc-data-model/#credential-subject-0)
    * We can add if for newly issued credentials but cannot set during the conversion of previously issued credentials.
    * **Answer**:
        * Up to Issuer, Optionally Issuer may include DID into credential subject
        * anoncreds-rs will provide a helper function to set `id`
* Q9: Predicates representation in credential subject
    * Derive an attribute and put it into `credentialSubject` like it demonstrated
      in the [specification](https://www.w3.org/TR/vc-data-model/#presentations-using-derived-credentials)
        * Example:
            * For Predicate: `{"name": "birthdate", "p_type": "<", "value":"20041012"}`
            * Derived attribute: `{"birthdate": "birthdate less 20041012"}`
        * During the `proofValue` crypto verification we can parse the phrase and restore predicate attributes
    * Put predicate as object into `credentialSubject`
        ```
          "credentialSubject": {
            ...
            "birthdate": {
              "type": "Predicate",
              "p_type": "<", 
              "value": "20041012"
            }
            ...
          }
        ```
    * **Answer**: Need more discussion
* Q10: Should we remove `mapping` completely or move under encoded `proofValue`?
    * Why `mapping` is bad: we make presentation tied to legacy styled Presentation Request
    * Mapping is something old-fashioned synthetic required for doing validation (not signature verification) that proof matches to
      the request itself on the verifier side
    * For doing crypto `proofValue` verification we only need the names of revealed attributes and predicated (with
      type)
    * `revealed attributes` and `predicates` can be validated as we include them into `credentialSubject` but `unrevealed` attributes cannot.
    * **Answer**: Drop `mapping` - see at the bottom of the document an example on how the validation of verifier's side still can be done
* Q11: Revocation signature/proof: Should it be put into the same value of two independent signatures/proofs must be put into credential/presentation?
    * **Answer**: For the current implementation it's good just to put everything inside encoded proof value
      * For future: Prepare a section example describing how non revocation can be extracted into a separate proof  
* Q12: For conversion of legacy credentials into W3C Credentials form we need to set `issuer_id` attribute. But legacy
  credentials do not contain this field explicitly. `AnonCreds-rs` is designed to be ledger/DID method agnostic, so it
  does not analyze/handle the values of id fields.
    * How should we get issuer DID for putting into credential?
        * Require `CredentialDefinition` to be passed as parameter
        * Parse if `legacy` cred def id form is used
    * **Answer**: Require passing credential definition as parameter 
* Q13: Issuance data: W3C specification requires setting of `issuanceDate` property to express the date and time when a credential becomes valid.
    * What datetime should we use? current / random of the day / start of the day
    * **Answer**: It's ok just to use the current time  

### Proposed implementation path for first iteration

1. Credential conversion APIs
2. Credential helper methods for non-AnonCreds integrity proof handling (set_integrity_proof, etc?)
    * Generation and verification of non-AnonCreds Data Integrity proof signature are done by third party libraries using `anoncreds-rs`
    * `anoncreds-rs` only provides methods to put ready data into a credential
3. Flow duplication APIs: All methods
4. No adoption of Credential Offer and Credential Request objects for W3C standard
5. Keep API stick to existing Presentation Request format

### Public API

#### Credential/Presentation Conversion methods

The idea for this approach is only provide conversion method for credentials and presentations.
So credentials and presentations themselves are generate the same way and the same functions as before but if W3C form
is require application uses conversion methods to get required format.

#### Credential Conversion methods

These methods allow to solve both cases:

Methods purpose - have to forms of credentials (probably even duplicate in wallet) to cover both cases: legacy and W3C
* `anoncreds_credential_to_w3c` - create W3C Presentation using a credential previously issued in legacy form
* `anoncreds_credential_from_w3c` - create a legacy styled presentation (for legacy Verifier) using a credential issued in W3C form

```rust
/// Convert credential in legacy form into W3C AnonCreds credential form
///
/// # Params
/// cred:       object handle pointing to credential in legacy form to convert
/// cred_p:     reference that will contain converted credential (in W3C form) instance pointer
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_credential_to_w3c(
    cred: ObjectHandle,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {}

/// Convert credential in W3C form into legacy credential form
///
/// # Params
/// cred:       object handle pointing to credential in W3C form to convert
/// cred_p:     reference that will contain converted credential (in legacy form) instance pointer
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_credential_from_w3c(
    cred: ObjectHandle,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {}
```

#### Credential object helper methods

```rust
/// Add Non-Anoncreds Data Integrity proof signature to W3C AnonCreds credential
///
/// # Params
/// cred -      object handle pointing to W3C AnonCreds credential
/// proof -     data integrity proof as JSON string
/// cred_p:     reference that will contain update credential
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_w3c_credential_add_non_anoncreds_integrity_proof(
    cred: ObjectHandle,
    proof: FfiStr,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {}

/// Add context to W3C AnonCreds credential
///
/// # Params
/// cred -      object handle pointing to W3C AnonCreds credential
/// context -   context to add into credential
/// cred_p:     reference that will contain update credential
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_w3c_credential_add_context(
    cred: ObjectHandle,
    context: FfiStr,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {}

/// Add type to W3C AnonCreds credential
///
/// # Params
/// cred -      object handle pointing to W3C AnonCreds credential
/// type -      type to add into credential
/// cred_p:     reference that will contain update credential
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_w3c_credential_add_type(
    cred: ObjectHandle,
    type_: FfiStr,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {}

/// Set subject id to W3C AnonCreds credential
///
/// # Params
/// cred -      object handle pointing to W3C AnonCreds credential
/// id -        subject id to add into credential
/// cred_p:     reference that will contain update credential
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_w3c_credential_set_subject_id(
    cred: ObjectHandle,
    id: FfiStr,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {}

/// Set id to W3C AnonCreds credential
///
/// # Params
/// cred -      object handle pointing to W3C AnonCreds credential
/// id -        id to add into credential
/// cred_p:     reference that will contain update credential
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_w3c_credential_id(
    cred: ObjectHandle,
    id: FfiStr,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {}
```

#### Optional: Presentation Conversion methods

Presentation conversion methods are only required if we decide not to implement duplication flow methods even for
presentation exchange.   
In this case, library will provide APIs to create/verify legacy formatted presentation and APIs to convert it into/from
W3C form to support different Verifiers.

```rust
/// Convert legacy styled AnonCreds presentation into W3C AnonCreds presentation form
///     The conversion process described at the specification: ---
///
/// # Params
/// cred -      object handle pointing to legacy styled AnonCreds presentation to convert
/// cred_p -    reference that will contain converted presentation (in W3C form) instance pointer
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_presentation_to_w3c(
    cred: ObjectHandle,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {}

/// Convert W3C styled AnonCreds presentation into legacy styled AnonCreds presentation
///     The conversion process described at the specification: ---
///
/// # Params
/// cred -      object handle pointing to W3C styled AnonCreds presentation to convert
/// cred_p -    reference that will contain converted presentation (in legacy form) instance pointer
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_presentation_from_w3c(
    cred: ObjectHandle,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {}
```

#### Optional: Methods duplication

The idea for this approach to duplicate all issuance/presentation related methods for w3c standard.
So the credentials and presentations themselves are generated using new flow methods.


> Note, that we still need to implement credential conversion methods to support the case of using existing/issued
> credentials for doing the w3c presentation.
> Firstly, old credentials should be converted into a W3C form, and the next new presentation creation method can be
> used.

In fact, there are 6 main flow methods in total.
4 of them we have to duplicate: `create_credential`, `process_credential`, `create_presentation`, `verify_presentation`.
Whether we want to duplicate `create_offer`, `create_request` methods if we do not change their format?

The reasons for adding duplication methods:

- avoid breaking changes in the existing API
    - for example if we want Credential Offer pointing to the form of a credential to be issued
- clear separation between flows
    - if a flow targeting issuing of W3C Credential the specific set of function to be used
- avoid the situation when function result value may be in different forms
    - example:
        - issuer creates offer in legacy form but with resulting credential format indication (legacy or w3c )
        - as the flow execution result, create credential function returns credential either in w3c or legacy form
          depending on offer
        - if application analyze credential somehow it cause difficulties
- easier deprecation of legacy styled credentials and APIs
- presentation conversion methods are not needed anymore in this case
    - only credential conversion method to do migration for previously issued credentials

> We can do only part of the work: add duplication methods for presentation but leave old methods for credentials

```rust
/// Create Credential Offer according to the AnonCreds specification
/// Note that Credential Offer still will be legacy styled (the same as result of anoncreds_create_credential_offer)
///
/// # Params
/// schema_id:              id of schema future credential refers to
/// cred_def_id:            id of credential definition future credential refers to
/// key_proof:              object handle pointing to credential definition key correctness proof
/// cred_offer_p:           reference that will contain created credential offer (in legacy form) instance pointer
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_create_w3c_credential_offer(
    schema_id: FfiStr,
    cred_def_id: FfiStr,
    key_proof: ObjectHandle,
    cred_offer_p: *mut ObjectHandle,
) -> ErrorCode {}

/// Create Credential Request according to the AnonCreds specification
/// Note that Credential Request still will be legacy styled (the same as result of anoncreds_create_credential_request)
///
/// # Params
/// entropy:                entropy string to use for request creation
/// prover_did:             DID of the credential holder
/// cred_def:               object handle pointing to credential definition
/// link_secret:            holder link secret
/// link_secret_id:         id of holder's link secret
/// credential_offer:       object handle pointing to credential offer
/// cred_req_p:             Reference that will contain created credential request (in legacy form) instance pointer.
/// cred_req_meta_p:        Reference that will contain created credential request metadata (in legacy form) instance pointer.
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_create_w3c_credential_request(
    entropy: FfiStr,
    prover_did: FfiStr,
    cred_def: ObjectHandle,
    link_secret: FfiStr,
    link_secret_id: FfiStr,
    cred_offer: ObjectHandle,
    cred_req_p: *mut ObjectHandle,
    cred_req_meta_p: *mut ObjectHandle,
) -> ErrorCode {}

/// Create Credential in W3C form according to the specification.
///
/// # Params
/// cred_def:              object handle pointing to the credential definition
/// cred_def_private:      object handle pointing to the private part of credential definition
/// cred_offer:            object handle pointing to the credential offer
/// cred_request:          object handle pointing to the credential request
/// attr_names:            list of attribute names
/// attr_raw_values:       list of attribute raw values
/// revocation:            object handle pointing to the credential revocation info
/// cred_p:                reference that will contain credential (in W3C form) instance pointer
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_create_w3c_credential(
    cred_def: ObjectHandle,
    cred_def_private: ObjectHandle,
    cred_offer: ObjectHandle,
    cred_request: ObjectHandle,
    attr_names: FfiStrList,
    attr_raw_values: FfiStrList,
    revocation: *const FfiCredRevInfo,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {}

/// Process an incoming W3C credential received from the issuer.
///
/// # Params
/// cred:                  object handle pointing to the credential in W3C form
/// cred_req_metadata:     object handle pointing to the credential request metadata
/// link_secret:           holder link secret
/// cred_def:              object handle pointing to the credential definition
/// rev_reg_def:           object handle pointing to the revocation registry definition
/// cred_p:                reference that will contain credential (in W3C form) instance pointer
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_process_w3c_credential(
    cred: ObjectHandle,
    cred_req_metadata: ObjectHandle,
    link_secret: FfiStr,
    cred_def: ObjectHandle,
    rev_reg_def: ObjectHandle,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {}

/// Get value of requested credential attribute as string
///
/// # Params
/// cred_def:              object handle pointing to the credential (in W3 form)  
/// name:                  name of attribute to retrieve
/// result_p:              reference that will contain value of request credential attribute
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_w3c_credential_get_attribute(
    handle: ObjectHandle,
    name: FfiStr,
    result_p: *mut *const c_char,
) -> ErrorCode {}

/// Create W3C Presentation according to the specification.
/// 
/// # Params
/// pres_req:               object handle pointing to presentation request
/// credentials:            credentials (in W3C form) to use for presentation preparation
/// credentials_prove:      attributes and predicates to prove per credential
/// link_secret:            holder link secret
/// schemas:                list of credential schemas
/// schema_ids:             list of schemas ids
/// cred_defs:              list of credential definitions
/// cred_def_ids:           list of credential definitions ids
/// presentation_p:         reference that will contain created presentation (in W3C form) instance pointer.
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_create_w3c_presentation(
    pres_req: ObjectHandle,
    credentials: FfiList<FfiCredentialEntry>,
    credentials_prove: FfiList<FfiCredentialProve>,
    link_secret: FfiStr,
    schemas: FfiList<ObjectHandle>,
    schema_ids: FfiStrList,
    cred_defs: FfiList<ObjectHandle>,
    cred_def_ids: FfiStrList,
    presentation_p: *mut ObjectHandle,
) -> ErrorCode {}

/// Verity W3C styled Presentation
///
/// # Params
/// presentation:                   object handle pointing to presentation
/// pres_req:                       object handle pointing to presentation request
/// schemas:                        list of credential schemas
/// schema_ids:                     list of schemas ids
/// cred_defs:                      list of credential definitions
/// cred_def_ids:                   list of credential definitions ids
/// rev_reg_defs:                   list of revocation definitions
/// rev_reg_def_ids:                list of revocation definitions ids
/// rev_status_list:                revocation status list
/// nonrevoked_interval_override:   not-revoked interval
/// result_p:                       reference that will contain presentation verification result.
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_verify_w3c_presentation(
    presentation: ObjectHandle,
    pres_req: ObjectHandle,
    schemas: FfiList<ObjectHandle>,
    schema_ids: FfiStrList,
    cred_defs: FfiList<ObjectHandle>,
    cred_def_ids: FfiStrList,
    rev_reg_defs: FfiList<ObjectHandle>,
    rev_reg_def_ids: FfiStrList,
    rev_status_list: FfiList<ObjectHandle>,
    nonrevoked_interval_override: FfiList<FfiNonrevokedIntervalOverride>,
    result_p: *mut i8,
) -> ErrorCode {}
```

### Demo scripts

#### Issue legacy Credential and present W3C Presentation

```
/// Issue legacy styled credential using existing methods
legacy_credential_offer = Issuer.anoncreds_create_credential_offer(...)
legacy_credential_request = Holder.anoncreds_create_credential_request(legacy_credential_offer,...)
legacy_credential = Issuer.anoncreds_create_credential(legacy_credential_request,...)
legacy_credential = Holder.anoncreds_process_credential(legacy_credential,...)

/// Convert legacy styled credential to W3C credential form
w3c_credential = Holder.anoncreds_credential_to_w3c(legacy_credential)

/// Do wallets need to store both credential forms to handle legacy and DIF presentations requests?  
Wallet.store_legacy_credential(legacy_credential)
Wallet.store_w3c_credential(w3c_credential)

/// Verifiy W3C preentation using converted W3C crdential form
w3c_presentation_request = Verifier.w3c_create_presentation_request()
w3c_presentation = Holder.anoncreds_w3c_create_presentation(w3c_presentation_request, w3c_credentials)
Verifier.anoncreds_w3c_verify_presentation(w3c_presentation)
```

#### Issue W3C Credential and present legacy Presentation

```
/// Issue W3C credential using new flow methods
w3c_credential_offer = Issuer.anoncreds_w3c_create_credential_offer(...)
w3c_credential_request = Holder.anoncreds_w3c_create_credential_request(w3c_credential_offer,...)
w3c_credential = Issuer.anoncreds_w3c_create_credential(w3c_credential_request,...)
w3c_credential = Holder.anoncreds_w3c_process_credential(w3c_credential,...)

/// Convert W3C credential to legacy form
legacy_credential = Holder.anoncreds_credential_from_w3c(w3c_credential)

/// Do wallets need to store both credential forms to handle legacy and DIF presentations requests?  
Wallet.store_legacy_credential(legacy_credential)
Wallet.store_w3c_credential(w3c_credential)

/// Verifiy legacy presentation using converted Iny crdential form
legacy_presentation_request = Verifier.create_presentation_request()
legacy_presentation = Holder.create_presentation(legacy_presentation_request, legacy_credential)
Verifier.anoncreds_verify_presentation(legacy_presentation)
```

#### Issue W3C Credential and present W3C Presentation

```
/// Issue W3C credential using new flow methods
w3c_credential_offer = Issuer.anoncreds_w3c_create_credential_offer(...)
w3c_credential_request = Holder.anoncreds_w3c_create_credential_request(w3c_credential_offer,...)
w3c_credential = Issuer.anoncreds_w3c_create_credential(w3c_credential_request,...)
w3c_credential = Holder.anoncreds_w3c_process_credential(w3c_credential,...)

/// Do wallets need to store both credential forms to handle legacy and DIF presentations requests?  
Wallet.store_w3c_credential(w3c_credential)

/// Verifiy W3C presenttion using W3C crdential form
w3c_presentation_request = Verifier.w3c_create_presentation_request()
w3c_presentation = Holder.anoncreds_w3c_create_presentation(w3c_presentation_request, w3c_credential)
Verifier.anoncreds_w3c_verify_presentation(w3c_presentation)
```

#### Issue W3C Credential, set RSA Identity Proof signature, and present W3C Presentation using RSA Identity Proof

```
/// Issue W3C credential using new flow methods
w3c_credential_offer = Issuer.anoncreds_w3c_create_credential_offer(...)
w3c_credential_request = Holder.anoncreds_w3c_create_credential_request(w3c_credential_offer,...)
w3c_credential = Issuer.anoncreds_w3c_create_credential(w3c_credential_request,...)
w3c_credential = Holder.anoncreds_w3c_process_credential(w3c_credential,...)

/// Add RSA Identity Proof signature to credential
integrity_proof = extartnal_library.create_rsa_integrity_proof(w3c_credential)
w3c_credential = anoncreds_w3c_credential_add_non_anoncreds_integrity_proof(w3c_credential, integrity_proof)

/// Do wallets need to store both credential forms to handle legacy and DIF presentations requests?  
Wallet.store_w3c_credential(w3c_credential)

/// Verifiy W3C presenttion using RSA Identity Proof signature
w3c_presentation_request = Verifier.w3c_create_presentation_request()
rsa_integrity_proof_presentation = extartnal_library.create_presentation_using_rsa_integrity_proof(w3c_presentation_request, w3c_credential)
extartnal_verifier.verify_rsa_integrity_proof_presentation(rsa_integrity_proof_presentation)
```

### Presentation validation

**Request**
```
{
   "name":"pres_req_1",
   "non_revoked":null,
   "nonce":"358493544514389191968232",
   "requested_attributes":{
      "attr1_referent":{
         "name":"first_name",
         "non_revoked":null,
         "restrictions":null
      },
      "attr2_referent":{
         "name":"sex",
         "non_revoked":null,
         "restrictions":null
      },
      "attr3_referent":{
         "names":[
            "last_name",
            "height"
         ],
         "non_revoked":null,
         "restrictions":null
      }
   },
   "requested_predicates":{
      "predicate1_referent":{
         "name":"age",
         "non_revoked":null,
         "p_type":">=",
         "p_value":18,
         "restrictions":null
      }
   },
   "ver":"1.0",
   "version":"0.1"
}
```

**Presentation**
```
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://raw.githubusercontent.com/DSRCorporation/anoncreds-rs/design/w3c-support/docs/design/w3c/context.json"
  ],
  "type": [
    "VerifiablePresentation",
    "AnonCredsPresentation"
  ],
  "verifiableCredential": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://raw.githubusercontent.com/DSRCorporation/anoncreds-rs/design/w3c-support/docs/design/w3c/context.json"
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
        "schema": "did:sov:3avoBCqDMFHFaKUHug9s8W:2:basic_person:0.1.0"
      },
      "credentialSubject": {
        "first_name": "Alice"
        "lastt_name": "Jons"
        "height": "185"
      },
      "proof": {
        "type": "AnonCredsPresentationProof2023",
        "mapping": {
          "revealedAttributes": ["attr1_referent"],
          "unrevealedAttributes": ["attr2_referent"],
          "revealedAttributeGroups": ["attr3_referent"],
          "requestedPredicates": ["predicate1_referent"]
        },
        "proofValue": "AAEBAnr2Ql...0UhJ-bIIdWFKVWxjU3ePxv_7HoY5pUw"
      }
    }
  ],
  "proof": {
    "type": "AnonCredsPresentationProof2023",
    "challenge": "182453895158932070575246",
    "proofValue": "AAAgtMR4....J19l-agSA"
  }
}
```

**Verifier validation steps is we keep mapping**:
```
// validate requested attributes
for (referent, requested) in presentation_request.requested_attributes {
    credential = presentation.verifiableCredential.find((verifiableCredential) => 
        verifiableCredential.proof.mapping.revealedAttributes.includes(referent) || 
        verifiableCredential.proof.mapping.unrevealedAttributes.includes(referent) || 
        verifiableCredential.proof.mapping.revealedAttributeGroups.includes(referent))
        
    credential.checkRestrictions(requested.restrictions)
        
    if !credential {
        error
    }
    if requested.name {
        assert(credential.credentialSubject[requested.name])
    }
    if requested.names {
        names.forEach((name) => assert(credential.credentialSubject[name]))
    }
}

// validate requested predicates
for (referent, requested) in presentation_request.requested_predicates {
    credential = presentation.verifiableCredential.find((verifiableCredential) => 
        verifiableCredential.proof.mapping.requestedPredicates.includes(referent))
    credential.checkRestrictions(requested.restrictions)
    assert(credential.credentialSubject[requested.name]) // if we include derived predicate into subject
}
```

**Verifier validation steps is we drop mapping**:
```
// validate requested attributes
for (referent, requested) in presentation_request.requested_attributes {
    if requested.name {
        // or filter if requted same attribute multiple times?
        credential = presentation.verifiableCredential.find((verifiableCredential) => 
            credentialSubject.contains(requested[name])
        )
        if credential {
            credential.checkRestrictions(requested.restrictions)
            assert(credential.credentialSubject[requested.name])
        }
        if !credential {
            // consider attribute as unrevealed
            // If we need to support and validate unrevealed attributes
            credential_with_attribute = presentation.verifiableCredential.find((verifiableCredential) => 
                schema = get_schema(verifiableCredential.schema_id) // all schemas already passed into verification function   
                schema.attributes.includes(requested.name)
                verifiableCredential.matches(restrictions)
            )
            if !credential_with_attribute {
                error    
            }
        }
    }
    if requested.names {
        for (referent, requested) in requested.names {
            // do same as for single attribute above 
            // make sure that all come from single credential
        }
    }
}

// validate requested predicates - we put predicate derived string or object into credentialSubject
// {
//    "age" ">= 18"
// }
for (referent, requested) in presentation_request.requested_predicates {
    // or filter if requted same attribute multiple times?
    credential = presentation.verifiableCredential.find((verifiableCredential) => 
        credentialSubject.contains(requested[name])
    )
    if !credential {
        error
    }
    credential.checkRestrictions(requested.restrictions)
    assert(credential.credentialSubject[requested.name])
}
```

### Examples

Example of an AnonCreds W3C credential:

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://raw.githubusercontent.com/DSRCorporation/anoncreds-rs/design/w3c-support/docs/design/w3c/context.json"
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
    "schema": "did:sov:3avoBCqDMFHFaKUHug9s8W:2:basic_person:0.1.0"
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

Example of an AnonCreds W3C presentation:

```json
{
  "@context":[
    "https://www.w3.org/2018/credentials/v1",
    "https://raw.githubusercontent.com/DSRCorporation/anoncreds-spec/w3c-credentials/data/anoncreds-w3c-context.json"
  ],
  "type":[
    "VerifiablePresentation",
    "AnonCredsPresentation"
  ],
  "verifiableCredential":[
    {
      "@context":[
        "https://www.w3.org/2018/credentials/v1",
        "https://raw.githubusercontent.com/DSRCorporation/anoncreds-spec/w3c-credentials/data/anoncreds-w3c-context.json"
      ],
      "type":[
        "VerifiableCredential",
        "AnonCredsCredential"
      ],
      "credentialSchema": {
        "type": "AnonCredsDefinition",
        "definition": "did:sov:3avoBCqDMFHFaKUHug9s8W:3:CL:13:default",
        "schema": "did:sov:3avoBCqDMFHFaKUHug9s8W:2:basic_person:0.1.0"
      },
      "credentialSubject":{
        "firstName":"Alice",
        "age":{
          "type":"AnonCredsPredicate",
          "p_type":">=",
          "p_value":18
        }
      },
      "issuanceDate":"2023-11-15T10:59:48.036203Z",
      "issuer":"issuer:id/path=bar",
      "proof":{
        "type":"AnonCredsPresentationProof2023",
        "mapping":{
          "predicates":["predicate1_referent"],
          "revealedAttributeGroups":[],
          "revealedAttributes":["attr1_referent"],
          "unrevealedAttributes":[]
        },
        "proofValue":"eyJzdWJfcHJvb2Yi...zMTc1NzU0NDAzNDQ0ODUifX1dfX19"
      }
    }
  ],
  "proof":{
    "type":"AnonCredsPresentationProof2023",
    "challenge":"413296376279822794586260",
    "proofValue":"eyJhZ2dyZWdhdGVkIjp7ImNfaGFzaCI6IjEwMT...IsMzAsMTM1LDE4MywxMDcsMTYwXV19fQ=="
  }
}
```