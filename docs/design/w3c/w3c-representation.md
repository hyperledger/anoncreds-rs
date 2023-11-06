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
* Extend W3C credentials:
    * Ability to set Data Integrity proof signatures for generated W3C credential objects:
        * W3C credentials may contain multiple signatures
        * AnonCreds-Rs only generates/handle AnonCreds signatures

#### Out of scope

* Credentials: Verify validity of the Data Integrity proof signature
* Presentations: Create presentation using Data Integrity proof signature
* Presentations: Verify validity of presentations using Data Integrity proof signatures
* Presentations: Support different formats (for example DIF) of Presentation Request

### Question impacting the approach

* Q1: Do we need conversion for intermediate messages to make them W3C compliant: Credential Offer, Credential Request?
    * Q1.1: (Depends on answer for Q1) If no conversion: Do we want Credential Offer indicates what form of credential
      will be issued as the process execution result?
    * Proposed answer: no conversion for the current phase
* Q2: Do we want duplicate methods (like `sign` and `sign_w3c`) or only use single conversion method (
  like `credential.to_w3c`) doing extra step?
    * There are 6 methods in total. 4 of them we have to duplicate any way. Whether we want to
      duplicate `create_offer`, `create_request` methods if we do not change their format.
    * Proposed answer: yes - duplicate all methods
* Q3: Are we still tied to legacy styled presentation request?
    * Can we make interface completely independent of Presentation Request? So any form can be handled on top level and
      specific data passed to AnonCreds-rs.
    * Proposed answer: Make AnonCreds-rs methods presentation agnostic.
* Q4: Do we want to provide general interfaces doing signing and verification of Data Integrity proof signature?
    * Accept sign/verify callbacks into convert/create functions:
        * Issue with setting multiple signatures
        * Much easier just to expose methods to add signature proof itself
    * Provide methods to put ready data into a credential
    * Proposed answer: delegate to third party libraries using `anoncreds-rs`
* Q5: Signature/Proof encoding: Which approach to use for encoding?
    * Basic approach used in Aries attachments: [BaseURL safe 64 encoding of object serialized as JSON string](https://github.com/hyperledger/aries-rfcs/tree/main/concepts/0017-attachments#base64url)?
    * Compact encoding implemented in Python PoC: Using the fact that most fields of credential signature and proof are big numbers rather that strings.
      * For example: the length of encoded credential signature string is about 2.5 times less than in the basic approach
      * Find an [example data](./encoding.md#example) to see the difference
    * Proposed answer: Start from basic approach?
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
* Q7: Should we care about back way conversion of credential issued in W3C form?
    * Assume that we issued W3C which cannot convert back into legacy form
    * For example supporting different attributes types can be used in credentialSubject (support nested objects, array,
      other features)
        * Need to decide on object encoding algorithm
* Q8: Should we include Holder DID into credential subject as [`id` attribute](https://www.w3.org/TR/vc-data-model/#identifiers)?
  * This enables credential subject [validation](https://www.w3.org/TR/vc-data-model/#credential-subject-0) 
  * We can add if for newly issued credentials but cannot set during the conversion of previously issued credentials.
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
* Q10: Should we remove `mapping` completely or move under encoded `proofValue`?
  * Why `mapping` is bad: we make presentation tied to legacy styled Presentation Request
  * Mapping is something old-fashioned synthetic required for doing validation (not signature verification) that proof matches to
    the request itself on the verifier side
  * For doing crypto `proofValue` verification we only need the names of revealed attributes and predicated (with
    type)
  * `revealed attributes` and `predicates` can be validated as we include them into `credentialSubject` but `unrevealed` attributes cannot.


### Proposed implementation path for first iteration

1. Credential conversion APIs
2. Credential helper methods for integrity proof handling (set_integrity_proof, get_signing_payload?, etc?)  
   * Generation and verification of Data Integrity proof signature are done by third party libraries using `anoncreds-rs`
   * `anoncreds-rs` only provides methods to put ready data into a credential
3. Flow duplication APIs
4. Adopt Credential Offer and Credential Request for W3C standard - No
   * It's not clear. W3C provides format of Credential and Presentation but not intermediate protocol messages
     * OpenID4VC - do they have intermediate messages (Credential Offer)?
5. Make presentation request agnostic API

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
/// Convert legacy styled AnonCreds credential into W3C AnonCreds credential form
///     The conversion process described at the specification: ---
///
/// # Params
/// cred -      object handle pointing to legacy styled credential to convert
/// cred_p -    reference that will contain converted credential (in W3C form) instance pointer
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_credential_to_w3c(
    cred: ObjectHandle,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {}

/// Convert W3C styled AnonCreds credential into legacy styled credential
///     The conversion process described at the specification: ---
///
/// # Params
/// cred -      object handle pointing to W3C styled AnonCreds credential to convert
/// cred_p -    reference that will contain converted credential (in legacy form) instance pointer
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_credential_from_w3c(
    cred: ObjectHandle,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {}
```

#### Credential object methods

```rust
/// Get W3C credential payload to sign for making Identity Proof
///
/// # Params
/// cred -                  object handle pointing to W3C styled AnonCreds credential
/// signing_payload_p -     reference that will contain payload to sign for generation of data integrity proof 
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_w3c_credential_get_signing_payload(
    cred: ObjectHandle,
    signing_payload_p: *mut *const c_char,
) -> ErrorCode {}

/// Set Data Integrity proof signature for W3C AnonCreds credential
///
/// # Params
/// cred -      object handle pointing to W3C styled AnonCreds credential
/// proof -     data integrity proof signature as JSON string
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_w3c_credential_set_integrity_proof(
    cred: ObjectHandle,
    proof: FfiStr,
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
/// It can be either legacy styled or W3C adopted depending on the answer for Q1 
/// If legacy styled credential to be used, it should indicate that credential in W3C AnonCreds form will be issued as the result.
///
/// Even if we do not change Credential Offer message itself we start from using a separate set of API functions
///
/// # Params
/// schema_id:              id of schema future credential refers to
/// cred_def_id:            id of credential definition future credential refers to
/// key_proof:              object handle pointing to credential definition key correctness proof
/// cred_offer_p - Reference that will contain created credential offer (in legacy form) instance pointer.
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_w3c_create_credential_offer(
    schema_id: FfiStr,
    cred_def_id: FfiStr,
    key_proof: ObjectHandle,
    cred_offer_p: *mut ObjectHandle,
) -> ErrorCode {}

/// Create Credential Request according to the AnonCreds specification
/// It can be either legacy styled or W3C adopted depending on the answer for Q1 
/// If legacy styled credential to be used, it should indicate that credential in W3C AnonCreds form will be issued as the result.
///
/// Even if we do not change Credential Request message itself we start from using a separate set of API functions
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
pub extern "C" fn anoncreds_w3c_create_credential_request(
    entropy: FfiStr,
    prover_did: FfiStr,
    cred_def: ObjectHandle,
    link_secret: FfiStr,
    link_secret_id: FfiStr,
    cred_offer: ObjectHandle,
    cred_req_p: *mut ObjectHandle,
    cred_req_meta_p: *mut ObjectHandle,
) -> ErrorCode {}

/// Create W3C styled Credential according to the specification.
///
/// # Params
/// cred_def:              object handle pointing to the credential definition 
/// cred_def_private:      object handle pointing to the private part of credential definition 
/// cred_offer:            object handle pointing to the credential offer
/// cred_request:          object handle pointing to the credential request
/// attr_names:            list of attribute names
/// attr_raw_values:       list of attribute values
/// revocation:            object handle pointing to the credential revocation data
/// cred_p:                reference that will contain credential (in W3C form) instance pointer
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_w3c_create_credential(
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
/// cred_def:              object handle pointing to the credential definition 
/// cred_def_private:      object handle pointing to the private part of credential definition 
/// cred_offer:            object handle pointing to the credential offer
/// cred_request:          object handle pointing to the credential request
/// attr_names:            list of attribute names
/// attr_raw_values:       list of attribute values
/// revocation:            object handle pointing to the credential revocation data
/// cred_p:                reference that will contain credential (in W3C form) instance pointer
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_w3c_process_credential(
    cred: ObjectHandle,
    cred_req_metadata: ObjectHandle,
    link_secret: FfiStr,
    cred_def: ObjectHandle,
    rev_reg_def: ObjectHandle,
    cred_p: *mut ObjectHandle,
) -> ErrorCode {}

/// Get value of request credential attribute as string
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

/// Create W3C styled Presentation according to the specification.
/// 
/// TODO: Function parameters need to be reworked if we decide to make it Presentation Request format agnostic
///
/// # Params
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
pub extern "C" fn anoncreds_w3c_create_presentation(
    credentials: FfiList<FfiCredentialEntry>,
    credentials_prove: FfiList<FfiCredentialProve>,
    link_secret: FfiStr,
    schemas: FfiList<ObjectHandle>,
    schema_ids: FfiStrList,
    cred_defs: FfiList<ObjectHandle>,
    cred_def_ids: FfiStrList,
    presentation_p: *mut ObjectHandle,
) -> ErrorCode {}

/// Create W3C styled Presentation according to the specification.
///
/// TODO: Function parameters need to be reworked if we decide to make it Presentation Request format agnostic
///
/// # Params
/// presentation:                   object handle pointing to presentation
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
pub extern "C" fn anoncreds_w3c_verify_presentation(
    presentation: ObjectHandle,
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

#### Optional: Credential Offer / Credential Request Conversion methods

Methods similar to Credential / Presentation conversion into W3C format.

> Do not see a sense 

### Demo scripts

> IN PROGRESS

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

/// Verifiy W3C presenttion using W3C crdential form
w3c_presentation_request = Verifier.w3c_create_presentation_request()
w3c_presentation = Holder.anoncreds_w3c_create_presentation(w3c_presentation_request, w3c_credential)
Verifier.anoncreds_w3c_verify_presentation(w3c_presentation)
```