## Design for W3C representation of AnonCreds credentials and presentation

This design document describes how W3C formatted Verifiable Credentials and Presentations are supported in `anoncreds-rs` library. 

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
/// cred_def:   object handle pointing to the credential definition
/// version:    version of w3c verifiable credential specification (1.1 or 2.0) to use
/// cred_p:     reference that will contain converted credential (in W3C form) instance pointer
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_credential_to_w3c(
    cred: ObjectHandle,
    cred_def: ObjectHandle,
    version: FfiStr,
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

#### Flow methods duplication

The idea for this approach to duplicate all issuance/presentation related methods for w3c standard.
So the credentials and presentations themselves are generated using new flow methods.

> Note, that we still need to implement credential conversion methods to support the case of using existing/issued
> credentials for doing the w3c presentation.
> Firstly, old credentials should be converted into a W3C form, and the next new presentation creation method can be
> used.

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

```rust
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
/// version:               version of w3c verifiable credential specification (1.1 or 2.0) to use
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
    version: *const FfiStr,
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

/// Get credential signature information required for proof building and verification
/// This information is aggregated from `anoncredsvc-2023` and `anoncredspresvc-2023` proofs.
/// It's needed for Holder and Verifier for public entities resolving
///     {`schema_id`, `cred_def_id`, `rev_reg_id`, `rev_reg_index`, `timestamp`}
///
/// # Params
/// handle:                object handle pointing to the credential (in W3 form)
/// result_p:              reference that will contain credential information
///
/// # Returns
/// Error code
#[no_mangle]
pub extern "C" fn anoncreds_w3c_credential_get_integrity_proof_details(
    handle: ObjectHandle,
    cred_proof_info_p: *mut ObjectHandle,
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
/// version:                version of w3c verifiable presentation specification (1.1 or 2.0) to use
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
