#[cfg(any(feature = "cl", feature = "cl_native"))]
/// Credential definition
pub mod cred_def;
#[cfg(any(feature = "cl", feature = "cl_native"))]
/// Credential offer
pub mod cred_offer;
#[cfg(any(feature = "cl", feature = "cl_native"))]
/// Credential request
pub mod cred_request;
#[cfg(any(feature = "cl", feature = "cl_native"))]
/// Credential
pub mod credential;

#[cfg(any(feature = "cl", feature = "cl_native"))]
/// Identity master secret
pub mod master_secret;

#[cfg(any(feature = "cl", feature = "cl_native"))]
/// Presentation request
pub mod pres_request;
#[cfg(any(feature = "cl", feature = "cl_native"))]
/// Presentation
pub mod presentation;

#[cfg(any(feature = "cl", feature = "cl_native"))]
/// Revocation registry operations
pub mod rev_reg;
#[cfg(any(feature = "cl", feature = "cl_native"))]
/// Revocation registry definition operations
pub mod rev_reg_def;

#[cfg(feature = "rich_schema")]
/// Rich schema
pub mod rich_schema;

/// V1 credential schema
pub mod schema;
