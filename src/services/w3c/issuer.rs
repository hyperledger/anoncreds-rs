use crate::data_types::cred_def::CredentialDefinition;
use crate::data_types::w3c::credential::W3CCredential;
use crate::data_types::w3c::credential_attributes::CredentialAttributes;
use crate::data_types::w3c::proof::{CredentialSignatureProof, DataIntegrityProof};
use crate::data_types::w3c::VerifiableCredentialSpecVersion;
use crate::error::Result;
use crate::issuer::CLCredentialIssuer;

use crate::types::{
    CredentialDefinitionPrivate, CredentialOffer, CredentialRequest, CredentialRevocationConfig,
};

/// Create an AnonCreds Credential in W3C form according to the [Anoncreds v1.0 specification -
/// Credential](https://hyperledger.github.io/anoncreds-spec/#issue-credential)
///
/// This object can be send to a holder which means that the credential is issued to that entity.
///
/// # Example
///
/// ```rust
/// use anoncreds::{issuer, w3c};
/// use anoncreds::prover;
/// use anoncreds::w3c::types::MakeCredentialAttributes;
///
/// use anoncreds::types::CredentialDefinitionConfig;
/// use anoncreds::types::SignatureType;
/// use anoncreds::data_types::issuer_id::IssuerId;
/// use anoncreds::data_types::schema::SchemaId;
/// use anoncreds::data_types::cred_def::CredentialDefinitionId;
///
/// let attribute_names: &[&str] = &["name", "age"];
/// let issuer_id = IssuerId::new("did:web:xyz").expect("Invalid issuer ID");
/// let schema_id = SchemaId::new("did:web:xyz/resource/schema").expect("Invalid schema ID");
/// let cred_def_id = CredentialDefinitionId::new("did:web:xyz/resource/cred-def",).expect("Invalid credential definition ID");
///
/// let schema = issuer::create_schema("schema name",
///                                    "1.0",
///                                    issuer_id.clone(),
///                                    attribute_names.into()
///                                    ).expect("Unable to create schema");
///
/// let (cred_def, cred_def_priv, key_correctness_proof) =
///     issuer::create_credential_definition(schema_id.clone(),
///                                          &schema,
///                                          issuer_id,
///                                          "default-tag",
///                                          SignatureType::CL,
///                                          CredentialDefinitionConfig::default()
///                                          ).expect("Unable to create Credential Definition");
///
/// let credential_offer =
///     issuer::create_credential_offer(schema_id,
///                                     cred_def_id,
///                                     &key_correctness_proof,
///                                     ).expect("Unable to create Credential Offer");
///
/// let link_secret =
///     prover::create_link_secret().expect("Unable to create link secret");
///
/// let (credential_request, credential_request_metadata) =
///     prover::create_credential_request(Some("entropy"),
///                                       None,
///                                       &cred_def,
///                                       &link_secret,
///                                       "my-secret-id",
///                                       &credential_offer,
///                                       ).expect("Unable to create credential request");
///
/// let mut credential_values = MakeCredentialAttributes::default();
/// credential_values.add("name", "john");
/// credential_values.add("age", "28");
///
/// let credential =
///     w3c::issuer::create_credential(&cred_def,
///                               &cred_def_priv,
///                               &credential_offer,
///                               &credential_request,
///                               credential_values.into(),
///                               None,
///                               None,
///                               ).expect("Unable to create credential");
/// ```
#[allow(clippy::too_many_arguments)]
pub fn create_credential(
    cred_def: &CredentialDefinition,
    cred_def_private: &CredentialDefinitionPrivate,
    cred_offer: &CredentialOffer,
    cred_request: &CredentialRequest,
    raw_credential_values: CredentialAttributes,
    revocation_config: Option<CredentialRevocationConfig>,
    version: Option<VerifiableCredentialSpecVersion>,
) -> Result<W3CCredential> {
    trace!("create_w3c_credential >>> cred_def: {:?}, cred_def_private: {:?}, cred_offer.nonce: {:?}, cred_request: {:?},\
            cred_values: {:?}, revocation_config: {:?}, version: {:?}",
            cred_def, secret!(&cred_def_private), &cred_offer.nonce, &cred_request, secret!(&raw_credential_values),
            revocation_config, version,
    );

    let credential_values = raw_credential_values.encode()?;

    let (credential_signature, signature_correctness_proof, rev_reg_id, rev_reg, witness) =
        CLCredentialIssuer::new(cred_def, cred_def_private).create_credential(
            cred_offer,
            cred_request,
            &credential_values,
            revocation_config,
        )?;

    let signature = CredentialSignatureProof {
        schema_id: cred_offer.schema_id.to_owned(),
        cred_def_id: cred_offer.cred_def_id.to_owned(),
        rev_reg_id,
        signature: credential_signature,
        signature_correctness_proof,
        rev_reg,
        witness,
    };

    let proof = DataIntegrityProof::new_credential_proof(signature);
    let credential = W3CCredential::new(
        cred_def.issuer_id.to_owned(),
        raw_credential_values,
        proof,
        version,
    );

    trace!(
        "create_w3c_credential <<< credential {:?}",
        secret!(&credential),
    );

    Ok(credential)
}
