use crate::Error;
use crate::data_types::issuer_id::IssuerId;
use crate::data_types::w3c::VerifiableCredentialSpecVersion;
use crate::data_types::w3c::credential::W3CCredential;
use crate::data_types::w3c::credential_attributes::CredentialSubject;
use crate::data_types::w3c::proof::{CredentialSignatureProofValue, DataIntegrityProof};
use crate::types::Credential;
use crate::utils::validation::Validatable;

/// Convert credential in legacy form into W3C AnonCreds credential form
///
/// # Example
///
/// ```rust
/// use anoncreds::w3c;
/// use anoncreds::issuer;
/// use anoncreds::prover;
/// use anoncreds::types::MakeCredentialValues;
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
/// let cred_def_id = CredentialDefinitionId::new("did:web:xyz/resource/cred-def").expect("Invalid credential definition ID");
///
/// let schema = issuer::create_schema("schema name",
///                                    "1.0",
///                                    issuer_id.clone(),
///                                    attribute_names.into(),
///                                    ).expect("Unable to create schema");
///
/// let (cred_def, cred_def_priv, key_correctness_proof) =
///     issuer::create_credential_definition(schema_id.clone(),
///                                          &schema,
///                                          issuer_id,
///                                          "default-tag",
///                                          SignatureType::CL,
///                                          CredentialDefinitionConfig::default(),
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
/// let mut credential_values = MakeCredentialValues::default();
/// credential_values.add_raw("name", "john").expect("Unable to add credential value");
/// credential_values.add_raw("age", "28").expect("Unable to add credential value");
///
/// let mut credential =
///     issuer::create_credential(&cred_def,
///                               &cred_def_priv,
///                               &credential_offer,
///                               &credential_request,
///                               credential_values.into(),
///                               None,
///                               ).expect("Unable to create credential");
///
/// prover::process_credential(&mut credential,
///                            &credential_request_metadata,
///                            &link_secret,
///                            &cred_def,
///                            None,
///                            ).expect("Unable to process the credential");
///
/// let _w3c_credential = w3c::credential_conversion::credential_to_w3c(&credential, &cred_def.issuer_id, None)
///                         .expect("Unable to convert credential to w3c form");
///
/// ```
pub fn credential_to_w3c(
    credential: &Credential,
    issuer_id: &IssuerId,
    version: Option<VerifiableCredentialSpecVersion>,
) -> Result<W3CCredential, Error> {
    trace!(
        "credential_to_w3c >>> credential: {:?}, issuer_id: {:?}",
        credential, issuer_id
    );

    credential.validate()?;

    let credential = credential.try_clone()?;
    let issuer = issuer_id.clone();
    let attributes = CredentialSubject::from(&credential.values);
    let signature = CredentialSignatureProofValue {
        schema_id: credential.schema_id,
        cred_def_id: credential.cred_def_id,
        rev_reg_id: credential.rev_reg_id,
        signature: credential.signature,
        signature_correctness_proof: credential.signature_correctness_proof,
        rev_reg: credential.rev_reg,
        witness: credential.witness,
    };
    let proof = DataIntegrityProof::new_credential_proof(&signature)?;
    let w3c_credential = W3CCredential::new(issuer, attributes, proof, version.as_ref());

    trace!("credential_to_w3c <<< w3c_credential {:?}", w3c_credential);

    Ok(w3c_credential)
}

/// Convert credential in W3C form into legacy credential form
///
/// # Example
///
/// ```rust
/// use anoncreds::w3c;
/// use anoncreds::issuer;
/// use anoncreds::prover;
/// use anoncreds::w3c::types::MakeCredentialAttributes;
/// use anoncreds::types::MakeCredentialValues;
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
/// let cred_def_id = CredentialDefinitionId::new("did:web:xyz/resource/cred-def").expect("Invalid credential definition ID");
///
/// let schema = issuer::create_schema("schema name",
///                                    "1.0",
///                                    issuer_id.clone(),
///                                    attribute_names.into(),
///                                    ).expect("Unable to create schema");
///
/// let (cred_def, cred_def_priv, key_correctness_proof) =
///     issuer::create_credential_definition(schema_id.clone(),
///                                          &schema,
///                                          issuer_id,
///                                          "default-tag",
///                                          SignatureType::CL,
///                                          CredentialDefinitionConfig::default(),
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
/// let mut credential =
///     w3c::issuer::create_credential(&cred_def,
///                                   &cred_def_priv,
///                                   &credential_offer,
///                                   &credential_request,
///                                   credential_values.into(),
///                                   None,
///                                   None,
///                                   ).expect("Unable to create credential");
///
/// w3c::prover::process_credential(&mut credential,
///                                &credential_request_metadata,
///                                &link_secret,
///                                &cred_def,
///                                None,
///                                ).expect("Unable to process the credential");
///
/// let _w3c_credential = w3c::credential_conversion::credential_from_w3c(&credential)
///                         .expect("Unable to convert credential to w3c form");
///
/// ```
pub fn credential_from_w3c(w3c_credential: &W3CCredential) -> Result<Credential, Error> {
    trace!(
        "credential_from_w3c >>> w3c_credential: {:?}",
        w3c_credential
    );

    w3c_credential.validate()?;

    let credential_signature = w3c_credential.get_credential_signature_proof()?.clone();
    let values = w3c_credential.credential_subject.encode()?;

    let credential = Credential {
        values,
        schema_id: credential_signature.schema_id,
        cred_def_id: credential_signature.cred_def_id,
        rev_reg_id: credential_signature.rev_reg_id,
        signature: credential_signature.signature,
        signature_correctness_proof: credential_signature.signature_correctness_proof,
        rev_reg: credential_signature.rev_reg,
        witness: credential_signature.witness,
    };

    trace!("credential_from_w3c <<< credential: {:?}", credential);

    Ok(credential)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::data_types::cred_def::{CredentialDefinition, CredentialDefinitionId};
    use crate::data_types::issuer_id::IssuerId;
    use crate::data_types::schema::{Schema, SchemaId};
    use crate::data_types::w3c::constants::ANONCREDS_CREDENTIAL_TYPES;
    use crate::data_types::w3c::constants::{ANONCREDS_VC_1_1_CONTEXTS, ANONCREDS_VC_2_0_CONTEXTS};
    use crate::data_types::w3c::context::Contexts;
    use crate::data_types::w3c::one_or_many::OneOrMany;
    use crate::data_types::w3c::proof::tests::{
        cl_credential_signature, cl_credential_signature_correctness_proof,
        credential_signature_proof,
    };
    use crate::types::{
        AttributeNames, CredentialDefinitionConfig, CredentialValues, MakeCredentialValues,
        SignatureType,
    };
    use crate::{ErrorKind, issuer};
    use rstest::*;

    pub(crate) const ISSUER_ID: &str = "mock:uri";
    pub(crate) const SCHEMA_ID: &str = "mock:uri";
    pub(crate) const CRED_DEF_ID: &str = "mock:uri";

    pub(crate) fn issuer_id() -> IssuerId {
        IssuerId::new_unchecked(ISSUER_ID)
    }

    pub(crate) fn schema_id() -> SchemaId {
        SchemaId::new_unchecked(SCHEMA_ID)
    }

    pub(crate) fn schema() -> Schema {
        issuer::create_schema("schema:name", "1.0", issuer_id(), attributes()).unwrap()
    }

    pub(crate) fn cred_def_id() -> CredentialDefinitionId {
        CredentialDefinitionId::new_unchecked(CRED_DEF_ID)
    }

    pub(crate) fn attributes() -> AttributeNames {
        AttributeNames::from(vec![
            "name".to_owned(),
            "height".to_owned(),
            "age".to_owned(),
        ])
    }

    pub(crate) fn credential_definition() -> CredentialDefinition {
        let schema = schema();
        let (cred_def, _, _) = issuer::create_credential_definition(
            schema_id(),
            &schema,
            issuer_id(),
            "default",
            SignatureType::CL,
            CredentialDefinitionConfig {
                support_revocation: true,
            },
        )
        .unwrap();
        cred_def
    }

    pub(crate) fn cred_values() -> CredentialValues {
        let mut make = MakeCredentialValues::default();
        make.add_raw("name", "Alice").unwrap();
        make.add_raw("height", "178").unwrap();
        make.add_raw("age", "20").unwrap();
        make.into()
    }

    fn legacy_credential() -> Credential {
        Credential {
            schema_id: schema_id(),
            cred_def_id: cred_def_id(),
            rev_reg_id: None,
            values: cred_values(),
            signature: cl_credential_signature(),
            signature_correctness_proof: cl_credential_signature_correctness_proof(),
            rev_reg: None,
            witness: None,
        }
    }

    pub fn w3c_credential() -> W3CCredential {
        W3CCredential::new(
            issuer_id(),
            CredentialSubject::try_from(&cred_values()).unwrap(),
            DataIntegrityProof::new_credential_proof(&credential_signature_proof()).unwrap(),
            None,
        )
    }

    #[test]
    fn test_convert_credential_to_and_from_w3c() {
        let original_legacy_credential = legacy_credential();
        let w3c_credential = credential_to_w3c(
            &original_legacy_credential,
            &credential_definition().issuer_id,
            None,
        )
        .expect("unable to convert credential to w3c form");
        let legacy_credential = credential_from_w3c(&w3c_credential)
            .expect("unable to convert credential to legacy form");
        assert_eq!(json!(original_legacy_credential), json!(legacy_credential),)
    }

    #[rstest]
    #[case(VerifiableCredentialSpecVersion::V1_1, ANONCREDS_VC_1_1_CONTEXTS.clone())]
    #[case(VerifiableCredentialSpecVersion::V2_0, ANONCREDS_VC_2_0_CONTEXTS.clone())]
    fn test_credential_to_w3c_form(
        #[case] version: VerifiableCredentialSpecVersion,
        #[case] expected_context: Contexts,
    ) {
        let legacy_credential = legacy_credential();
        let w3c_credential = credential_to_w3c(
            &legacy_credential,
            &credential_definition().issuer_id,
            Some(version),
        )
        .expect("unable to convert credential to w3c form");

        assert_eq!(w3c_credential.context, expected_context.clone());
        assert_eq!(w3c_credential.type_, ANONCREDS_CREDENTIAL_TYPES.clone());

        let expected_attributes = CredentialSubject::from(&legacy_credential.values);
        assert_eq!(w3c_credential.credential_subject, expected_attributes);

        let proof = w3c_credential
            .get_credential_signature_proof()
            .expect("credential signature proof is not set");

        assert_eq!(proof.schema_id, legacy_credential.schema_id);
        assert_eq!(proof.cred_def_id, legacy_credential.cred_def_id);
        assert_eq!(proof.rev_reg_id, legacy_credential.rev_reg_id);
        assert_eq!(proof.signature, credential_signature_proof().signature);
        assert_eq!(
            proof.signature_correctness_proof,
            credential_signature_proof().signature_correctness_proof
        );
    }

    #[test]
    fn test_credential_from_w3c_form() {
        let w3c_credential = w3c_credential();
        let legacy_credential = credential_from_w3c(&w3c_credential)
            .expect("unable to convert credential from w3c form");
        let proof = w3c_credential
            .get_credential_signature_proof()
            .expect("credential signature proof is not set");
        assert_eq!(proof.schema_id, legacy_credential.schema_id);
        assert_eq!(proof.cred_def_id, legacy_credential.cred_def_id);
        assert_eq!(proof.rev_reg_id, legacy_credential.rev_reg_id);
        assert_eq!(cred_values(), legacy_credential.values);
        assert_eq!(proof.signature, legacy_credential.signature);
        assert_eq!(
            proof.signature_correctness_proof,
            legacy_credential.signature_correctness_proof
        );
        assert_eq!(proof.rev_reg, legacy_credential.rev_reg);
    }

    #[test]
    fn test_credential_from_w3c_form_when_no_signature_proof() {
        let mut w3c_credential = w3c_credential();
        w3c_credential.proof = OneOrMany::default();
        let err = credential_from_w3c(&w3c_credential).unwrap_err();
        assert_eq!(ErrorKind::Input, err.kind());
    }
}
