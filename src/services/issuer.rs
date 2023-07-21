use crate::cl::{Issuer, RevocationRegistry};
use crate::data_types::cred_def::CredentialDefinitionId;
use crate::data_types::issuer_id::IssuerId;
use crate::data_types::rev_reg::{CLSignaturesRevocationRegistry, RevocationRegistryId};
use crate::data_types::rev_reg_def::RevocationRegistryDefinitionId;
use crate::data_types::schema::SchemaId;
use crate::data_types::{
    cred_def::{CredentialDefinition, CredentialDefinitionData},
    nonce::Nonce,
    rev_reg_def::{RevocationRegistryDefinitionValue, RevocationRegistryDefinitionValuePublicKeys},
    schema::Schema,
};
use crate::error::{Error, ErrorKind, Result, ValidationError};
use crate::services::helpers::{
    build_credential_schema, build_credential_values, build_non_credential_schema,
};
use crate::types::{CredentialDefinitionConfig, CredentialRevocationConfig};
use crate::utils::validation::Validatable;
use bitvec::bitvec;
use std::collections::BTreeSet;

use super::tails::TailsWriter;
use super::types::{
    AttributeNames, Credential, CredentialDefinitionPrivate, CredentialKeyCorrectnessProof,
    CredentialOffer, CredentialRequest, CredentialValues, RegistryType,
    RevocationRegistryDefinition, RevocationRegistryDefinitionPrivate, RevocationStatusList,
    SignatureType,
};

/// Create an Anoncreds schema according to the [Anoncreds v1.0
/// specification - Schema](https://hyperledger.github.io/anoncreds-spec/#schema-publisher-publish-schema-object)
///
/// This object can be stored on a VDR, verifiable data registry, to be used later on. It is
/// important to note that the identifier for the schema is omitted as this is used or VDR defined.
///
/// # Example
///
/// ```rust
/// use anoncreds::issuer;
///
/// let attribute_names: &[&str] = &["name", "age"];
///
/// let schema = issuer::create_schema("schema name",
///                                    "1.0", "did:web:xyz",
///                                    attribute_names.into()
///                                    ).expect("Unable to create schema");
/// ```
pub fn create_schema<II>(
    schema_name: &str,
    schema_version: &str,
    issuer_id: II,
    attr_names: AttributeNames,
) -> Result<Schema>
where
    II: TryInto<IssuerId, Error = ValidationError>,
{
    trace!(
        "create_schema >>> schema_name: {}, schema_version: {}, attr_names: {:?}",
        schema_name,
        schema_version,
        attr_names,
    );
    let issuer_id = issuer_id.try_into()?;

    let schema = Schema {
        name: schema_name.to_string(),
        version: schema_version.to_string(),
        issuer_id,
        attr_names,
    };

    schema.validate()?;

    Ok(schema)
}

/// Create an Anoncreds credential definition according to the [Anoncreds v1.0 specification -
/// Credential Definition without revocation
/// support](https://hyperledger.github.io/anoncreds-spec/#generating-a-credential-definition-without-revocation-support)
/// or [Anoncreds v1.0 specification - Credential Definition with
/// revocation](https://hyperledger.github.io/anoncreds-spec/#generating-a-credential-definition-with-revocation-support)
///
/// If you want to add support for revocation, you can add this with the
/// [`CredentialDefinitionConfig`] property.
///
/// This object can be stored on a VDR, verifiable data registry, to be used later on. It is
/// important to note that the identifier for the credential definition is omitted as this is used
/// or VDR defined.
///
/// # Example
///
/// ```rust
/// use anoncreds::issuer;
/// use anoncreds::types::CredentialDefinitionConfig;
/// use anoncreds::types::SignatureType;
///
/// let attribute_names: &[&str] = &["name", "age"];
/// let schema = issuer::create_schema("schema name",
///                                    "1.0",
///                                    "did:web:xyz",
///                                    attribute_names.into()
///                                    ).expect("Unable to create schema");
///
/// let (cred_def, cred_def_priv, key_correctness_proof) =
///     issuer::create_credential_definition("did:web:xyz/resource/schema",
///                                          &schema,
///                                          "did:web:xyz",
///                                          "default-tag",
///                                          SignatureType::CL,
///                                          CredentialDefinitionConfig::default()
///                                          ).expect("Unable to create Credential Definition");
/// ```
pub fn create_credential_definition<SI, II>(
    schema_id: SI,
    schema: &Schema,
    issuer_id: II,
    tag: &str,
    signature_type: SignatureType,
    config: CredentialDefinitionConfig,
) -> Result<(
    CredentialDefinition,
    CredentialDefinitionPrivate,
    CredentialKeyCorrectnessProof,
)>
where
    SI: TryInto<SchemaId, Error = ValidationError>,
    II: TryInto<IssuerId, Error = ValidationError>,
{
    trace!(
        "create_credential_definition >>> schema: {:?}, config: {:?}",
        schema,
        config
    );
    let issuer_id = issuer_id.try_into()?;
    let schema_id = schema_id.try_into()?;

    let credential_schema = build_credential_schema(&schema.attr_names.0)?;
    let non_credential_schema = build_non_credential_schema()?;

    let (credential_public_key, credential_private_key, correctness_proof) =
        Issuer::new_credential_def(
            &credential_schema,
            &non_credential_schema,
            config.support_revocation,
        )?;

    let cred_def = CredentialDefinition {
        schema_id,
        signature_type,
        issuer_id,
        tag: tag.to_owned(),
        value: CredentialDefinitionData {
            primary: credential_public_key.get_primary_key().try_clone()?,
            revocation: credential_public_key.get_revocation_key().cloned(),
        },
    };

    let cred_def_private = CredentialDefinitionPrivate {
        value: credential_private_key,
    };
    let cred_key_proof = CredentialKeyCorrectnessProof {
        value: correctness_proof,
    };
    trace!(
        "create_credential_definition <<< cred_def: {:?}, cred_def: {:?}, key_correctness_proof: {:?}",
        cred_def,
        secret!(&cred_def_private),
        cred_key_proof
    );

    Ok((cred_def, cred_def_private, cred_key_proof))
}

/// Create an Anoncreds revocation registry definition according to the [Anoncreds v1.0 -
/// Revocation Registry
/// Definition](https://hyperledger.github.io/anoncreds-spec/#issuer-create-and-publish-revocation-registry-objects).
///
/// This object can be stored on a VDR, verifiable data registry, to be used later on. It is
/// important to note that the identifier for the revocation registry definition is omitted as this
/// is used or VDR defined.
///
/// # Example
///
/// ```rust
/// use anoncreds::issuer;
/// use anoncreds::types::CredentialDefinitionConfig;
/// use anoncreds::types::SignatureType;
/// use anoncreds::types::RegistryType;
/// use anoncreds::tails::TailsFileWriter;
///
/// let attribute_names: &[&str] = &["name", "age"];
/// let schema = issuer::create_schema("schema name",
///                                    "1.0",
///                                    "did:web:xyz",
///                                    attribute_names.into()
///                                    ).expect("Unable to create schema");
///
/// let (cred_def, cred_def_priv, key_correctness_proof) =
///     issuer::create_credential_definition("did:web:xyz/resource/schema",
///                                          &schema,
///                                          "did:web:xyz",
///                                          "default-tag",
///                                          SignatureType::CL,
///                                          CredentialDefinitionConfig {
///                                             support_revocation: true
///                                          },
///                                          ).expect("Unable to create Credential Definition");
///
/// let mut tw = TailsFileWriter::new(None);
/// let (rev_reg_def, rev_reg_def_priv) =
///     issuer::create_revocation_registry_def(&cred_def,
///                                            "did:web:xyz/resource/cred-def",
///                                            "did:web:xyz",
///                                            "default-tag",
///                                            RegistryType::CL_ACCUM,
///                                            1000,
///                                            &mut tw
///                                            ).expect("Unable to create revocation registry");
/// ```
pub fn create_revocation_registry_def<TW>(
    cred_def: &CredentialDefinition,
    cred_def_id: impl TryInto<CredentialDefinitionId, Error = ValidationError>,
    issuer_id: impl TryInto<IssuerId, Error = ValidationError>,
    tag: &str,
    rev_reg_type: RegistryType,
    max_cred_num: u32,
    tails_writer: &mut TW,
) -> Result<(
    RevocationRegistryDefinition,
    RevocationRegistryDefinitionPrivate,
)>
where
    TW: TailsWriter,
{
    trace!("create_revocation_registry >>> cred_def: {:?}, tag: {:?}, max_cred_num: {:?}, rev_reg_type: {:?}",
             cred_def, tag, max_cred_num, rev_reg_type);
    let cred_def_id = cred_def_id.try_into()?;
    let issuer_id = issuer_id.try_into()?;

    if issuer_id != cred_def.issuer_id {
        return Err(err_msg!(
            "Issuer id must be the same as the issuer id in the credential definition"
        ));
    }

    let credential_pub_key = cred_def.get_public_key().map_err(err_map!(
        Unexpected,
        "Error fetching public key from credential definition"
    ))?;

    // NOTE: registry is created with issuance_by_default: false  and it is not used.
    // The accum value in the registy is derived from issuance by default: false in `create_revocation_status_list`
    let (revoc_key_pub, revoc_key_priv, _, mut rev_tails_generator) =
        Issuer::new_revocation_registry_def(&credential_pub_key, max_cred_num, false)?;

    let rev_keys_pub = RevocationRegistryDefinitionValuePublicKeys {
        accum_key: revoc_key_pub,
    };

    let (tails_location, tails_hash) = tails_writer.write(&mut rev_tails_generator)?;

    let revoc_reg_def_value = RevocationRegistryDefinitionValue {
        max_cred_num,
        public_keys: rev_keys_pub,
        tails_location,
        tails_hash,
    };

    let revoc_reg_def = RevocationRegistryDefinition {
        revoc_def_type: rev_reg_type,
        issuer_id,
        tag: tag.to_string(),
        cred_def_id,
        value: revoc_reg_def_value,
    };

    let revoc_def_priv = RevocationRegistryDefinitionPrivate {
        value: revoc_key_priv,
    };

    trace!(
        "create_revocation_registry <<< revoc_reg_def: {:?}, private: {:?}",
        revoc_reg_def,
        secret!(&revoc_def_priv),
    );

    Ok((revoc_reg_def, revoc_def_priv))
}

/// Create an Anoncreds Revocation Status List according to the [Anoncreds v1.0 - Revocation Status
/// List](https://hyperledger.github.io/anoncreds-spec/#creating-the-initial-revocation-status-list-object).
///
/// This object can be stored on a VDR, verifiable data registry, to be used later on.
///
/// # Example
///
/// ```rust
/// use anoncreds::issuer;
/// use anoncreds::types::CredentialDefinitionConfig;
/// use anoncreds::types::SignatureType;
/// use anoncreds::types::RegistryType;
/// use anoncreds::tails::TailsFileWriter;
///
/// let attribute_names: &[&str] = &["name", "age"];
/// let schema = issuer::create_schema("schema name",
///                                    "1.0",
///                                    "did:web:xyz",
///                                    attribute_names.into()
///                                    ).expect("Unable to create schema");
///
/// let (cred_def, cred_def_priv, key_correctness_proof) =
///     issuer::create_credential_definition("did:web:xyz/resource/schema",
///                                          &schema,
///                                          "did:web:xyz",
///                                          "default-tag",
///                                          SignatureType::CL,
///                                          CredentialDefinitionConfig {
///                                             support_revocation: true
///                                          },
///                                          ).expect("Unable to create Credential Definition");
///
/// let mut tw = TailsFileWriter::new(None);
/// let (rev_reg_def, rev_reg_def_priv) =
///     issuer::create_revocation_registry_def(&cred_def,
///                                            "did:web:xyz/resource/cred-def",
///                                            "did:web:xyz",
///                                            "default-tag",
///                                            RegistryType::CL_ACCUM,
///                                            1000,
///                                            &mut tw
///                                            ).expect("Unable to create revocation registry");
///
/// let rev_status_list =
///     issuer::create_revocation_status_list("did:web:xyz/resource/rev-reg-def",
///                                           &rev_reg_def,
///                                           "did:web:xyz",
///                                           None,
///                                           true
///                                           ).expect("Unable to create revocation status list");
/// ```
pub fn create_revocation_status_list(
    cred_def: &CredentialDefinition,
    rev_reg_def_id: impl TryInto<RevocationRegistryDefinitionId, Error = ValidationError>,
    rev_reg_def: &RevocationRegistryDefinition,
    rev_reg_priv: &RevocationRegistryDefinitionPrivate,
    issuer_id: impl TryInto<IssuerId, Error = ValidationError>,
    issuance_by_default: bool,
    timestamp: Option<u64>,
) -> Result<RevocationStatusList> {
    let max_cred_num = rev_reg_def.value.max_cred_num;
    let rev_reg_def_id = rev_reg_def_id.try_into()?;
    let issuer_id = issuer_id.try_into()?;
    let mut rev_reg = RevocationRegistry::from(CLSignaturesRevocationRegistry::empty()?);

    if issuer_id != rev_reg_def.issuer_id {
        return Err(err_msg!(
            "Issuer id must be the same as the issuer id in the revocation registry definition"
        ));
    }

    let list = if issuance_by_default {
        let cred_pub_key = cred_def.get_public_key()?;
        let issued = (1..=max_cred_num).collect::<BTreeSet<_>>();

        Issuer::update_revocation_registry(
            &mut rev_reg,
            max_cred_num,
            issued,
            BTreeSet::new(),
            &cred_pub_key,
            &rev_reg_priv.value,
        )?;
        bitvec![0; max_cred_num as usize ]
    } else {
        bitvec![1; max_cred_num as usize ]
    };

    RevocationStatusList::new(
        Some(rev_reg_def_id.to_string().as_str()),
        issuer_id,
        list,
        Some(rev_reg.into()),
        timestamp,
    )
}

/// Update a timestamp in an Anoncreds Revocation Status List according to the [Anoncreds v1.0 -
/// Revocation Status
/// List](https://hyperledger.github.io/anoncreds-spec/#creating-the-initial-revocation-status-list-object).
///
///
/// # Example
///
/// ```rust
/// use anoncreds::issuer;
/// use anoncreds::types::CredentialDefinitionConfig;
/// use anoncreds::types::SignatureType;
/// use anoncreds::types::RegistryType;
/// use anoncreds::tails::TailsFileWriter;
///
/// let attribute_names: &[&str] = &["name", "age"];
/// let schema = issuer::create_schema("schema name",
///                                    "1.0",
///                                    "did:web:xyz",
///                                    attribute_names.into()
///                                    ).expect("Unable to create schema");
///
/// let (cred_def, cred_def_priv, key_correctness_proof) =
///     issuer::create_credential_definition("did:web:xyz/resource/schema",
///                                          &schema,
///                                          "did:web:xyz",
///                                          "default-tag",
///                                          SignatureType::CL,
///                                          CredentialDefinitionConfig {
///                                             support_revocation: true
///                                          },
///                                          ).expect("Unable to create Credential Definition");
///
/// let mut tw = TailsFileWriter::new(None);
/// let (rev_reg_def, rev_reg_def_priv) =
///     issuer::create_revocation_registry_def(&cred_def,
///                                            "did:web:xyz/resource/cred-def",
///                                            "did:web:xyz",
///                                            "default-tag",
///                                            RegistryType::CL_ACCUM,
///                                            1000,
///                                            &mut tw
///                                            ).expect("Unable to create revocation registry");
///
/// let rev_status_list = issuer::create_revocation_status_list("did:web:xyz/resource/rev-reg-def",
///                                                             &rev_reg_def,
///                                                             "did:web:xyz",
///                                                             None,
///                                                             true
///                                                             ).expect("Unable to create revocation status list");
///
/// let updated_rev_status_list = issuer::update_revocation_status_list_timestamp_only(1000,
///                                                                                    &rev_status_list
///                                                                                    );
/// ```
#[must_use]
pub fn update_revocation_status_list_timestamp_only(
    timestamp: u64,
    current_list: &RevocationStatusList,
) -> RevocationStatusList {
    let mut list = current_list.clone();
    // this does not error as only timestamp is updated
    list.update(None, None, None, Some(timestamp)).unwrap();
    list
}

/// Update an Anoncreds Revocation Status List according to the [Anoncreds v1.0 - Revocation Status
/// List](https://hyperledger.github.io/anoncreds-spec/#creating-the-initial-revocation-status-list-object).
///
///
/// # Example
///
/// ```rust
/// use anoncreds::issuer;
/// use anoncreds::types::CredentialDefinitionConfig;
/// use anoncreds::types::SignatureType;
/// use anoncreds::types::RegistryType;
/// use anoncreds::tails::TailsFileWriter;
/// use std::collections::BTreeSet;
///
/// let attribute_names: &[&str] = &["name", "age"];
/// let schema = issuer::create_schema("schema name",
///                                    "1.0",
///                                    "did:web:xyz",
///                                    attribute_names.into()
///                                    ).expect("Unable to create schema");
///
/// let (cred_def, cred_def_priv, key_correctness_proof) =
///     issuer::create_credential_definition("did:web:xyz/resource/schema",
///                                          &schema,
///                                          "did:web:xyz",
///                                          "default-tag",
///                                          SignatureType::CL,
///                                          CredentialDefinitionConfig {
///                                             support_revocation: true
///                                          },
///                                          ).expect("Unable to create Credential Definition");
///
/// let mut tw = TailsFileWriter::new(None);
/// let (rev_reg_def, rev_reg_def_priv) =
///     issuer::create_revocation_registry_def(&cred_def,
///                                            "did:web:xyz/resource/cred-def",
///                                            "did:web:xyz",
///                                            "default-tag",
///                                            RegistryType::CL_ACCUM,
///                                            1000,
///                                            &mut tw
///                                            ).expect("Unable to create revocation registry");
///
/// let rev_status_list = issuer::create_revocation_status_list("did:web:xyz/resource/rev-reg-def",
///                                                             &rev_reg_def,
///                                                             "did:web:xyz",
///                                                             None,
///                                                             true
///                                                             ).expect("Unable to create revocation status list");
///
/// let mut issued: BTreeSet<u32> = BTreeSet::new();
/// issued.insert(1);
///
/// let updated_rev_status_list = issuer::update_revocation_status_list(None,
///                                                                     Some(issued),
///                                                                     None,
///                                                                     &rev_reg_def,
///                                                                     &rev_status_list
///                                                                     ).expect("Unable to update revocation status list");
/// ```
pub fn update_revocation_status_list(
    cred_def: &CredentialDefinition,
    rev_reg_def: &RevocationRegistryDefinition,
    rev_reg_priv: &RevocationRegistryDefinitionPrivate,
    current_list: &RevocationStatusList,
    issued: Option<BTreeSet<u32>>,
    revoked: Option<BTreeSet<u32>>,
    timestamp: Option<u64>,
) -> Result<RevocationStatusList> {
    let mut new_list = current_list.clone();
    let issued = issued.map(|i_list| {
        i_list
            .into_iter()
            .filter(|&i| current_list.get(i as usize).unwrap_or(false))
            .collect::<BTreeSet<_>>()
    });

    let revoked = revoked.map(|r_list| {
        r_list
            .into_iter()
            .filter(|&i| !current_list.get(i as usize).unwrap_or(true))
            .collect::<BTreeSet<_>>()
    });

    let rev_reg_opt: Option<RevocationRegistry> = current_list.try_into()?;
    let mut rev_reg = rev_reg_opt.ok_or_else(|| {
        Error::from_msg(
            ErrorKind::Unexpected,
            "Require Accumulator Value to update Rev Status List",
        )
    })?;
    let cred_pub_key = cred_def.get_public_key()?;
    let max_cred_num = rev_reg_def.value.max_cred_num;

    Issuer::update_revocation_registry(
        &mut rev_reg,
        max_cred_num,
        issued.clone().unwrap_or_default(),
        revoked.clone().unwrap_or_default(),
        &cred_pub_key,
        &rev_reg_priv.value,
    )?;
    new_list.update(Some(rev_reg), issued, revoked, timestamp)?;

    Ok(new_list)
}

/// Create an Anoncreds credential offer according to the [Anoncreds v1.0 specification -
/// Credential Offer](https://hyperledger.github.io/anoncreds-spec/#credential-offer)
///
/// This object can be send to an holder which they can then use to request a credential.
///
/// # Example
///
/// ```rust
/// use anoncreds::issuer;
/// use anoncreds::types::CredentialDefinitionConfig;
/// use anoncreds::types::SignatureType;
///
/// let attribute_names: &[&str] = &["name", "age"];
/// let schema = issuer::create_schema("schema name",
///                                    "1.0",
///                                    "did:web:xyz",
///                                    attribute_names.into()
///                                    ).expect("Unable to create schema");
///
/// let (cred_def, cred_def_priv, key_correctness_proof) =
///     issuer::create_credential_definition("did:web:xyz/resource/schema",
///                                          &schema,
///                                          "did:web:xyz",
///                                          "default-tag",
///                                          SignatureType::CL,
///                                          CredentialDefinitionConfig::default()
///                                          ).expect("Unable to create Credential Definition");
///
/// let credential_offer =
///     issuer::create_credential_offer("did:web:xyz/resource/schema",
///                                     "did:web:xyz/resource/cred-def",
///                                     &key_correctness_proof,
///                                     ).expect("Unable to create Credential Offer");
/// ```
pub fn create_credential_offer(
    schema_id: impl TryInto<SchemaId, Error = ValidationError>,
    cred_def_id: impl TryInto<CredentialDefinitionId, Error = ValidationError>,
    correctness_proof: &CredentialKeyCorrectnessProof,
) -> Result<CredentialOffer> {
    let schema_id = schema_id.try_into()?;
    let cred_def_id = cred_def_id.try_into()?;
    trace!("create_credential_offer >>> cred_def_id: {:?}", cred_def_id);

    let nonce = Nonce::new().map_err(err_map!(Unexpected, "Error creating nonce"))?;

    let key_correctness_proof = correctness_proof
        .try_clone()
        .map_err(err_map!(Unexpected))?;
    let credential_offer = CredentialOffer {
        schema_id,
        cred_def_id,
        key_correctness_proof: key_correctness_proof.value,
        nonce,
        method_name: None,
    };

    trace!("create_credential_offer <<< result: {:?}", credential_offer);
    Ok(credential_offer)
}

/// Create an Anoncreds credential according to the [Anoncreds v1.0 specification -
/// Credential](https://hyperledger.github.io/anoncreds-spec/#issue-credential)
///
/// This object can be send to a holder which means that the credential is issued to that entity.
///
/// # Example
///
/// ```rust
/// use anoncreds::issuer;
/// use anoncreds::prover;
/// use anoncreds::types::MakeCredentialValues;
///
/// use anoncreds::types::CredentialDefinitionConfig;
/// use anoncreds::types::SignatureType;
///
/// let attribute_names: &[&str] = &["name", "age"];
/// let schema = issuer::create_schema("schema name",
///                                    "1.0",
///                                    "did:web:xyz",
///                                    attribute_names.into()
///                                    ).expect("Unable to create schema");
///
/// let (cred_def, cred_def_priv, key_correctness_proof) =
///     issuer::create_credential_definition("did:web:xyz/resource/schema",
///                                          &schema,
///                                          "did:web:xyz",
///                                          "default-tag",
///                                          SignatureType::CL,
///                                          CredentialDefinitionConfig::default()
///                                          ).expect("Unable to create Credential Definition");
///
/// let credential_offer =
///     issuer::create_credential_offer("did:web:xyz/resource/schema",
///                                     "did:web:xyz/resource/cred-def",
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
/// let credential =
///     issuer::create_credential(&cred_def,
///                               &cred_def_priv,
///                               &credential_offer,
///                               &credential_request,
///                               credential_values.into(),
///                               None,
///                               None,
///                               None
///                               ).expect("Unable to create credential");
/// ```
#[allow(clippy::too_many_arguments)]
pub fn create_credential(
    cred_def: &CredentialDefinition,
    cred_def_private: &CredentialDefinitionPrivate,
    cred_offer: &CredentialOffer,
    cred_request: &CredentialRequest,
    cred_values: CredentialValues,
    rev_reg_id: Option<RevocationRegistryId>,
    rev_status_list: Option<&RevocationStatusList>,
    revocation_config: Option<CredentialRevocationConfig>,
) -> Result<Credential> {
    trace!("create_credential >>> cred_def: {:?}, cred_def_private: {:?}, cred_offer.nonce: {:?}, cred_request: {:?},\
            cred_values: {:?}, revocation_config: {:?}",
            cred_def, secret!(&cred_def_private), &cred_offer.nonce, &cred_request, secret!(&cred_values), revocation_config,
            );

    let cred_public_key = cred_def.get_public_key().map_err(err_map!(
        Unexpected,
        "Error fetching public key from credential definition"
    ))?;
    let credential_values = build_credential_values(&cred_values.0, None)?;

    let (credential_signature, signature_correctness_proof, rev_reg, witness) =
        if let (Some(revocation_config), Some(rev_status_list)) =
            (revocation_config, rev_status_list)
        {
            let rev_reg_def = &revocation_config.reg_def.value;
            let rev_reg: Option<CLSignaturesRevocationRegistry> = rev_status_list.into();
            let rev_reg = rev_reg.ok_or_else(|| {
                err_msg!(
                    Unexpected,
                    "RevocationStatusList should have accumulator value"
                )
            })?;

            let mut rev_reg: RevocationRegistry = rev_reg.into();

            let status = rev_status_list
                .get(revocation_config.registry_idx as usize)
                .ok_or_else(|| {
                    err_msg!(
                        "Revocation status list does not have the index {}",
                        revocation_config.registry_idx
                    )
                })?;

            // This will be a temporary solution for the `issuance_on_demand` vs
            // `issuance_by_default` state. Right now, we pass in the revcation status list and
            // we check in this list whether the provided idx (revocation_config.registry_idx)
            // is inside the revocation status list. If it is not in there we hit an edge case,
            // which should not be possible within the happy flow.
            //
            // If the index is inside the revocation status list we check whether it is set to
            // `true` or `false` within the bitvec.
            // When it is set to `true`, or 1, we invert the value. This means that we use
            // `issuance_on_demand`.
            // When it is set to `false`, or 0, we invert the value. This means that we use
            // `issuance_by_default`.
            let issuance_by_default = !status;

            let (credential_signature, signature_correctness_proof, witness, _opt_delta) =
                Issuer::sign_credential_with_revoc(
                    &cred_request.entropy()?,
                    &cred_request.blinded_ms,
                    &cred_request.blinded_ms_correctness_proof,
                    cred_offer.nonce.as_native(),
                    cred_request.nonce.as_native(),
                    &credential_values,
                    &cred_public_key,
                    &cred_def_private.value,
                    revocation_config.registry_idx,
                    rev_reg_def.max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &revocation_config.reg_def_private.value,
                )?;
            (
                credential_signature,
                signature_correctness_proof,
                Some(rev_reg),
                Some(witness),
            )
        } else {
            let (signature, correctness_proof) = Issuer::sign_credential(
                &cred_request.entropy()?,
                &cred_request.blinded_ms,
                &cred_request.blinded_ms_correctness_proof,
                cred_offer.nonce.as_native(),
                cred_request.nonce.as_native(),
                &credential_values,
                &cred_public_key,
                &cred_def_private.value,
            )?;
            (signature, correctness_proof, None, None)
        };

    let credential = Credential {
        schema_id: cred_offer.schema_id.clone(),
        cred_def_id: cred_offer.cred_def_id.clone(),
        rev_reg_id,
        values: cred_values,
        signature: credential_signature,
        signature_correctness_proof,
        rev_reg,
        witness,
    };

    trace!(
        "create_credential <<< credential {:?}",
        secret!(&credential),
    );

    Ok(credential)
}

#[cfg(test)]
mod tests {
    use crate::{services::helpers::encode_credential_attribute, tails::TailsFileWriter};

    use super::*;

    #[test]
    fn test_issuer_id_equal_in_revocation_registry_definiton_and_credential_definition(
    ) -> Result<()> {
        let credential_definition_issuer_id = "sample:id";
        let revocation_registry_definition_issuer_id = credential_definition_issuer_id;

        let attr_names = AttributeNames::from(vec!["name".to_owned(), "age".to_owned()]);
        let schema = create_schema("schema:name", "1.0", "sample:uri", attr_names)?;
        let cred_def = create_credential_definition(
            "schema:id",
            &schema,
            credential_definition_issuer_id,
            "default",
            SignatureType::CL,
            CredentialDefinitionConfig {
                support_revocation: true,
            },
        )?;
        let res = create_revocation_registry_def(
            &cred_def.0,
            "sample:uri",
            revocation_registry_definition_issuer_id,
            "default",
            RegistryType::CL_ACCUM,
            1,
            &mut TailsFileWriter::new(None),
        );

        assert!(res.is_ok());
        Ok(())
    }

    #[test]
    fn test_issuer_id_unequal_in_revocation_registry_definiton_and_credential_definition(
    ) -> Result<()> {
        let credential_definition_issuer_id = "sample:id";
        let revocation_registry_definition_issuer_id = "another:id";

        let attr_names = AttributeNames::from(vec!["name".to_owned(), "age".to_owned()]);
        let schema = create_schema("schema:name", "1.0", "sample:uri", attr_names)?;
        let cred_def = create_credential_definition(
            "schema:id",
            &schema,
            credential_definition_issuer_id,
            "default",
            SignatureType::CL,
            CredentialDefinitionConfig {
                support_revocation: true,
            },
        )?;
        let res = create_revocation_registry_def(
            &cred_def.0,
            "sample:uri",
            revocation_registry_definition_issuer_id,
            "default",
            RegistryType::CL_ACCUM,
            1,
            &mut TailsFileWriter::new(None),
        );

        assert!(res.is_err());
        Ok(())
    }

    #[test]
    fn test_encode_attribute() {
        assert_eq!(
            encode_credential_attribute("101 Wilson Lane").unwrap(),
            "68086943237164982734333428280784300550565381723532936263016368251445461241953"
        );
        assert_eq!(encode_credential_attribute("87121").unwrap(), "87121");
        assert_eq!(
            encode_credential_attribute("SLC").unwrap(),
            "101327353979588246869873249766058188995681113722618593621043638294296500696424"
        );
        assert_eq!(
            encode_credential_attribute("101 Tela Lane").unwrap(),
            "63690509275174663089934667471948380740244018358024875547775652380902762701972"
        );
        assert_eq!(
            encode_credential_attribute("UT").unwrap(),
            "93856629670657830351991220989031130499313559332549427637940645777813964461231"
        );
        assert_eq!(
            encode_credential_attribute("").unwrap(),
            "102987336249554097029535212322581322789799900648198034993379397001115665086549"
        );
        assert_eq!(
            encode_credential_attribute("None").unwrap(),
            "99769404535520360775991420569103450442789945655240760487761322098828903685777"
        );
        assert_eq!(encode_credential_attribute("0").unwrap(), "0");
        assert_eq!(encode_credential_attribute("1").unwrap(), "1");

        // max i32
        assert_eq!(
            encode_credential_attribute("2147483647").unwrap(),
            "2147483647"
        );
        assert_eq!(
            encode_credential_attribute("2147483648").unwrap(),
            "26221484005389514539852548961319751347124425277437769688639924217837557266135"
        );

        // min i32
        assert_eq!(
            encode_credential_attribute("-2147483648").unwrap(),
            "-2147483648"
        );
        assert_eq!(
            encode_credential_attribute("-2147483649").unwrap(),
            "68956915425095939579909400566452872085353864667122112803508671228696852865689"
        );

        assert_eq!(
            encode_credential_attribute("0.0").unwrap(),
            "62838607218564353630028473473939957328943626306458686867332534889076311281879"
        );
        assert_eq!(
            encode_credential_attribute("\x00").unwrap(),
            "49846369543417741186729467304575255505141344055555831574636310663216789168157"
        );
        assert_eq!(
            encode_credential_attribute("\x01").unwrap(),
            "34356466678672179216206944866734405838331831190171667647615530531663699592602"
        );
        assert_eq!(
            encode_credential_attribute("\x02").unwrap(),
            "99398763056634537812744552006896172984671876672520535998211840060697129507206"
        );
    }
}
