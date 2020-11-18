use std::collections::{BTreeSet, HashSet};
use std::iter::FromIterator;

use super::types::*;
use crate::error::Result;
use crate::services::helpers::*;
use crate::ursa::cl::{
    issuer::Issuer as CryptoIssuer, RevocationRegistryDelta as CryptoRevocationRegistryDelta,
    Witness,
};
use indy_data_types::anoncreds::{
    cred_def::{CredentialDefinitionData, CredentialDefinitionV1},
    nonce::Nonce,
    rev_reg::{RevocationRegistryDeltaV1, RevocationRegistryV1},
    rev_reg_def::{
        RevocationRegistryDefinitionV1, RevocationRegistryDefinitionValue,
        RevocationRegistryDefinitionValuePublicKeys,
    },
    schema::SchemaV1,
};
use indy_utils::{Qualifiable, Validatable};

use super::tails::{TailsFileReader, TailsReader, TailsWriter};

pub fn new_schema(
    origin_did: &DidValue,
    schema_name: &str,
    schema_version: &str,
    attr_names: AttributeNames,
    seq_no: Option<u32>,
) -> Result<Schema> {
    trace!("new_schema >>> origin_did: {:?}, schema_name: {:?}, schema_version: {:?}, attr_names: {:?}",
        origin_did, schema_name, schema_version, attr_names);

    origin_did.validate()?;
    let schema_id = SchemaId::new(&origin_did, schema_name, schema_version);
    let schema = SchemaV1 {
        id: schema_id,
        name: schema_name.to_string(),
        version: schema_version.to_string(),
        attr_names,
        seq_no,
    };
    Ok(Schema::SchemaV1(schema))
}

pub fn make_credential_definition_id(
    origin_did: &DidValue,
    schema_id: &SchemaId,
    schema_seq_no: Option<u32>,
    tag: &str,
    signature_type: SignatureType,
) -> Result<(CredentialDefinitionId, SchemaId)> {
    let schema_id = match (origin_did.get_method(), schema_id.get_method()) {
        (None, Some(_)) => {
            return Err(err_msg!(
                "Cannot use an unqualified Origin DID with fully qualified Schema ID",
            ));
        }
        (method, _) => schema_id.default_method(method),
    };
    let schema_infix_id = schema_seq_no
        .map(|n| SchemaId(n.to_string()))
        .unwrap_or(SchemaId(schema_id.0.clone()));

    Ok((
        CredentialDefinitionId::new(origin_did, &schema_infix_id, &signature_type.to_str(), tag),
        schema_infix_id,
    ))
}

pub fn new_credential_definition(
    origin_did: &DidValue,
    schema: &Schema,
    tag: &str,
    signature_type: SignatureType,
    config: CredentialDefinitionConfig,
) -> Result<(
    CredentialDefinition,
    CredentialDefinitionPrivate,
    CredentialKeyCorrectnessProof,
)> {
    trace!(
        "new_credential_definition >>> schema: {:?}, config: {:?}",
        schema,
        config
    );

    let schema = match schema {
        Schema::SchemaV1(s) => s,
    };
    let (cred_def_id, schema_id) =
        make_credential_definition_id(origin_did, &schema.id, schema.seq_no, tag, signature_type)?;

    let credential_schema = build_credential_schema(&schema.attr_names.0)?;
    let non_credential_schema = build_non_credential_schema()?;

    let (credential_public_key, credential_private_key, correctness_proof) =
        CryptoIssuer::new_credential_def(
            &credential_schema,
            &non_credential_schema,
            config.support_revocation,
        )?;

    let cred_def = CredentialDefinition::CredentialDefinitionV1(CredentialDefinitionV1 {
        id: cred_def_id,
        schema_id,
        signature_type,
        tag: tag.to_owned(),
        value: CredentialDefinitionData {
            primary: credential_public_key.get_primary_key()?.try_clone()?,
            revocation: credential_public_key.get_revocation_key()?.clone(),
        },
    });

    let cred_def_private = CredentialDefinitionPrivate {
        value: credential_private_key,
    };
    let cred_key_proof = CredentialKeyCorrectnessProof {
        value: correctness_proof,
    };
    trace!(
        "new_credential_definition <<< cred_def: {:?}, cred_def: {:?}, key_correctness_proof: {:?}",
        cred_def,
        secret!(&cred_def_private),
        cred_key_proof
    );

    Ok((cred_def, cred_def_private, cred_key_proof))
}

pub fn make_revocation_registry_id(
    origin_did: &DidValue,
    cred_def: &CredentialDefinition,
    tag: &str,
    rev_reg_type: RegistryType,
) -> Result<RevocationRegistryId> {
    let cred_def = match cred_def {
        CredentialDefinition::CredentialDefinitionV1(c) => c,
    };

    let origin_did = match (origin_did.get_method(), cred_def.id.get_method()) {
        (None, Some(_)) => {
            return Err(err_msg!("Cannot use an unqualified Origin DID with a fully qualified Credential Definition ID"));
        }
        (Some(_), None) => {
            return Err(err_msg!("Cannot use a fully qualified Origin DID with an unqualified Credential Definition ID"));
        }
        _ => origin_did,
    };

    Ok(RevocationRegistryId::new(
        &origin_did,
        &cred_def.id,
        &rev_reg_type.to_str(),
        tag,
    ))
}

pub fn new_revocation_registry<TW>(
    origin_did: &DidValue,
    cred_def: &CredentialDefinition,
    tag: &str,
    rev_reg_type: RegistryType,
    issuance_type: IssuanceType,
    max_cred_num: u32,
    tails_writer: &mut TW,
) -> Result<(
    RevocationRegistryDefinition,
    RevocationRegistryDefinitionPrivate,
    RevocationRegistry,
)>
where
    TW: TailsWriter,
{
    trace!("new_revocation_registry >>> origin_did: {:?}, cred_def: {:?}, tag: {:?}, max_cred_num: {:?}, rev_reg_type: {:?}, issuance_type: {:?}",
            origin_did, cred_def, tag, max_cred_num, rev_reg_type, issuance_type);

    let rev_reg_id = make_revocation_registry_id(origin_did, cred_def, tag, rev_reg_type)?;

    let cred_def = match cred_def {
        CredentialDefinition::CredentialDefinitionV1(c) => c,
    };
    let credential_pub_key = cred_def.get_public_key().map_err(err_map!(
        Unexpected,
        "Error fetching public key from credential definition"
    ))?;

    // NOTE: registry is created with issuance_by_default: false, then updated later
    // this avoids generating the tails twice and is significantly faster
    let (revoc_key_pub, revoc_key_priv, revoc_registry, mut rev_tails_generator) =
        CryptoIssuer::new_revocation_registry_def(&credential_pub_key, max_cred_num, false)?;

    let rev_keys_pub = RevocationRegistryDefinitionValuePublicKeys {
        accum_key: revoc_key_pub,
    };

    let (tails_location, tails_hash) = tails_writer.write(&mut rev_tails_generator)?;

    let revoc_reg_def_value = RevocationRegistryDefinitionValue {
        max_cred_num,
        issuance_type,
        public_keys: rev_keys_pub,
        tails_location: tails_location.clone(),
        tails_hash,
    };

    let revoc_reg_def = RevocationRegistryDefinition::RevocationRegistryDefinitionV1(
        RevocationRegistryDefinitionV1 {
            id: rev_reg_id.clone(),
            revoc_def_type: rev_reg_type,
            tag: tag.to_string(),
            cred_def_id: cred_def.id.clone(),
            value: revoc_reg_def_value,
        },
    );

    let revoc_reg = RevocationRegistry::RevocationRegistryV1(RevocationRegistryV1 {
        value: revoc_registry,
    });

    // now update registry to reflect issuance-by-default
    let revoc_reg = if issuance_type == IssuanceType::ISSUANCE_BY_DEFAULT {
        let tails_reader = TailsFileReader::new(&tails_location);
        let issued = BTreeSet::from_iter((1..=max_cred_num).into_iter());
        let (reg, _delta) = update_revocation_registry(
            &revoc_reg_def,
            &revoc_reg,
            issued,
            BTreeSet::new(),
            &tails_reader,
        )?;
        reg
    } else {
        revoc_reg
    };

    let revoc_def_priv = RevocationRegistryDefinitionPrivate {
        value: revoc_key_priv,
    };
    trace!(
        "new_revocation_registry <<< revoc_reg_def: {:?}, private: {:?}, revoc_reg: {:?}",
        revoc_reg_def,
        secret!(&revoc_def_priv),
        revoc_reg
    );

    Ok((revoc_reg_def, revoc_def_priv, revoc_reg))
}

pub fn update_revocation_registry(
    rev_reg_def: &RevocationRegistryDefinition,
    rev_reg: &RevocationRegistry,
    issued: BTreeSet<u32>,
    revoked: BTreeSet<u32>,
    tails_reader: &TailsReader,
) -> Result<(RevocationRegistry, RevocationRegistryDelta)> {
    let rev_reg_def = match rev_reg_def {
        RevocationRegistryDefinition::RevocationRegistryDefinitionV1(v1) => v1,
    };
    let mut rev_reg = match rev_reg {
        RevocationRegistry::RevocationRegistryV1(v1) => v1.value.clone(),
    };
    let max_cred_num = rev_reg_def.value.max_cred_num;
    let delta = CryptoIssuer::update_revocation_registry(
        &mut rev_reg,
        max_cred_num,
        issued,
        revoked,
        tails_reader,
    )?;
    Ok((
        RevocationRegistry::RevocationRegistryV1(RevocationRegistryV1 { value: rev_reg }),
        RevocationRegistryDelta::RevocationRegistryDeltaV1(RevocationRegistryDeltaV1 {
            value: delta,
        }),
    ))
}

pub fn new_credential_offer(
    schema_id: &SchemaId,
    cred_def: &CredentialDefinition,
    correctness_proof: &CredentialKeyCorrectnessProof,
) -> Result<CredentialOffer> {
    trace!("new_credential_offer >>> cred_def: {:?}", cred_def);

    let nonce = Nonce::new().map_err(err_map!(Unexpected, "Error creating nonce"))?;

    let cred_def = match cred_def {
        CredentialDefinition::CredentialDefinitionV1(c) => c,
    };

    let key_correctness_proof = correctness_proof
        .try_clone()
        .map_err(err_map!(Unexpected))?;
    let credential_offer = CredentialOffer {
        schema_id: schema_id.clone(),
        cred_def_id: cred_def.id.clone(),
        key_correctness_proof: key_correctness_proof.value,
        nonce,
        method_name: None,
    };

    trace!("new_credential_offer <<< result: {:?}", credential_offer);
    Ok(credential_offer)
}

pub fn new_credential(
    cred_def: &CredentialDefinition,
    cred_def_private: &CredentialDefinitionPrivate,
    cred_offer: &CredentialOffer,
    cred_request: &CredentialRequest,
    cred_values: &CredentialValues,
    revocation_config: Option<CredentialRevocationConfig>,
) -> Result<(
    Credential,
    Option<RevocationRegistry>,
    Option<RevocationRegistryDelta>,
)> {
    trace!("new_credential >>> cred_def: {:?}, cred_def_private: {:?}, cred_offer.nonce: {:?}, cred_request: {:?},\
            cred_values: {:?}, revocation_config: {:?}",
            cred_def, secret!(&cred_def_private), &cred_offer.nonce, &cred_request, secret!(&cred_values), revocation_config,
            );

    let cred_public_key = match cred_def {
        CredentialDefinition::CredentialDefinitionV1(cd) => {
            cd.get_public_key().map_err(err_map!(
                Unexpected,
                "Error fetching public key from credential definition"
            ))?
        }
    };
    let credential_values = build_credential_values(&cred_values.0, None)?;

    let (
        credential_signature,
        signature_correctness_proof,
        rev_reg_id,
        rev_reg,
        rev_reg_delta,
        witness,
    ) = match revocation_config {
        Some(revocation) => {
            let (rev_reg_def, reg_reg_id) = match revocation.reg_def {
                RevocationRegistryDefinition::RevocationRegistryDefinitionV1(v1) => {
                    (&v1.value, v1.id.clone())
                }
            };
            let mut rev_reg = match revocation.registry {
                RevocationRegistry::RevocationRegistryV1(v1) => v1.value.clone(),
            };
            let (credential_signature, signature_correctness_proof, delta) =
                CryptoIssuer::sign_credential_with_revoc(
                    &cred_request.prover_did.0,
                    &cred_request.blinded_ms,
                    &cred_request.blinded_ms_correctness_proof,
                    cred_offer.nonce.as_native(),
                    cred_request.nonce.as_native(),
                    &credential_values,
                    &cred_public_key,
                    &cred_def_private.value,
                    revocation.registry_idx,
                    rev_reg_def.max_cred_num,
                    rev_reg_def.issuance_type.to_bool(),
                    &mut rev_reg,
                    &revocation.reg_def_private.value,
                    &revocation.tails_reader,
                )?;

            let cred_rev_reg_id = match cred_offer.method_name.as_ref() {
                Some(ref _method_name) => Some(reg_reg_id.to_unqualified()),
                _ => Some(reg_reg_id.clone()),
            };
            let witness = {
                let used = HashSet::new(); // FIXME HashSet::from_iter((0..revocation.registry_idx).into_iter());
                let (by_default, issued, revoked) = match rev_reg_def.issuance_type {
                    IssuanceType::ISSUANCE_ON_DEMAND => (false, used, HashSet::new()),
                    IssuanceType::ISSUANCE_BY_DEFAULT => (true, HashSet::new(), used),
                };

                let rev_reg_delta =
                    CryptoRevocationRegistryDelta::from_parts(None, &rev_reg, &issued, &revoked);
                Witness::new(
                    revocation.registry_idx,
                    rev_reg_def.max_cred_num,
                    by_default,
                    &rev_reg_delta,
                    &revocation.tails_reader,
                )?
            };
            (
                credential_signature,
                signature_correctness_proof,
                cred_rev_reg_id,
                Some(rev_reg),
                delta,
                Some(witness),
            )
        }
        None => {
            let (signature, correctness_proof) = CryptoIssuer::sign_credential(
                &cred_request.prover_did.0,
                &cred_request.blinded_ms,
                &cred_request.blinded_ms_correctness_proof,
                cred_offer.nonce.as_native(),
                cred_request.nonce.as_native(),
                &credential_values,
                &cred_public_key,
                &cred_def_private.value,
            )?;
            (signature, correctness_proof, None, None, None, None)
        }
    };

    let credential = Credential {
        schema_id: cred_offer.schema_id.clone(),
        cred_def_id: cred_offer.cred_def_id.clone(),
        rev_reg_id,
        values: cred_values.clone(),
        signature: credential_signature,
        signature_correctness_proof,
        rev_reg: rev_reg.clone(),
        witness,
    };

    let rev_reg = rev_reg
        .map(|reg| RevocationRegistry::RevocationRegistryV1(RevocationRegistryV1 { value: reg }));
    let rev_reg_delta = rev_reg_delta.map(|delta| {
        RevocationRegistryDelta::RevocationRegistryDeltaV1(RevocationRegistryDeltaV1 {
            value: delta,
        })
    });

    trace!(
        "new_credential <<< credential {:?}, rev_reg_delta {:?}",
        secret!(&credential),
        rev_reg_delta
    );

    Ok((credential, rev_reg, rev_reg_delta))
}

pub fn revoke_credential(
    rev_reg: &RevocationRegistry,
    max_cred_num: u32,
    rev_idx: u32,
    tails_reader: &TailsReader,
) -> Result<(RevocationRegistry, RevocationRegistryDelta)> {
    trace!(
        "revoke >>> rev_reg: {:?}, max_cred_num: {:?}, rev_idx: {:?}",
        rev_reg,
        max_cred_num,
        secret!(&rev_idx)
    );

    let mut rev_reg = match rev_reg {
        RevocationRegistry::RevocationRegistryV1(v1) => v1.value.clone(),
    };
    let rev_reg_delta =
        CryptoIssuer::revoke_credential(&mut rev_reg, max_cred_num, rev_idx, tails_reader)?;

    let new_rev_reg =
        RevocationRegistry::RevocationRegistryV1(RevocationRegistryV1 { value: rev_reg });
    let delta = RevocationRegistryDelta::RevocationRegistryDeltaV1(RevocationRegistryDeltaV1 {
        value: rev_reg_delta,
    });
    trace!("revoke <<< rev_reg_delta {:?}", delta);

    Ok((new_rev_reg, delta))
}

#[allow(dead_code)]
pub fn recover_credential(
    rev_reg: &RevocationRegistry,
    max_cred_num: u32,
    rev_idx: u32,
    tails_reader: &TailsReader,
) -> Result<(RevocationRegistry, RevocationRegistryDelta)> {
    trace!(
        "recover >>> rev_reg: {:?}, max_cred_num: {:?}, rev_idx: {:?}",
        rev_reg,
        max_cred_num,
        secret!(&rev_idx)
    );

    let mut rev_reg = match rev_reg {
        RevocationRegistry::RevocationRegistryV1(v1) => v1.value.clone(),
    };
    let rev_reg_delta =
        CryptoIssuer::recovery_credential(&mut rev_reg, max_cred_num, rev_idx, tails_reader)?;

    let new_rev_reg =
        RevocationRegistry::RevocationRegistryV1(RevocationRegistryV1 { value: rev_reg });
    let delta = RevocationRegistryDelta::RevocationRegistryDeltaV1(RevocationRegistryDeltaV1 {
        value: rev_reg_delta,
    });
    trace!("recover <<< rev_reg_delta {:?}", delta);

    Ok((new_rev_reg, delta))
}

pub fn merge_revocation_registry_deltas(
    rev_reg_delta: &RevocationRegistryDelta,
    other_delta: &RevocationRegistryDelta,
) -> Result<RevocationRegistryDelta> {
    match (rev_reg_delta, other_delta) {
        (
            RevocationRegistryDelta::RevocationRegistryDeltaV1(v1),
            RevocationRegistryDelta::RevocationRegistryDeltaV1(other),
        ) => {
            let mut result = v1.clone();
            result.value.merge(&other.value)?;
            Ok(RevocationRegistryDelta::RevocationRegistryDeltaV1(result))
        }
    }
}

pub struct CredentialRevocationConfig<'a> {
    pub reg_def: &'a RevocationRegistryDefinition,
    pub reg_def_private: &'a RevocationRegistryDefinitionPrivate,
    pub registry: &'a RevocationRegistry,
    pub registry_idx: u32,
    pub tails_reader: TailsReader,
}

impl<'a> std::fmt::Debug for CredentialRevocationConfig<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CredentialRevocationConfig {{ reg_def: {:?}, private: {:?}, registry: {:?}, idx: {}, reader: {:?} }}",
            self.reg_def,
            secret!(self.reg_def_private),
            self.registry,
            secret!(self.registry_idx),
            self.tails_reader,
        )
    }
}

/*#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_credential_definition() {
        let attrs = r#"["one", "two"]"#;
        let attr_names = serde_json::from_str::<AttributeNames>(attrs).unwrap();
        Issuer::new_credential_definition(&attr_names, false).unwrap();
    }
}
*/
