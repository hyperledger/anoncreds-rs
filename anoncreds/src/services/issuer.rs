use std::collections::{BTreeSet, HashSet};
use std::iter::FromIterator;

use indy_utils::ValidationError;

use super::types::*;
use crate::data_types::anoncreds::cred_def::CredentialDefinitionId;
use crate::data_types::anoncreds::issuer_id::IssuerId;
use crate::data_types::anoncreds::rev_reg::RevocationRegistryId;
use crate::data_types::anoncreds::schema::SchemaId;
use crate::data_types::anoncreds::{
    cred_def::{CredentialDefinition, CredentialDefinitionData},
    nonce::Nonce,
    rev_reg::{RevocationRegistryDeltaV1, RevocationRegistryV1},
    rev_reg_def::{
        RevocationRegistryDefinitionV1, RevocationRegistryDefinitionValue,
        RevocationRegistryDefinitionValuePublicKeys,
    },
    schema::Schema,
};
use crate::error::Result;
use crate::services::helpers::*;
use crate::ursa::cl::{
    issuer::Issuer as CryptoIssuer, RevocationRegistryDelta as CryptoRevocationRegistryDelta,
    Witness,
};

use super::tails::{TailsFileReader, TailsReader, TailsWriter};

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
    Ok(schema)
}

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
        CryptoIssuer::new_credential_def(
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
            primary: credential_public_key.get_primary_key()?.try_clone()?,
            revocation: credential_public_key.get_revocation_key()?,
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

pub fn create_revocation_registry<TW>(
    cred_def: &CredentialDefinition,
    cred_def_id: impl TryInto<CredentialDefinitionId, Error = ValidationError>,
    tag: &str,
    rev_reg_type: RegistryType,
    issuance_type: IssuanceType,
    max_cred_num: u32,
    tails_writer: &mut TW,
) -> Result<(
    RevocationRegistryDefinition,
    RevocationRegistryDefinitionPrivate,
    RevocationRegistry,
    RevocationRegistryDelta,
)>
where
    TW: TailsWriter,
{
    trace!("create_revocation_registry >>> cred_def: {:?}, tag: {:?}, max_cred_num: {:?}, rev_reg_type: {:?}, issuance_type: {:?}",
             cred_def, tag, max_cred_num, rev_reg_type, issuance_type);
    let cred_def_id = cred_def_id.try_into()?;

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
            revoc_def_type: rev_reg_type,
            tag: tag.to_string(),
            cred_def_id,
            value: revoc_reg_def_value,
        },
    );

    let revoc_reg = RevocationRegistry::RevocationRegistryV1(RevocationRegistryV1 {
        value: revoc_registry,
    });

    // now update registry to reflect issuance-by-default
    let (revoc_reg, revoc_init_delta) = if issuance_type == IssuanceType::ISSUANCE_BY_DEFAULT {
        let tails_reader = TailsFileReader::new_tails_reader(&tails_location);
        let issued = BTreeSet::from_iter(1..=max_cred_num);
        update_revocation_registry(
            &revoc_reg_def,
            &revoc_reg,
            issued,
            BTreeSet::new(),
            &tails_reader,
        )?
    } else {
        let delta = revoc_reg.initial_delta();
        (revoc_reg, delta)
    };

    let revoc_def_priv = RevocationRegistryDefinitionPrivate {
        value: revoc_key_priv,
    };

    trace!(
        "create_revocation_registry <<< revoc_reg_def: {:?}, private: {:?}, revoc_reg: {:?}",
        revoc_reg_def,
        secret!(&revoc_def_priv),
        revoc_reg
    );

    Ok((revoc_reg_def, revoc_def_priv, revoc_reg, revoc_init_delta))
}

pub fn update_revocation_registry(
    rev_reg_def: &RevocationRegistryDefinition,
    rev_reg: &RevocationRegistry,
    issued: BTreeSet<u32>,
    revoked: BTreeSet<u32>,
    tails_reader: &TailsReader,
) -> Result<(RevocationRegistry, RevocationRegistryDelta)> {
    let RevocationRegistryDefinition::RevocationRegistryDefinitionV1(rev_reg_def) = rev_reg_def;
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

pub fn create_credential(
    cred_def: &CredentialDefinition,
    cred_def_private: &CredentialDefinitionPrivate,
    cred_offer: &CredentialOffer,
    cred_request: &CredentialRequest,
    cred_values: CredentialValues,
    rev_reg_id: Option<RevocationRegistryId>,
    revocation_config: Option<CredentialRevocationConfig>,
) -> Result<(
    Credential,
    Option<RevocationRegistry>,
    Option<RevocationRegistryDelta>,
)> {
    trace!("create_credential >>> cred_def: {:?}, cred_def_private: {:?}, cred_offer.nonce: {:?}, cred_request: {:?},\
            cred_values: {:?}, revocation_config: {:?}",
            cred_def, secret!(&cred_def_private), &cred_offer.nonce, &cred_request, secret!(&cred_values), revocation_config,
            );

    let cred_public_key = cred_def.get_public_key().map_err(err_map!(
        Unexpected,
        "Error fetching public key from credential definition"
    ))?;
    let credential_values = build_credential_values(&cred_values.0, None)?;

    let (credential_signature, signature_correctness_proof, rev_reg, rev_reg_delta, witness) =
        match revocation_config {
            Some(revocation) => {
                let rev_reg_def = match revocation.reg_def {
                    RevocationRegistryDefinition::RevocationRegistryDefinitionV1(v1) => &v1.value,
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

                let witness = {
                    let empty = HashSet::new();
                    let (by_default, issued, revoked) = match rev_reg_def.issuance_type {
                        IssuanceType::ISSUANCE_ON_DEMAND => {
                            (false, revocation.registry_used, &empty)
                        }
                        IssuanceType::ISSUANCE_BY_DEFAULT => {
                            (true, &empty, revocation.registry_used)
                        }
                    };

                    let rev_reg_delta =
                        CryptoRevocationRegistryDelta::from_parts(None, &rev_reg, issued, revoked);
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
                (signature, correctness_proof, None, None, None)
            }
        };

    let credential = Credential {
        schema_id: cred_offer.schema_id.to_owned(),
        cred_def_id: cred_offer.cred_def_id.to_owned(),
        rev_reg_id,
        values: cred_values,
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
        "create_credential <<< credential {:?}, rev_reg_delta {:?}",
        secret!(&credential),
        rev_reg_delta
    );

    Ok((credential, rev_reg, rev_reg_delta))
}

pub fn revoke_credential(
    rev_reg_def: &RevocationRegistryDefinition,
    rev_reg: &RevocationRegistry,
    cred_rev_idx: u32,
    tails_reader: &TailsReader,
) -> Result<(RevocationRegistry, RevocationRegistryDelta)> {
    trace!(
        "revoke >>> rev_reg_def: {:?}, rev_reg: {:?}, cred_rev_idx: {:?}",
        rev_reg_def,
        rev_reg,
        secret!(&cred_rev_idx)
    );

    let max_cred_num = match rev_reg_def {
        RevocationRegistryDefinition::RevocationRegistryDefinitionV1(v1) => v1.value.max_cred_num,
    };
    let mut rev_reg = match rev_reg {
        RevocationRegistry::RevocationRegistryV1(v1) => v1.value.clone(),
    };
    let rev_reg_delta =
        CryptoIssuer::revoke_credential(&mut rev_reg, max_cred_num, cred_rev_idx, tails_reader)?;

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
    rev_reg_def: &RevocationRegistryDefinition,
    rev_reg: &RevocationRegistry,
    cred_rev_idx: u32,
    tails_reader: &TailsReader,
) -> Result<(RevocationRegistry, RevocationRegistryDelta)> {
    trace!(
        "recover >>> rev_reg_def: {:?}, rev_reg: {:?}, cred_rev_idx: {:?}",
        rev_reg_def,
        rev_reg,
        secret!(&cred_rev_idx)
    );

    let max_cred_num = match rev_reg_def {
        RevocationRegistryDefinition::RevocationRegistryDefinitionV1(v1) => v1.value.max_cred_num,
    };
    let mut rev_reg = match rev_reg {
        RevocationRegistry::RevocationRegistryV1(v1) => v1.value.clone(),
    };
    let rev_reg_delta =
        CryptoIssuer::recovery_credential(&mut rev_reg, max_cred_num, cred_rev_idx, tails_reader)?;

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

#[cfg(test)]
mod tests {
    use super::*;

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
