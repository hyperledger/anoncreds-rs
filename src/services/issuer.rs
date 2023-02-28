use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::collections::{BTreeSet, HashSet};
use std::iter::FromIterator;

use super::types::*;

use crate::data_types::cred_def::CredentialDefinitionId;
use crate::data_types::issuer_id::IssuerId;
use crate::data_types::rev_reg::RevocationRegistryId;
use crate::data_types::rev_reg_def::RevocationRegistryDefinitionId;
use crate::data_types::schema::SchemaId;
use crate::data_types::{
    cred_def::{CredentialDefinition, CredentialDefinitionData},
    nonce::Nonce,
    rev_reg_def::{RevocationRegistryDefinitionValue, RevocationRegistryDefinitionValuePublicKeys},
    schema::Schema,
};
use crate::error::{Error, ErrorKind, Result, ValidationError};
use crate::services::helpers::*;
use crate::ursa::cl::{
    issuer::Issuer as CryptoIssuer, RevocationRegistryDelta as CryptoRevocationRegistryDelta,
    Witness,
};
use crate::utils::validation::Validatable;
use bitvec::bitvec;

use super::tails::{TailsFileReader, TailsWriter};

const ACCUM_NO_ISSUED: &str = "{\"accum\":\"1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000\"}";

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
        CryptoIssuer::new_revocation_registry_def(&credential_pub_key, max_cred_num, false)?;

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

pub fn create_revocation_status_list(
    rev_reg_def_id: impl TryInto<RevocationRegistryDefinitionId, Error = ValidationError>,
    rev_reg_def: &RevocationRegistryDefinition,
    issuer_id: impl TryInto<IssuerId, Error = ValidationError>,
    timestamp: Option<u64>,
    issuance_by_default: bool,
) -> Result<RevocationStatusList>
{
    let mut rev_reg: ursa::cl::RevocationRegistry = serde_json::from_str(ACCUM_NO_ISSUED)?;
    let max_cred_num = rev_reg_def.value.max_cred_num;
    let rev_reg_def_id = rev_reg_def_id.try_into()?;
    let issuer_id = issuer_id.try_into()?;

    let list = if issuance_by_default {
        let tails_reader = TailsFileReader::new_tails_reader(&rev_reg_def.value.tails_location);
        let issued = BTreeSet::from_iter(1..=max_cred_num);

        CryptoIssuer::update_revocation_registry(
            &mut rev_reg,
            max_cred_num,
            issued,
            BTreeSet::new(),
            &tails_reader,
        )?;
        bitvec![0; max_cred_num as usize ]
    } else {
        bitvec![1; max_cred_num as usize ]
    };

    RevocationStatusList::new(
        Some(rev_reg_def_id.to_string().as_str()),
        issuer_id,
        list,
        Some(rev_reg),
        timestamp,
    )
}

/// Update the timestamp only without changing any actual state
pub fn update_revocation_status_list_timestamp_only(
    timestamp: u64,
    current_list: &RevocationStatusList,
) -> RevocationStatusList {
    let mut list = current_list.clone();
    // this does not error as only timestamp is updated
    list.update(None, None, None, Some(timestamp)).unwrap();
    list
}
/// Update Revocation Status List
/// - if `timestamp` is `None`: the timestamp is not updated
pub fn update_revocation_status_list(
    timestamp: Option<u64>,
    issued: Option<BTreeSet<u32>>,
    revoked: Option<BTreeSet<u32>>,
    rev_reg_def: &RevocationRegistryDefinition,
    current_list: &RevocationStatusList,
) -> Result<RevocationStatusList> {
    let mut new_list = current_list.clone();
    let issued = issued.map(|i_list| {
        BTreeSet::from_iter(
            i_list
                .into_iter()
                .filter(|&i| current_list.get(i as usize).unwrap_or(false)),
        )
    });

    let revoked = revoked.map(|r_list| {
        BTreeSet::from_iter(
            r_list
                .into_iter()
                .filter(|&i| !current_list.get(i as usize).unwrap_or(true)),
        )
    });

    let rev_reg_opt: Option<ursa::cl::RevocationRegistry> = current_list.into();
    let mut rev_reg = rev_reg_opt.ok_or_else(|| {
        Error::from_msg(
            ErrorKind::Unexpected,
            "Require Accumulator Value to update Rev Status List",
        )
    })?;
    let tails_reader = TailsFileReader::new_tails_reader(&rev_reg_def.value.tails_location);
    let max_cred_num = rev_reg_def.value.max_cred_num;

    CryptoIssuer::update_revocation_registry(
        &mut rev_reg,
        max_cred_num,
        issued.clone().unwrap_or_default(),
        revoked.clone().unwrap_or_default(),
        &tails_reader,
    )?;
    new_list.update(Some(rev_reg), issued, revoked, timestamp)?;

    Ok(new_list)
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
    let rand_str = String::from_utf8(thread_rng().sample_iter(&Alphanumeric).take(22).collect())
        .map_err(|_| err_msg!("Unable to instantiate random string for prover did"))?;
    let prover_did = cred_request.prover_did.as_ref().unwrap_or(&rand_str);

    let (credential_signature, signature_correctness_proof, rev_reg, witness) =
        match (revocation_config, rev_status_list) {
            (Some(revocation_config), Some(rev_status_list)) => {
                let rev_reg_def = &revocation_config.reg_def.value;
                let rev_reg: Option<ursa::cl::RevocationRegistry> = rev_status_list.into();
                let mut rev_reg = rev_reg.ok_or_else(|| {
                    err_msg!(
                        Unexpected,
                        "RevocationStatusList should have accumulator value"
                    )
                })?;

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

                let (credential_signature, signature_correctness_proof, delta) =
                    CryptoIssuer::sign_credential_with_revoc(
                        prover_did,
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
                        &revocation_config.tails_reader,
                    )?;

                let witness = {
                    // `delta` is None if `issuance_type == issuance_by_default`
                    // So in this case the delta goes from none to the new one,
                    // which is all issued (by default) and non is revoked
                    //
                    // Note: delta is actually never used but we keep it so it is inline with
                    // ursa::cl::Witness type
                    let rev_reg_delta = delta.unwrap_or_else(|| {
                        let empty = HashSet::new();
                        CryptoRevocationRegistryDelta::from_parts(None, &rev_reg, &empty, &empty)
                    });
                    Witness::new(
                        revocation_config.registry_idx,
                        rev_reg_def.max_cred_num,
                        issuance_by_default,
                        &rev_reg_delta,
                        &revocation_config.tails_reader,
                    )?
                };
                (
                    credential_signature,
                    signature_correctness_proof,
                    Some(rev_reg),
                    Some(witness),
                )
            }
            _ => {
                let (signature, correctness_proof) = CryptoIssuer::sign_credential(
                    prover_did,
                    &cred_request.blinded_ms,
                    &cred_request.blinded_ms_correctness_proof,
                    cred_offer.nonce.as_native(),
                    cred_request.nonce.as_native(),
                    &credential_values,
                    &cred_public_key,
                    &cred_def_private.value,
                )?;
                (signature, correctness_proof, None, None)
            }
        };

    let credential = Credential {
        schema_id: cred_offer.schema_id.to_owned(),
        cred_def_id: cred_offer.cred_def_id.to_owned(),
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
    use crate::tails::TailsFileWriter;

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
