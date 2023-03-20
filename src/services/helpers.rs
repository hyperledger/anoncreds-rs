use std::collections::{HashMap, HashSet};

use crate::data_types::{
    credential::AttributeValues,
    nonce::Nonce,
    pres_request::{AttributeInfo, NonRevokedInterval, PredicateInfo, PresentationRequestPayload},
    presentation::RequestedProof,
};
use crate::utils::hash::SHA256;

use crate::error::Result;
use crate::ursa::{
    bn::BigNumber,
    cl::{
        issuer, verifier, CredentialSchema, CredentialValues as CryptoCredentialValues,
        MasterSecret as CryptoMasterSecret, NonCredentialSchema, SubProofRequest,
    },
};

pub fn attr_common_view(attr: &str) -> String {
    attr.replace(' ', "").to_lowercase()
}

pub fn build_credential_schema(attrs: &HashSet<String>) -> Result<CredentialSchema> {
    trace!("build_credential_schema >>> attrs: {:?}", attrs);

    let mut credential_schema_builder = issuer::Issuer::new_credential_schema_builder()?;
    for attr in attrs {
        credential_schema_builder.add_attr(&attr_common_view(attr))?;
    }

    let res = credential_schema_builder.finalize()?;

    trace!("build_credential_schema <<< res: {:?}", res);

    Ok(res)
}

pub fn build_non_credential_schema() -> Result<NonCredentialSchema> {
    trace!("build_non_credential_schema");

    let mut non_credential_schema_builder = issuer::Issuer::new_non_credential_schema_builder()?;
    non_credential_schema_builder.add_attr("link_secret")?;
    let res = non_credential_schema_builder.finalize()?;

    trace!("build_non_credential_schema <<< res: {:?}", res);
    Ok(res)
}

pub fn build_credential_values(
    credential_values: &HashMap<String, AttributeValues>,
    link_secret: Option<&CryptoMasterSecret>,
) -> Result<CryptoCredentialValues> {
    trace!(
        "build_credential_values >>> credential_values: {:?}",
        credential_values
    );

    let mut credential_values_builder = issuer::Issuer::new_credential_values_builder()?;
    for (attr, values) in credential_values {
        credential_values_builder.add_dec_known(&attr_common_view(attr), &values.encoded)?;
    }
    if let Some(ms) = link_secret {
        credential_values_builder.add_value_hidden("link_secret", &ms.value()?)?;
    }

    let res = credential_values_builder.finalize()?;

    trace!("build_credential_values <<< res: {:?}", res);

    Ok(res)
}

pub fn encode_credential_attribute(raw_value: &str) -> Result<String> {
    if let Ok(val) = raw_value.parse::<i32>() {
        Ok(val.to_string())
    } else {
        let digest = SHA256::digest(raw_value.as_bytes());
        #[cfg(target_endian = "big")]
        let digest = {
            let mut d = digest;
            d.reverse();
            d
        };
        Ok(BigNumber::from_bytes(&digest)?.to_dec()?)
    }
}

pub fn build_sub_proof_request(
    attrs_for_credential: &[AttributeInfo],
    predicates_for_credential: &[PredicateInfo],
) -> Result<SubProofRequest> {
    trace!(
        "build_sub_proof_request >>> attrs_for_credential: {:?}, predicates_for_credential: {:?}",
        attrs_for_credential,
        predicates_for_credential
    );

    let mut sub_proof_request_builder = verifier::Verifier::new_sub_proof_request_builder()?;

    for attr in attrs_for_credential {
        let names = if let Some(name) = &attr.name {
            vec![name.clone()]
        } else if let Some(names) = &attr.names {
            names.to_owned()
        } else {
            error!(
                r#"Attr for credential restriction should contain "name" or "names" param. Current attr: {:?}"#,
                attr
            );
            return Err(err_msg!(
                r#"Attr for credential restriction should contain "name" or "names" param."#,
            ));
        };

        for name in names {
            sub_proof_request_builder.add_revealed_attr(&attr_common_view(&name))?
        }
    }

    for predicate in predicates_for_credential {
        let p_type = format!("{}", predicate.p_type);

        sub_proof_request_builder.add_predicate(
            &attr_common_view(&predicate.name),
            &p_type,
            predicate.p_value,
        )?;
    }

    let res = sub_proof_request_builder.finalize()?;

    trace!("build_sub_proof_request <<< res: {:?}", res);

    Ok(res)
}

pub fn new_nonce() -> Result<Nonce> {
    Nonce::new().map_err(err_map!(Unexpected))
}

pub fn get_revealed_attributes_for_credential(
    sub_proof_index: usize,
    requested_proof: &RequestedProof,
    pres_req: &PresentationRequestPayload,
) -> Result<(Vec<AttributeInfo>, Option<NonRevokedInterval>)> {
    trace!("_get_revealed_attributes_for_credential >>> sub_proof_index: {:?}, requested_credentials: {:?}, pres_req: {:?}",
           sub_proof_index, requested_proof, pres_req);
    let mut non_revoked_interval: Option<NonRevokedInterval> = None;
    let mut revealed_attrs_for_credential = requested_proof
        .revealed_attrs
        .iter()
        .filter(|&(attr_referent, revealed_attr_info)| {
            sub_proof_index == revealed_attr_info.sub_proof_index as usize
                && pres_req.requested_attributes.contains_key(attr_referent)
        })
        .map(|(attr_referent, _)| {
            let info = pres_req.requested_attributes[attr_referent].clone();
            if let Some(int) = &info.non_revoked {
                match non_revoked_interval.as_mut() {
                    Some(ni) => {
                        ni.compare_and_set(int);
                    }
                    None => non_revoked_interval = Some(int.clone()),
                }
            };

            info
        })
        .collect::<Vec<AttributeInfo>>();

    revealed_attrs_for_credential.append(
        &mut requested_proof
            .revealed_attr_groups
            .iter()
            .filter(|&(attr_referent, revealed_attr_info)| {
                sub_proof_index == revealed_attr_info.sub_proof_index as usize
                    && pres_req.requested_attributes.contains_key(attr_referent)
            })
            .map(|(attr_referent, _)| {
                let info = pres_req.requested_attributes[attr_referent].clone();
                if let Some(int) = &info.non_revoked {
                    match non_revoked_interval.as_mut() {
                        Some(ni) => {
                            ni.compare_and_set(int);
                        }
                        None => non_revoked_interval = Some(NonRevokedInterval::default()),
                    }
                };
                info
            })
            .collect::<Vec<AttributeInfo>>(),
    );

    trace!(
        "_get_revealed_attributes_for_credential <<< revealed_attrs_for_credential: {:?}",
        revealed_attrs_for_credential
    );

    Ok((revealed_attrs_for_credential, non_revoked_interval))
}

pub fn get_predicates_for_credential(
    sub_proof_index: usize,
    requested_proof: &RequestedProof,
    pres_req: &PresentationRequestPayload,
) -> Result<(Vec<PredicateInfo>, Option<NonRevokedInterval>)> {
    trace!("_get_predicates_for_credential >>> sub_proof_index: {:?}, requested_credentials: {:?}, pres_req: {:?}",
           sub_proof_index, requested_proof, pres_req);

    let mut non_revoked_interval: Option<NonRevokedInterval> = None;
    let predicates_for_credential = requested_proof
        .predicates
        .iter()
        .filter(|&(predicate_referent, requested_referent)| {
            sub_proof_index == requested_referent.sub_proof_index as usize
                && pres_req
                    .requested_predicates
                    .contains_key(predicate_referent)
        })
        .map(|(predicate_referent, _)| {
            let info = pres_req.requested_predicates[predicate_referent].clone();
            if let Some(int) = &info.non_revoked {
                match non_revoked_interval.as_mut() {
                    Some(ni) => {
                        ni.compare_and_set(int);
                    }
                    None => non_revoked_interval = Some(int.clone()),
                }
            };

            info
        })
        .collect::<Vec<PredicateInfo>>();

    trace!(
        "_get_predicates_for_credential <<< predicates_for_credential: {:?}",
        predicates_for_credential
    );

    Ok((predicates_for_credential, non_revoked_interval))
}
