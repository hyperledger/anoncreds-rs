use ursa::{
    bn::BigNumber,
    cl::{
        issuer, verifier, CredentialSchema, CredentialValues as CryptoCredentialValues,
        MasterSecret as CryptoMasterSecret, NonCredentialSchema, SubProofRequest,
    },
};

use crate::error::Result;

use indy_data_types::anoncreds::{
    credential::AttributeValues,
    nonce::Nonce,
    pres_request::{AttributeInfo, NonRevocedInterval, PredicateInfo},
};
use indy_utils::hash::SHA256;

use std::collections::{HashMap, HashSet};

pub fn attr_common_view(attr: &str) -> String {
    attr.replace(" ", "").to_lowercase()
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
    non_credential_schema_builder.add_attr("master_secret")?;
    let res = non_credential_schema_builder.finalize()?;

    trace!("build_non_credential_schema <<< res: {:?}", res);
    Ok(res)
}

pub fn build_credential_values(
    credential_values: &HashMap<String, AttributeValues>,
    master_secret: Option<&CryptoMasterSecret>,
) -> Result<CryptoCredentialValues> {
    trace!(
        "build_credential_values >>> credential_values: {:?}",
        credential_values
    );

    let mut credential_values_builder = issuer::Issuer::new_credential_values_builder()?;
    for (attr, values) in credential_values {
        credential_values_builder.add_dec_known(&attr_common_view(attr), &values.encoded)?;
    }
    if let Some(ms) = master_secret {
        credential_values_builder.add_value_hidden("master_secret", &ms.value()?)?;
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

pub fn get_non_revoc_interval(
    global_interval: &Option<NonRevocedInterval>,
    local_interval: &Option<NonRevocedInterval>,
) -> Option<NonRevocedInterval> {
    trace!(
        "get_non_revoc_interval >>> global_interval: {:?}, local_interval: {:?}",
        global_interval,
        local_interval
    );

    let interval = local_interval
        .clone()
        .or_else(|| global_interval.clone().or(None));

    trace!("get_non_revoc_interval <<< interval: {:?}", interval);

    interval
}

pub fn new_nonce() -> Result<Nonce> {
    Nonce::new().map_err(err_map!(Unexpected))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn _interval() -> NonRevocedInterval {
        NonRevocedInterval {
            from: None,
            to: Some(123),
        }
    }

    #[test]
    fn get_non_revoc_interval_for_global() {
        let res = get_non_revoc_interval(&Some(_interval()), &None).unwrap();
        assert_eq!(_interval(), res);
    }

    #[test]
    fn get_non_revoc_interval_for_local() {
        let res = get_non_revoc_interval(&None, &Some(_interval())).unwrap();
        assert_eq!(_interval(), res);
    }

    #[test]
    fn get_non_revoc_interval_for_none() {
        let res = get_non_revoc_interval(&None, &None);
        assert_eq!(None, res);
    }
}
