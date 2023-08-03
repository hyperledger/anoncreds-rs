use super::storage::{IssuerWallet, Ledger, ProverWallet, StoredCredDef, StoredRevDef};
use std::{
    collections::{BTreeSet, HashMap},
    fs::create_dir,
};

use anoncreds::{
    data_types::{
        cred_def::{CredentialDefinition, CredentialDefinitionId},
        cred_offer::CredentialOffer,
        credential::Credential,
        presentation::Presentation,
        rev_reg::RevocationRegistryId,
        rev_reg_def::RevocationRegistryDefinitionId,
        schema::{Schema, SchemaId},
    },
    issuer, prover,
    tails::TailsFileWriter,
    types::{
        CredentialDefinitionConfig, CredentialRequest, CredentialRevocationConfig,
        MakeCredentialValues, PresentCredentials, PresentationRequest, RegistryType, SignatureType,
    },
    verifier,
};

#[allow(unused)]
pub struct TestError(String);

// {cred_def_id: {
//       schema_id, credential_values, support_revocation, rev_reg_id, rev_idx
// }}
#[allow(unused)]
pub type IssuerValues<'a> =
    HashMap<&'a str, (&'a str, HashMap<&'a str, &'a str>, bool, &'a str, u32)>;

// {cred_def_id: {
//       attribute_per_credential, predicate_for_credential }}
#[allow(unused)]
pub type ProverValues<'a> = HashMap<&'a str, (Vec<&'a str>, Vec<&'a str>)>;

// { rev_reg_def_id: {req_timestamp, override_timestamp} }
#[allow(unused)]
pub type Override<'a> = HashMap<&'a RevocationRegistryDefinitionId, HashMap<u64, u64>>;

#[derive(Debug)]
pub struct Mock<'a> {
    pub issuer_wallets: HashMap<&'a str, IssuerWallet<'a>>,
    pub prover_wallets: HashMap<&'a str, ProverWallet<'a>>,
    pub ledger: Ledger<'a>,
    pub tails_path: &'a str,
    pub max_cred_num: u32,
}

impl<'a> Mock<'a> {
    #[allow(unused)]
    pub fn new(
        issuer_ids: &[&'a str],
        prover_ids: &[&'a str],
        tails_path: &'a str,
        max_cred_num: u32,
    ) -> Self {
        let mut iws = HashMap::new();
        let mut pws = HashMap::new();
        for i in issuer_ids {
            iws.insert(*i, IssuerWallet::default());
        }
        for i in prover_ids {
            pws.insert(*i, ProverWallet::default());
        }

        Self {
            issuer_wallets: iws,
            prover_wallets: pws,
            ledger: Ledger::default(),
            tails_path,
            max_cred_num,
        }
    }

    #[allow(unused)]
    pub fn verifer_verifies_presentations_for_requests(
        &self,
        presentations: &[Presentation],
        reqs: &[PresentationRequest],
        overrides: &[Option<&Override>],
    ) -> Vec<Result<bool, TestError>> {
        let mut results = vec![];
        let schemas: HashMap<&SchemaId, &Schema> = HashMap::from_iter(self.ledger.schemas.iter());
        let cred_defs: HashMap<&CredentialDefinitionId, &CredentialDefinition> =
            HashMap::from_iter(self.ledger.cred_defs.iter());
        let mut rev_status_lists = vec![];

        self.ledger
            .revcation_list
            .iter()
            .for_each(|(_, v)| v.iter().for_each(|(_, list)| rev_status_lists.push(list)));
        let rev_reg_def_map = HashMap::from_iter(self.ledger.rev_reg_defs.iter());

        for (i, presentation) in presentations.iter().enumerate() {
            let valid = verifier::verify_presentation(
                &presentation,
                &reqs[i],
                &schemas,
                &cred_defs,
                Some(&rev_reg_def_map),
                Some(rev_status_lists.clone()),
                overrides[i],
            )
            .map_err(|e| TestError(e.to_string()));
            results.push(valid);
        }
        results
    }

    // This creates cred defs based on the schemas, assumes 1 schema 1 cred def
    // issuer wallet holds all data relating to cred def and rev def
    // prover wallet contains the cred offers from the credentials
    // ledger holds the rev reg def / rev reg info
    #[allow(unused)]
    pub fn issuer_setup(
        &mut self,
        issuer_id: &'static str,
        prover_id: &'static str,
        values: &'a IssuerValues,
        time_now: u64,
        issuance_by_default: bool,
    ) {
        for (cred_def_id, (schema_id, _, support_revocation, rev_reg_id, _)) in values.iter() {
            let (cred_def_pub, cred_def_priv, cred_def_correctness) =
                issuer::create_credential_definition(
                    schema_id.to_string(),
                    &self.ledger.schemas[&SchemaId::new_unchecked(*schema_id)],
                    issuer_id,
                    "tag",
                    SignatureType::CL,
                    CredentialDefinitionConfig {
                        support_revocation: *support_revocation,
                    },
                )
                .expect("Error creating gvt credential definition");

            if *support_revocation {
                // This will create a tails file locally in the .tmp dir
                create_dir(self.tails_path)
                    .or_else(|e| -> Result<(), std::io::Error> {
                        println!(
                            "Tail file path creation error but test can still proceed {}",
                            e
                        );
                        Ok(())
                    })
                    .unwrap();

                let mut tf = TailsFileWriter::new(Some(self.tails_path.to_owned()));
                let (rev_reg_def_pub, rev_reg_def_priv) = issuer::create_revocation_registry_def(
                    &cred_def_pub,
                    *cred_def_id,
                    issuer_id,
                    "some_tag",
                    RegistryType::CL_ACCUM,
                    self.max_cred_num,
                    &mut tf,
                )
                .unwrap();

                let iw_mut = self.issuer_wallets.get_mut(issuer_id).unwrap();
                iw_mut.rev_defs.insert(
                    &rev_reg_id,
                    StoredRevDef {
                        public: rev_reg_def_pub.clone(),
                        private: rev_reg_def_priv,
                    },
                );

                let rev_reg_def_priv = match iw_mut.rev_defs.get(rev_reg_id) {
                    Some(rev_def) => &rev_def.private,
                    None => panic!("Revocation definition not found for ID {}", rev_reg_id),
                };

                let revocation_status_list = issuer::create_revocation_status_list(
                    &cred_def_pub,
                    *rev_reg_id,
                    &rev_reg_def_pub,
                    rev_reg_def_priv,
                    issuer_id,
                    issuance_by_default,
                    Some(time_now),
                )
                .unwrap();

                self.ledger.revcation_list.insert(
                    rev_reg_id,
                    HashMap::from([(time_now, revocation_status_list)]),
                );

                self.ledger.rev_reg_defs.insert(
                    RevocationRegistryDefinitionId::new_unchecked(*rev_reg_id),
                    rev_reg_def_pub,
                );
            }

            // Issuer creates a Credential Offer
            let cred_offer = issuer::create_credential_offer(
                schema_id.to_string(),
                *cred_def_id,
                &cred_def_correctness,
            )
            .expect("Error creating credential offer");

            // Update wallets and ledger
            self.prover_wallets
                .get_mut(prover_id)
                .unwrap()
                .cred_offers
                .insert(*cred_def_id, cred_offer);

            self.issuer_wallets
                .get_mut(issuer_id)
                .unwrap()
                .cred_defs
                .insert(
                    *cred_def_id,
                    StoredCredDef {
                        private: cred_def_priv,
                        key_proof: cred_def_correctness,
                    },
                );
            self.ledger.cred_defs.insert(
                CredentialDefinitionId::new_unchecked(*cred_def_id),
                cred_def_pub,
            );
        }
    }

    #[allow(unused)]
    fn issuer_create_credential(
        &self,
        issuer_wallet: &IssuerWallet,
        ledger: &Ledger,
        cred_request: &CredentialRequest,
        offer: &CredentialOffer,
        rev_reg_id: &str,
        cred_def_id: &str,
        values: &HashMap<&str, &str>,
        prev_rev_reg_time: u64,
        rev_idx: u32,
    ) -> Credential {
        let schema = self.ledger.schemas.get(&offer.schema_id).unwrap();
        let revocation_list = self
            .ledger
            .revcation_list
            .get(rev_reg_id)
            .map(|h| h.get(&prev_rev_reg_time))
            .flatten();
        let mut cred_values = MakeCredentialValues::default();
        let names: Vec<String> = schema.attr_names.clone().0.into_iter().collect();
        for (i, v) in names.iter().enumerate() {
            if let Some(value) = values.get(&v.as_str()) {
                cred_values
                    .add_raw(names[i].clone(), value.to_string())
                    .expect("Error encoding attribute");
            } else {
                panic!(
                    "No credential value given for attribute name: {} in {:?}",
                    v, values
                );
            }
        }

        let (rev_config, rev_id) = match issuer_wallet.rev_defs.get(rev_reg_id) {
            Some(stored_rev_def) => (
                Some(CredentialRevocationConfig {
                    reg_def: &stored_rev_def.public,
                    reg_def_private: &stored_rev_def.private,
                    registry_idx: rev_idx,
                }),
                Some(RevocationRegistryId::new_unchecked(rev_reg_id)),
            ),
            None => (None, None),
        };

        let issue_cred = issuer::create_credential(
            &ledger
                .cred_defs
                .get(&CredentialDefinitionId::new_unchecked(cred_def_id))
                .unwrap(),
            &issuer_wallet.cred_defs[cred_def_id].private,
            offer,
            cred_request,
            cred_values.into(),
            rev_id,
            revocation_list,
            rev_config,
        )
        .expect("Error creating credential");

        issue_cred
    }

    // prover requests and gets credential stored in their wallets
    // This updates ledger on revocation reg also
    #[allow(unused)]
    pub fn issuer_create_credential_and_store_in_prover_wallet(
        &mut self,
        issuer_id: &'static str,
        prover_id: &'static str,
        values: &'a IssuerValues,
        time_prev_rev_reg: u64,
        time_new_rev_reg: u64,
    ) {
        for (cred_def_id, (_, cred_values, _, rev_reg_id, rev_idx)) in values.iter() {
            let offer = &self.prover_wallets[prover_id].cred_offers[cred_def_id];
            let cred_def = self
                .ledger
                .cred_defs
                .get(&CredentialDefinitionId::new_unchecked(cred_def_id.clone()))
                .unwrap();
            // Prover creates a Credential Request
            let cred_req_data = prover::create_credential_request(
                Some("entropy"),
                None,
                &cred_def,
                &self.prover_wallets[prover_id].link_secret,
                "default",
                &offer,
            )
            .expect("Error creating credential request");

            // Issuer creates a credential
            let mut recv_cred = self.issuer_create_credential(
                &self.issuer_wallets[issuer_id],
                &self.ledger,
                &cred_req_data.0,
                &offer,
                *rev_reg_id,
                cred_def_id,
                cred_values,
                time_prev_rev_reg,
                *rev_idx,
            );

            let rev_def = self.issuer_wallets[issuer_id]
                .rev_defs
                .get(*rev_reg_id)
                .map(|e| &e.public);

            let rev_def_priv = self.issuer_wallets[issuer_id]
                .rev_defs
                .get(*rev_reg_id)
                .map(|e| &e.private);

            // prover processes it
            prover::process_credential(
                &mut recv_cred,
                &cred_req_data.1,
                &self.prover_wallets[prover_id].link_secret,
                &cred_def,
                rev_def,
            )
            .expect("Error processing credential");

            // Update prover wallets and ledger with new revocation status list
            let pw = self.prover_wallets.get_mut(prover_id).unwrap();
            pw.cred_reqs.push(cred_req_data);
            pw.credentials.push(recv_cred);

            if let Some(rev_def) = rev_def {
                let list = self
                    .ledger
                    .revcation_list
                    .get(*rev_reg_id)
                    .unwrap()
                    .get(&time_prev_rev_reg)
                    .unwrap();

                let updated_list = issuer::update_revocation_status_list(
                    cred_def,
                    rev_def,
                    rev_def_priv.unwrap(),
                    list,
                    Some(BTreeSet::from([*rev_idx])),
                    None,
                    Some(time_new_rev_reg),
                )
                .unwrap();

                let map = self.ledger.revcation_list.get_mut(&*rev_reg_id).unwrap();
                map.insert(time_new_rev_reg, updated_list);
            }
        }
    }

    #[allow(unused)]
    pub fn prover_creates_revocation_states(
        &mut self,
        prover_id: &'static str,
        time_to_update_to: u64,
    ) {
        let mut rev_states = self.prover_wallets[prover_id].rev_states.clone();
        for cred in &self.prover_wallets[prover_id].credentials {
            if let Some(id) = &cred.rev_reg_id {
                let rev_status_list = self
                    .ledger
                    .revcation_list
                    .get(id.to_string().as_str())
                    .unwrap()
                    .get(&time_to_update_to)
                    .unwrap();

                let state = prover::create_revocation_state_with_witness(
                    cred.witness.as_ref().unwrap().clone(),
                    rev_status_list,
                    time_to_update_to,
                )
                .unwrap();

                // this overwrites the rev_state as there should only just be one that works
                rev_states.insert(id.clone(), (Some(state), Some(time_to_update_to)));
            };
        }
        self.prover_wallets.get_mut(prover_id).unwrap().rev_states = rev_states;
    }

    #[allow(unused)]
    pub fn prover_creates_presentation(
        &self,
        prover_id: &'static str,
        prover_values: ProverValues,
        self_attested: HashMap<String, String>,
        req: &PresentationRequest,
    ) -> Presentation {
        let schemas: HashMap<&SchemaId, &Schema> = HashMap::from_iter(self.ledger.schemas.iter());
        let cred_defs: HashMap<&CredentialDefinitionId, &CredentialDefinition> =
            HashMap::from_iter(self.ledger.cred_defs.iter());

        let mut present = PresentCredentials::default();
        for cred in self.prover_wallets[prover_id].credentials.iter() {
            let values = prover_values
                .get(cred.cred_def_id.to_string().as_str())
                .unwrap();
            {
                let (rev_state, timestamp) = if let Some(id) = &cred.rev_reg_id {
                    self.prover_wallets[prover_id].rev_states.get(&id).unwrap()
                } else {
                    &(None, None)
                };

                let mut cred1 = present.add_credential(cred, *timestamp, rev_state.as_ref());
                for a in &values.0 {
                    cred1.add_requested_attribute(a.clone(), true);
                }
                for p in &values.1 {
                    cred1.add_requested_predicate(p.clone());
                }
            }
        }

        let presentation = prover::create_presentation(
            req,
            present,
            Some(self_attested.clone()),
            &self.prover_wallets[prover_id].link_secret,
            &schemas,
            &cred_defs,
        )
        .expect("Error creating presentation");

        presentation
    }
}
