use super::storage::{IssuerWallet, Ledger, ProverWallet, StoredCredDef, StoredRevDef};
use serde_json::json;
use std::{
    collections::{BTreeSet, HashMap},
    fs::create_dir,
};

use crate::utils::{fixtures, VerifierWallet};
use anoncreds::data_types::nonce::Nonce;
use anoncreds::data_types::w3c::credential::{
    CredentialAttributeValue, CredentialAttributes, W3CCredential,
};
use anoncreds::data_types::w3c::presentation::W3CPresentation;
use anoncreds::types::{
    CredentialRequestMetadata, CredentialRevocationState, CredentialValues,
    RevocationRegistryDefinition, RevocationStatusList,
};
use anoncreds::w3c::credential_conversion::{credential_from_w3c, credential_to_w3c};
use anoncreds::w3c::types::MakeCredentialAttributes;
use anoncreds::{
    data_types::{
        cred_def::{CredentialDefinition, CredentialDefinitionId},
        cred_offer::CredentialOffer,
        credential::Credential,
        presentation::Presentation,
        rev_reg_def::RevocationRegistryDefinitionId,
        schema::{Schema, SchemaId},
    },
    issuer, prover,
    tails::TailsFileWriter,
    types::{
        CredentialDefinitionConfig, CredentialRequest, CredentialRevocationConfig,
        MakeCredentialValues, PresentCredentials, PresentationRequest, RegistryType, SignatureType,
    },
    verifier, w3c,
};

#[derive(Debug)]
pub struct TestError(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialFormat {
    Legacy,
    W3C,
}

#[derive(Debug)]
pub enum Credentials {
    Legacy(Credential),
    W3C(W3CCredential),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresentationFormat {
    Legacy,
    W3C,
}

#[derive(Debug)]
pub enum Presentations {
    Legacy(Presentation),
    W3C(W3CPresentation),
}

impl Credentials {
    pub fn legacy(&self) -> &Credential {
        match self {
            Credentials::Legacy(credential) => credential,
            _ => panic!("Legacy credential expected"),
        }
    }

    pub fn w3c(&self) -> &W3CCredential {
        match self {
            Credentials::W3C(credential) => credential,
            _ => panic!("W3C credential expected"),
        }
    }
}

impl Presentations {
    pub fn legacy(&self) -> &Presentation {
        match self {
            Presentations::Legacy(presentation) => presentation,
            _ => panic!("Legacy presentation expected"),
        }
    }

    pub fn w3c(&self) -> &W3CPresentation {
        match self {
            Presentations::W3C(presentation) => presentation,
            _ => panic!("W3C presentation expected"),
        }
    }
}

pub type IssuerValues<'a> =
    HashMap<&'a str, (&'a str, HashMap<&'a str, &'a str>, bool, &'a str, u32)>;

pub type Override<'a> = HashMap<RevocationRegistryDefinitionId, HashMap<u64, u64>>;

#[derive(Debug)]
pub struct Mock<'a> {
    pub issuer_wallets: HashMap<&'a str, IssuerWallet>,
    pub prover_wallets: HashMap<&'a str, ProverWallet<'a>>,
    pub verifier_wallets: HashMap<&'a str, VerifierWallet>,
    pub ledger: Ledger<'a>,
    pub tails_path: &'a str,
    pub max_cred_num: u32,
}

impl<'a> Mock<'a> {
    pub fn new(
        issuer_ids: &[&'a str],
        prover_ids: &[&'a str],
        verifier_ids: &[&'a str],
        tails_path: &'a str,
        max_cred_num: u32,
    ) -> Self {
        let mut iws = HashMap::new();
        let mut pws = HashMap::new();
        let mut vws = HashMap::new();
        for i in issuer_ids {
            iws.insert(*i, IssuerWallet::default());
        }
        for i in prover_ids {
            pws.insert(*i, ProverWallet::default());
        }
        for i in verifier_ids {
            vws.insert(*i, VerifierWallet::default());
        }

        Self {
            issuer_wallets: iws,
            prover_wallets: pws,
            verifier_wallets: vws,
            ledger: Ledger::default(),
            tails_path,
            max_cred_num,
        }
    }

    fn prepare_presentation_verification_data(
        &self,
    ) -> (
        HashMap<SchemaId, Schema>,
        HashMap<CredentialDefinitionId, CredentialDefinition>,
        Vec<RevocationStatusList>,
        HashMap<RevocationRegistryDefinitionId, RevocationRegistryDefinition>,
    ) {
        let schemas: HashMap<SchemaId, Schema> = HashMap::from_iter(
            self.ledger
                .schemas
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
        let cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition> = HashMap::from_iter(
            self.ledger
                .cred_defs
                .iter()
                .map(|(k, v)| v.try_clone().map(|v| (k.clone(), v)))
                .collect::<Result<HashMap<_, _>, anoncreds::Error>>()
                .unwrap(),
        );
        let mut rev_status_lists = vec![];

        self.ledger.revocation_list.iter().for_each(|(_, v)| {
            v.iter()
                .for_each(|(_, list)| rev_status_lists.push(list.clone()))
        });
        let rev_reg_def_map = HashMap::from_iter(
            self.ledger
                .rev_reg_defs
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
        (schemas, cred_defs, rev_status_lists, rev_reg_def_map)
    }

    pub fn verifer_verifies_presentations_for_requests(
        &self,
        verifier_id: &str,
        presentations: &[Presentations],
        reqs: &[PresentationRequest],
        overrides: &[Option<&Override>],
    ) -> Vec<Result<bool, TestError>> {
        let verifier_wallets = &self.verifier_wallets[verifier_id];
        let mut results = vec![];
        let (schemas, cred_defs, rev_status_lists, rev_reg_def_map) =
            self.prepare_presentation_verification_data();

        for (i, presentation) in presentations.iter().enumerate() {
            let valid = verifier_wallets.verify_presentation(
                presentation,
                &reqs[i],
                &schemas,
                &cred_defs,
                Some(&rev_reg_def_map),
                Some(rev_status_lists.clone()),
                overrides[i],
            );
            results.push(valid);
        }
        results
    }

    // This creates cred defs based on the schemas, assumes 1 schema 1 cred def
    // issuer wallet holds all data relating to cred def and rev def
    // prover wallet contains the cred offers from the credentials
    // ledger holds the rev reg def / rev reg info
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
                    (*schema_id).try_into().unwrap(),
                    &self.ledger.schemas[&SchemaId::new_unchecked(*schema_id)],
                    issuer_id.try_into().unwrap(),
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
                    (*cred_def_id).try_into().unwrap(),
                    "some_tag",
                    RegistryType::CL_ACCUM,
                    self.max_cred_num,
                    &mut tf,
                )
                .unwrap();

                let iw_mut = self.issuer_wallets.get_mut(issuer_id).unwrap();
                iw_mut.rev_defs.insert(
                    rev_reg_id.to_string(),
                    StoredRevDef {
                        public: rev_reg_def_pub.clone(),
                        private: rev_reg_def_priv,
                    },
                );

                let rev_reg_def_priv = match iw_mut.rev_defs.get(&rev_reg_id.to_string()) {
                    Some(rev_def) => &rev_def.private,
                    None => panic!("Revocation definition not found for ID {}", rev_reg_id),
                };

                let revocation_status_list = issuer::create_revocation_status_list(
                    &cred_def_pub,
                    (*rev_reg_id).try_into().unwrap(),
                    &rev_reg_def_pub,
                    rev_reg_def_priv,
                    issuance_by_default,
                    Some(time_now),
                )
                .unwrap();

                self.ledger.revocation_list.insert(
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
                schema_id.to_string().try_into().unwrap(),
                (*cred_def_id).try_into().unwrap(),
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
                    cred_def_id.to_string(),
                    StoredCredDef {
                        public: cred_def_pub.try_clone().unwrap(),
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

    fn get_schema(&self, schema_id: &SchemaId) -> &Schema {
        self.ledger.schemas.get(schema_id).unwrap()
    }

    fn get_cred_def(&self, cred_def_id: &CredentialDefinitionId) -> &CredentialDefinition {
        self.ledger.cred_defs.get(cred_def_id).unwrap()
    }

    fn get_rev_config(
        &self,
        issuer_wallet: &'a IssuerWallet,
        rev_reg_id: &str,
        rev_idx: u32,
        prev_rev_reg_time: u64,
    ) -> Option<CredentialRevocationConfig> {
        let revocation_list = self
            .ledger
            .revocation_list
            .get(rev_reg_id)
            .and_then(|h| h.get(&prev_rev_reg_time));

        issuer_wallet
            .rev_defs
            .get(rev_reg_id)
            .map(|stored_rev_def| {
                Result::<_, TestError>::Ok(CredentialRevocationConfig {
                    reg_def: &stored_rev_def.public,
                    reg_def_private: &stored_rev_def.private,
                    registry_idx: rev_idx,
                    status_list: revocation_list
                        .ok_or_else(|| TestError("Missing status list".to_string()))?,
                })
            })
            .transpose()
            .expect("Error creating revocation config")
    }

    fn issuer_create_credential(
        &self,
        issuer_wallet: &IssuerWallet,
        ledger: &Ledger,
        credential_format: &CredentialFormat,
        cred_request: &CredentialRequest,
        offer: &CredentialOffer,
        rev_reg_id: &str,
        cred_def_id: &str,
        values: &HashMap<&str, &str>,
        prev_rev_reg_time: u64,
        rev_idx: u32,
    ) -> Credentials {
        let schema = self.get_schema(&offer.schema_id);
        let cred_def = self.get_cred_def(&offer.cred_def_id);
        let rev_config = self.get_rev_config(issuer_wallet, rev_reg_id, rev_idx, prev_rev_reg_time);

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

        let issue_cred = issuer_wallet.create_credential(
            credential_format,
            cred_def_id,
            offer,
            cred_request,
            cred_values.into(),
            Some(&rev_reg_id),
            rev_config.as_ref().map(|config| config.status_list),
            rev_config.as_ref().map(|config| config.registry_idx),
        );

        issue_cred
    }

    // prover requests and gets credential stored in their wallets
    // This updates ledger on revocation reg also
    pub fn issuer_create_credential_and_store_in_prover_wallet(
        &mut self,
        issuer_id: &'static str,
        prover_id: &'static str,
        values: &'a IssuerValues,
        time_prev_rev_reg: u64,
        time_new_rev_reg: u64,
        credential_format: CredentialFormat,
    ) {
        let issuer_wallet = self.issuer_wallets.get(issuer_id).unwrap();

        for (cred_def_id, (_, cred_values, _, rev_reg_id, rev_idx)) in values.iter() {
            let offer = &self.prover_wallets[prover_id].cred_offers[cred_def_id];
            let cred_def = self
                .ledger
                .cred_defs
                .get(&CredentialDefinitionId::new_unchecked(*cred_def_id))
                .unwrap();
            // Prover creates a Credential Request
            let cred_req_data = prover::create_credential_request(
                Some("entropy"),
                None,
                cred_def,
                &self.prover_wallets[prover_id].link_secret,
                "default",
                offer,
            )
            .expect("Error creating credential request");

            let rev_def = issuer_wallet.rev_defs.get(*rev_reg_id).map(|e| &e.public);

            let rev_def_priv = issuer_wallet.rev_defs.get(*rev_reg_id).map(|e| &e.private);

            // Issuer creates a credential
            let mut recv_cred = self.issuer_create_credential(
                &issuer_wallet,
                &self.ledger,
                &credential_format,
                &cred_req_data.0,
                offer,
                rev_reg_id,
                cred_def_id,
                cred_values,
                time_prev_rev_reg,
                *rev_idx,
            );

            // prover processes it
            let prover_wallet = self.prover_wallets.get_mut(prover_id).unwrap();
            prover_wallet.store_credential(
                &cred_def_id,
                &mut recv_cred,
                &cred_req_data.1,
                cred_def,
                rev_def,
            );
            prover_wallet.convert_credential(cred_def_id, &recv_cred, &cred_def);

            // Update prover wallets and ledger with new revocation status list
            prover_wallet.cred_reqs.push(cred_req_data);

            if let Some(rev_def) = rev_def {
                let list = self
                    .ledger
                    .revocation_list
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

                let map = self.ledger.revocation_list.get_mut(rev_reg_id).unwrap();
                map.insert(time_new_rev_reg, updated_list);
            }
        }
    }

    pub fn prover_creates_revocation_states(
        &mut self,
        prover_id: &'static str,
        time_to_update_to: u64,
    ) {
        let mut rev_states = self.prover_wallets[prover_id].rev_states.clone();
        for (id, cred) in &self.prover_wallets[prover_id].credentials {
            if let Some(id) = &cred.rev_reg_id {
                let rev_status_list = self
                    .ledger
                    .revocation_list
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
                rev_states.insert(id.0.clone(), (Some(state), Some(time_to_update_to)));
            };
        }
        self.prover_wallets.get_mut(prover_id).unwrap().rev_states = rev_states;
    }

    fn get_schemas(&self) -> HashMap<SchemaId, Schema> {
        HashMap::from_iter(
            self.ledger
                .schemas
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        )
    }

    fn get_cred_defs(&self) -> HashMap<CredentialDefinitionId, CredentialDefinition> {
        HashMap::from_iter(
            self.ledger
                .cred_defs
                .iter()
                .map(|(k, v)| v.try_clone().map(|v| (k.clone(), v)))
                .collect::<Result<HashMap<_, _>, anoncreds::Error>>()
                .unwrap(),
        )
    }

    pub fn prover_creates_presentation(
        &self,
        prover_id: &'static str,
        present_credentials: &Vec<CredentialToPresent>,
        self_attested: Option<HashMap<String, String>>,
        req: &PresentationRequest,
        format: PresentationFormat,
    ) -> Presentations {
        let prover_wallet = &self.prover_wallets[prover_id];
        let schemas = self.get_schemas();
        let cred_defs = self.get_cred_defs();
        prover_wallet.create_presentation(
            &format,
            &schemas,
            &cred_defs,
            req,
            present_credentials,
            self_attested,
        )
    }
}

impl<'a> Ledger<'a> {
    pub fn add_schema(&mut self, schema_id: &str, schema: &Schema) {
        let schema_id = SchemaId::new_unchecked(schema_id);
        self.schemas.insert(schema_id, schema.clone());
    }

    pub fn add_cred_def(&mut self, cred_def_id: &str, cred_def: &CredentialDefinition) {
        let cred_def_id = CredentialDefinitionId::new_unchecked(cred_def_id);
        self.cred_defs
            .insert(cred_def_id, cred_def.try_clone().unwrap());
    }

    pub fn add_rev_reg_def(
        &mut self,
        rev_reg_def_id: &str,
        rev_reg_def: &RevocationRegistryDefinition,
    ) {
        let rev_reg_def_id = RevocationRegistryDefinitionId::new_unchecked(rev_reg_def_id);
        self.rev_reg_defs
            .insert(rev_reg_def_id, rev_reg_def.clone());
    }

    pub fn resolve_schemas(&self, schema_ids: Vec<&str>) -> HashMap<SchemaId, Schema> {
        let mut schemas = HashMap::new();
        for schema_id in schema_ids {
            let schema_id = SchemaId::new_unchecked(schema_id);
            let schema = self.schemas.get(&schema_id).expect("Schema not found");
            schemas.insert(schema_id, schema.clone());
        }
        schemas
    }

    pub fn resolve_cred_defs(
        &self,
        cred_def_ids: Vec<&str>,
    ) -> HashMap<CredentialDefinitionId, CredentialDefinition> {
        let mut cred_defs = HashMap::new();
        for cred_def_id in cred_def_ids {
            let cred_def_id = CredentialDefinitionId::new_unchecked(cred_def_id);
            let cred_def = self.cred_defs.get(&cred_def_id).expect("CredDef not found");
            cred_defs.insert(cred_def_id, cred_def.try_clone().unwrap());
        }
        cred_defs
    }

    pub fn resolve_rev_reg_defs(
        &self,
        rev_reg_def_ids: Vec<&str>,
    ) -> HashMap<RevocationRegistryDefinitionId, RevocationRegistryDefinition> {
        let mut rev_reg_def_map = HashMap::new();
        for rev_reg_def_id in rev_reg_def_ids {
            let rev_reg_def_id = RevocationRegistryDefinitionId::new_unchecked(rev_reg_def_id);
            let rev_reg_def = self
                .rev_reg_defs
                .get(&rev_reg_def_id)
                .expect("RevRegDef not found");
            rev_reg_def_map.insert(rev_reg_def_id, rev_reg_def.clone());
        }
        rev_reg_def_map
    }
}

impl IssuerWallet {
    pub fn create_schema(&self, ledger: &mut Ledger, name: &str) -> (Schema, String) {
        let (schema, schema_id) = fixtures::create_schema(name);
        ledger.add_schema(schema_id, &schema);
        (schema, schema_id.to_string())
    }

    pub fn create_cred_def(
        &mut self,
        ledger: &mut Ledger,
        schema: &Schema,
        support_revocation: bool,
    ) -> (CredentialDefinition, String) {
        let ((cred_def, cred_def_priv, cred_key_correctness_proof), cred_def_id) =
            fixtures::create_cred_def(schema, support_revocation);
        ledger.add_cred_def(cred_def_id, &cred_def);
        self.cred_defs.insert(
            cred_def_id.to_string(),
            StoredCredDef {
                public: cred_def.try_clone().unwrap(),
                private: cred_def_priv,
                key_proof: cred_key_correctness_proof,
            },
        );
        (cred_def, cred_def_id.to_string())
    }

    pub fn create_revocation_registry<'b>(
        &mut self,
        ledger: &mut Ledger,
        cred_def: &CredentialDefinition,
        time: Option<u64>,
        issuance_by_default: bool,
    ) -> (String, RevocationRegistryDefinition, RevocationStatusList) {
        // Create tails file writer
        let mut tf = TailsFileWriter::new(None);

        let ((rev_reg_def, rev_reg_def_priv), rev_reg_def_id) =
            fixtures::create_rev_reg_def(cred_def, &mut tf);

        // Issuer creates revocation status list - to be put on the ledger
        let revocation_status_list = fixtures::create_revocation_status_list(
            cred_def,
            &rev_reg_def,
            &rev_reg_def_priv,
            time,
            issuance_by_default,
        );

        self.rev_defs.insert(
            rev_reg_def_id.to_string(),
            StoredRevDef {
                public: rev_reg_def.clone(),
                private: rev_reg_def_priv,
            },
        );

        ledger.add_rev_reg_def(rev_reg_def_id, &rev_reg_def);

        (
            rev_reg_def_id.to_string(),
            rev_reg_def,
            revocation_status_list,
        )
    }

    pub fn create_credential_offer(&self, schema_id: &str, cred_def_id: &str) -> CredentialOffer {
        let correctness_proof = &self
            .cred_defs
            .get(cred_def_id)
            .expect("Credential Definition correctness proof not found")
            .key_proof;
        issuer::create_credential_offer(
            schema_id.try_into().unwrap(),
            cred_def_id.try_into().unwrap(),
            correctness_proof,
        )
        .expect("Error creating credential offer")
    }

    pub fn create_credential(
        &self,
        format: &CredentialFormat,
        cred_def_id: &str,
        cred_offer: &CredentialOffer,
        cred_request: &CredentialRequest,
        cred_values: CredentialValues,
        rev_reg_def_id: Option<&str>,
        revocation_status_list: Option<&RevocationStatusList>,
        credential_rev_index: Option<u32>,
    ) -> Credentials {
        let cred_def_record = &self
            .cred_defs
            .get(cred_def_id)
            .expect("Credential Definition not found");
        let cred_def_private = &cred_def_record.private;
        let cred_def = &cred_def_record.public;

        let revocation_config =
            match rev_reg_def_id {
                Some(rev_reg_def_id) => self.rev_defs.get(rev_reg_def_id).map(|stored_rev_def| {
                    CredentialRevocationConfig {
                        reg_def: &stored_rev_def.public,
                        reg_def_private: &stored_rev_def.private,
                        registry_idx: credential_rev_index
                            .expect("Credential Revocation Index must be provided"),
                        status_list: revocation_status_list.expect("Missing status list"),
                    }
                }),
                None => None,
            };

        let credential = match format {
            CredentialFormat::Legacy => {
                let issue_cred = issuer::create_credential(
                    cred_def,
                    cred_def_private,
                    &cred_offer,
                    &cred_request,
                    cred_values,
                    revocation_config,
                )
                .expect("Error creating credential");
                Credentials::Legacy(issue_cred)
            }
            CredentialFormat::W3C => {
                let issue_cred = w3c::issuer::create_credential(
                    cred_def,
                    cred_def_private,
                    &cred_offer,
                    &cred_request,
                    CredentialAttributes::from(&cred_values),
                    revocation_config,
                    None,
                )
                .expect("Error creating credential");
                Credentials::W3C(issue_cred)
            }
        };

        credential
    }

    pub fn update_revocation_status_list(
        &self,
        cred_def: &CredentialDefinition,
        rev_reg_def_id: &str,
        current_list: &RevocationStatusList,
        issued: Option<BTreeSet<u32>>,
        revoked: Option<BTreeSet<u32>>,
        timestamp: Option<u64>,
    ) -> RevocationStatusList {
        let rev_reg = self
            .rev_defs
            .get(rev_reg_def_id)
            .expect("Revocation Registry Definition not found");
        issuer::update_revocation_status_list(
            cred_def,
            &rev_reg.public,
            &rev_reg.private,
            current_list,
            issued,
            revoked,
            timestamp,
        )
        .unwrap()
    }
}

impl<'a> ProverWallet<'a> {
    pub fn create_credential_request(
        &self,
        cred_def: &CredentialDefinition,
        credential_offer: &CredentialOffer,
    ) -> (CredentialRequest, CredentialRequestMetadata) {
        prover::create_credential_request(
            Some(self.entropy),
            None,
            cred_def,
            &self.link_secret,
            &self.link_secret_id,
            credential_offer,
        )
        .expect("Error creating credential request")
    }

    pub fn store_credential(
        &mut self,
        id: &str,
        credential: &mut Credentials,
        cred_request_metadata: &CredentialRequestMetadata,
        cred_def: &CredentialDefinition,
        rev_reg_def: Option<&RevocationRegistryDefinition>,
    ) {
        match credential {
            Credentials::Legacy(ref mut credential) => {
                prover::process_credential(
                    credential,
                    cred_request_metadata,
                    &self.link_secret,
                    cred_def,
                    rev_reg_def,
                )
                .expect("Error processing credential");
                self.credentials
                    .insert(id.to_string(), credential.try_clone().unwrap());
            }
            Credentials::W3C(ref mut credential) => {
                w3c::prover::process_credential(
                    credential,
                    cred_request_metadata,
                    &self.link_secret,
                    cred_def,
                    rev_reg_def,
                )
                .expect("Error processing credential");
                self.w3c_credentials
                    .insert(id.to_string(), credential.clone());
            }
        }
    }

    pub fn create_or_update_revocation_state(
        &self,
        tails_location: &str,
        rev_reg_def: &RevocationRegistryDefinition,
        rev_status_list: &RevocationStatusList,
        rev_reg_idx: u32,
        rev_state: Option<&CredentialRevocationState>,
        old_rev_status_list: Option<&RevocationStatusList>,
    ) -> CredentialRevocationState {
        prover::create_or_update_revocation_state(
            tails_location,
            &rev_reg_def,
            rev_status_list,
            rev_reg_idx,
            rev_state,
            old_rev_status_list,
        )
        .expect("Error creating revocation state")
    }

    pub fn prepare_credentials_to_present<'b, T: RevocableCredential>(
        &'b self,
        credentials: &'b HashMap<String, T>,
        present_credentials: &Vec<CredentialToPresent>,
    ) -> PresentCredentials<'b, T> {
        let mut present = PresentCredentials::default();

        for present_credential in present_credentials.iter() {
            let credential = credentials
                .get(&present_credential.id)
                .expect("Credential not found");

            let (rev_state, timestamp) = if let Some(id) = &credential.rev_reg_id() {
                self.rev_states.get(&id.0).unwrap()
            } else {
                &(None, None)
            };

            let mut cred = present.add_credential(credential, *timestamp, rev_state.as_ref());
            for data in present_credential.attributes.iter() {
                match data.form {
                    PresentAttributeForm::RevealedAttribute => {
                        cred.add_requested_attribute(&data.referent, true);
                    }
                    PresentAttributeForm::UnrevealedAttribute => {
                        cred.add_requested_attribute(&data.referent, false);
                    }
                    PresentAttributeForm::Predicate => {
                        cred.add_requested_predicate(&data.referent);
                    }
                }
            }
        }
        present
    }

    pub fn create_presentation(
        &self,
        format: &PresentationFormat,
        schemas: &HashMap<SchemaId, Schema>,
        cred_defs: &HashMap<CredentialDefinitionId, CredentialDefinition>,
        pres_request: &PresentationRequest,
        present_credentials: &Vec<CredentialToPresent>,
        self_attested_credentials: Option<HashMap<String, String>>,
    ) -> Presentations {
        match format {
            PresentationFormat::Legacy => {
                let present =
                    self.prepare_credentials_to_present(&self.credentials, present_credentials);
                let presentation = prover::create_presentation(
                    pres_request,
                    present,
                    self_attested_credentials,
                    &self.link_secret,
                    schemas,
                    cred_defs,
                )
                .expect("Error creating presentation");
                Presentations::Legacy(presentation)
            }
            PresentationFormat::W3C => {
                let present =
                    self.prepare_credentials_to_present(&self.w3c_credentials, present_credentials);
                let presentation = w3c::prover::create_presentation(
                    pres_request,
                    present,
                    &self.link_secret,
                    schemas,
                    cred_defs,
                )
                .expect("Error creating presentation");
                Presentations::W3C(presentation)
            }
        }
    }

    pub fn convert_credential(
        &mut self,
        id: &str,
        credential: &Credentials,
        cred_def: &CredentialDefinition,
    ) {
        match credential {
            Credentials::Legacy(legacy_cred) => {
                // Convert legacy credential into W3C form
                let w3c_cred = credential_to_w3c(&legacy_cred, cred_def)
                    .expect("Error converting legacy credential into W3C form");

                // Store w3c credential in wallet
                self.w3c_credentials.insert(id.to_string(), w3c_cred);
            }
            Credentials::W3C(w3c_cred) => {
                // Convert w3c credential into legacy form
                let legacy_cred = credential_from_w3c(&w3c_cred)
                    .expect("Error converting legacy credential into W3C form");

                // Store legacy credential in wallet
                self.credentials.insert(id.to_string(), legacy_cred);
            }
        }
    }
}

impl VerifierWallet {
    pub fn generate_nonce(&self) -> Nonce {
        verifier::generate_nonce().expect("Error generating presentation request nonce")
    }

    pub fn verify_presentation(
        &self,
        presentation: &Presentations,
        pres_req: &PresentationRequest,
        schemas: &HashMap<SchemaId, Schema>,
        cred_defs: &HashMap<CredentialDefinitionId, CredentialDefinition>,
        rev_reg_defs: Option<
            &HashMap<RevocationRegistryDefinitionId, RevocationRegistryDefinition>,
        >,
        rev_status_lists: Option<Vec<RevocationStatusList>>,
        nonrevoke_interval_override: Option<
            &HashMap<RevocationRegistryDefinitionId, HashMap<u64, u64>>,
        >,
    ) -> Result<bool, TestError> {
        match presentation {
            Presentations::Legacy(presentation) => verifier::verify_presentation(
                presentation,
                pres_req,
                schemas,
                cred_defs,
                rev_reg_defs,
                rev_status_lists,
                nonrevoke_interval_override,
            )
            .map_err(|e| TestError(e.to_string())),
            Presentations::W3C(presentation) => w3c::verifier::verify_presentation(
                presentation,
                pres_req,
                schemas,
                cred_defs,
                rev_reg_defs,
                rev_status_lists,
                nonrevoke_interval_override,
            )
            .map_err(|e| TestError(e.to_string())),
        }
    }

    pub fn check_presentation_attribute(
        &self,
        presentation: &Presentations,
        attribute: PresentedAttribute,
    ) {
        match presentation {
            Presentations::Legacy(presentation) => {
                match attribute.expected {
                    ExpectedAttributeValue::RevealedAttribute(expected) => {
                        assert_eq!(
                            expected,
                            presentation
                                .requested_proof
                                .revealed_attrs
                                .get(attribute.referent)
                                .unwrap()
                                .raw
                        );
                    }
                    ExpectedAttributeValue::GroupedAttribute(expected) => {
                        let revealed_attr_groups = presentation
                            .requested_proof
                            .revealed_attr_groups
                            .get(attribute.referent)
                            .unwrap();
                        assert_eq!(
                            expected,
                            revealed_attr_groups.values.get(attribute.name).unwrap().raw
                        );
                    }
                    ExpectedAttributeValue::UnrevealedAttribute(expected) => {
                        assert_eq!(
                            expected,
                            presentation
                                .requested_proof
                                .unrevealed_attrs
                                .get(attribute.referent)
                                .unwrap()
                                .sub_proof_index
                        );
                    }
                    ExpectedAttributeValue::Predicate => {
                        presentation
                            .requested_proof
                            .predicates
                            .get(attribute.referent)
                            .unwrap();
                    }
                };
            }
            Presentations::W3C(presentation) => {
                match attribute.expected {
                    ExpectedAttributeValue::RevealedAttribute(expected)
                    | ExpectedAttributeValue::GroupedAttribute(expected) => {
                        let credential = presentation
                            .verifiable_credential
                            .iter()
                            .find(|credential| {
                                credential
                                    .credential_subject
                                    .attributes
                                    .0
                                    .contains_key(&attribute.name.to_lowercase())
                            })
                            .unwrap();
                        assert_eq!(
                            &CredentialAttributeValue::Attribute(expected.to_string()),
                            credential
                                .credential_subject
                                .attributes
                                .0
                                .get(&attribute.name.to_lowercase())
                                .unwrap()
                        );
                    }
                    ExpectedAttributeValue::UnrevealedAttribute(expected) => {
                        // not checking here
                    }
                    ExpectedAttributeValue::Predicate => {
                        let credential = presentation
                            .verifiable_credential
                            .iter()
                            .find(|credential| {
                                credential
                                    .credential_subject
                                    .attributes
                                    .0
                                    .contains_key(&attribute.name.to_lowercase())
                            })
                            .unwrap();
                        credential
                            .credential_subject
                            .attributes
                            .0
                            .get(&attribute.name.to_lowercase())
                            .unwrap();
                    }
                };
            }
        }
    }
}

pub struct CredentialToPresent {
    pub id: String,
    pub attributes: Vec<PresentAttribute>,
}

pub struct PresentAttribute {
    pub referent: String,
    pub form: PresentAttributeForm,
}

pub enum PresentAttributeForm {
    RevealedAttribute,
    UnrevealedAttribute,
    Predicate,
}

pub struct PresentedAttribute<'a> {
    pub referent: &'a str,
    pub name: &'a str,
    pub expected: ExpectedAttributeValue<'a>,
}

pub enum ExpectedAttributeValue<'a> {
    RevealedAttribute(&'a str),
    UnrevealedAttribute(u32),
    GroupedAttribute(&'a str),
    Predicate,
}

pub trait RevocableCredential {
    fn rev_reg_id(&self) -> Option<&RevocationRegistryDefinitionId>;
}

impl RevocableCredential for Credential {
    fn rev_reg_id(&self) -> Option<&RevocationRegistryDefinitionId> {
        self.rev_reg_id.as_ref()
    }
}

impl RevocableCredential for W3CCredential {
    fn rev_reg_id(&self) -> Option<&RevocationRegistryDefinitionId> {
        self.get_rev_reg_id()
    }
}
