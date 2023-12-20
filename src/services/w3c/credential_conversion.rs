use crate::data_types::cred_def::CredentialDefinition;
use crate::data_types::w3c::credential::W3CCredential;
use crate::data_types::w3c::credential_attributes::CredentialAttributes;
use crate::data_types::w3c::proof::{CredentialSignatureProof, DataIntegrityProof};
use crate::data_types::w3c::VerifiableCredentialSpecVersion;
use crate::types::Credential;
use crate::utils::validation::Validatable;
use crate::Error;

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
/// let _w3c_credential = w3c::credential_conversion::credential_to_w3c(&credential, &cred_def, None)
///                         .expect("Unable to convert credential to w3c form");
///
/// ```
pub fn credential_to_w3c(
    credential: &Credential,
    cred_def: &CredentialDefinition,
    version: Option<VerifiableCredentialSpecVersion>,
) -> Result<W3CCredential, Error> {
    trace!(
        "credential_to_w3c >>> credential: {:?}, cred_def: {:?}",
        credential,
        cred_def
    );

    credential.validate()?;

    let credential = credential.try_clone()?;
    let issuer = cred_def.issuer_id.clone();
    let attributes = CredentialAttributes::from(&credential.values);
    let signature = CredentialSignatureProof {
        schema_id: credential.schema_id,
        cred_def_id: credential.cred_def_id,
        rev_reg_id: credential.rev_reg_id,
        signature: credential.signature,
        signature_correctness_proof: credential.signature_correctness_proof,
        rev_reg: credential.rev_reg,
        witness: credential.witness,
    };
    let proof = DataIntegrityProof::new_credential_proof(signature);
    let w3c_credential = W3CCredential::new(issuer, attributes, proof, version);

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

    let credential_signature = w3c_credential.get_credential_signature_proof()?;
    let values = w3c_credential.credential_subject.attributes.encode()?;

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
pub(super) mod tests {
    use super::*;
    use crate::data_types::cred_def::CredentialDefinitionId;
    use crate::data_types::issuer_id::IssuerId;
    use crate::data_types::schema::{Schema, SchemaId};
    use crate::data_types::w3c::constants::ANONCREDS_CREDENTIAL_TYPES;
    use crate::data_types::w3c::constants::{ANONCREDS_VC_1_1_CONTEXTS, ANONCREDS_VC_2_0_CONTEXTS};
    use crate::data_types::w3c::context::Contexts;
    use crate::data_types::w3c::one_or_many::OneOrMany;
    use crate::types::{
        AttributeNames, CredentialDefinitionConfig, CredentialValues, MakeCredentialValues,
        SignatureType,
    };
    use crate::{issuer, ErrorKind};
    use anoncreds_clsignatures::{
        CredentialSignature as CLCredentialSignature,
        SignatureCorrectnessProof as CLSignatureCorrectnessProof,
    };
    use rstest::*;

    pub const ISSUER_ID: &str = "mock:uri";
    pub const SCHEMA_ID: &str = "mock:uri";
    pub const CRED_DEF_ID: &str = "mock:uri";

    pub fn issuer_id() -> IssuerId {
        IssuerId::new_unchecked(ISSUER_ID)
    }

    pub fn schema_id() -> SchemaId {
        SchemaId::new_unchecked(SCHEMA_ID)
    }

    pub fn schema() -> Schema {
        issuer::create_schema("schema:name", "1.0", issuer_id(), _attributes()).unwrap()
    }

    pub fn cred_def_id() -> CredentialDefinitionId {
        CredentialDefinitionId::new_unchecked(CRED_DEF_ID)
    }

    pub fn _attributes() -> AttributeNames {
        AttributeNames::from(vec![
            "name".to_owned(),
            "height".to_owned(),
            "age".to_owned(),
        ])
    }

    pub fn credential_definition() -> CredentialDefinition {
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

    pub fn cred_values() -> CredentialValues {
        let mut make = MakeCredentialValues::default();
        make.add_raw("name", "Alice").unwrap();
        make.add_raw("height", "178").unwrap();
        make.add_raw("age", "20").unwrap();
        make.into()
    }

    fn _cl_credential_signature() -> CLCredentialSignature {
        // clsignatures library does not provide a function to either get default or construct signature
        serde_json::from_value(json!({
            "p_credential": {
                "m_2": "57832835556928742723946725004638238236382427793876617639158517726445069815397",
                "a": "20335594316731334597758816443885619716281946894071547670112874227353349613733788033617671091848119624077343554670947282810485774124636153228333825818186760397527729892806528284243491342499262911619541896964620427749043381625203893661466943880747122017539322865930800203806065857795584699623987557173946111100450130555197585324032975907705976283592876161733661021481170756352943172201881541765527633833412431874555779986196454199886878078859992928382512010526711165717317294021035408585595567390933051546616905350933492259317172537982279278238456869493798937355032304448696707549688520575565393297998400926856935054785",
                "e": "259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930114221280625468933785621106476195767",
                "v": "6264315754962089362691677910875768714719628097173834826942639456162861264780209679632476338104728648674666095282910717315628966174111516324733617604883927936031834134944562245348356595475949760140820205017843765225176947252534891385340037654527825604373031641665762232119470199172203915071879260274922482308419475927587898260844045340005759709509719230224917577081434498505999519246994431019808643717455525020238858900077950802493426663298211783820016830018445034267920428147219321200498121844471986156393710041532347890155773933440967485292509669092990420513062430659637641764166558511575862600071368439136343180394499313466692464923385392375334511727761876368691568580574716011747008456027092663180661749027223129454567715456876258225945998241007751462618767907499044716919115655029979467845162863204339002632523083819"
            }
        })).unwrap()
    }

    fn _cl_credential_signature_correctness_proof() -> CLSignatureCorrectnessProof {
        // clsignatures library does not provide a function to either get default or construct signature correctness proof
        serde_json::from_value(json!({
            "se": "16380378819766384687299800964395104347426132415600670073499502988403571039552426989440730562439872799389359320216622430122149635890650280073919616970308875713611769602805907315796100888051513191790990723115153015179238215201014858697020476301190889292739142646098613335687696678474499610035829049097552703970387216872374849734708764603376911608392816067509505173513379900549958002287975424637744258982508227210821445545063280589183914569333870632968595659796744088289167771635644102920825749994200219186110532662348311959247565066406030309945998501282244986323336410628720691577720308242032279888024250179409222261839",
            "c": "54687071895183924055442269144489786903186459631877792294627879136747836413523"
        })).unwrap()
    }

    fn _legacy_credential() -> Credential {
        Credential {
            schema_id: schema_id(),
            cred_def_id: cred_def_id(),
            rev_reg_id: None,
            values: cred_values(),
            signature: _cl_credential_signature(),
            signature_correctness_proof: _cl_credential_signature_correctness_proof(),
            rev_reg: None,
            witness: None,
        }
    }

    fn _signature_data() -> CredentialSignatureProof {
        CredentialSignatureProof {
            schema_id: schema_id(),
            cred_def_id: cred_def_id(),
            rev_reg_id: None,
            signature: _cl_credential_signature(),
            signature_correctness_proof: _cl_credential_signature_correctness_proof(),
            rev_reg: None,
            witness: None,
        }
    }

    pub fn w3c_credential() -> W3CCredential {
        W3CCredential::new(
            issuer_id(),
            CredentialAttributes::from(&cred_values()),
            DataIntegrityProof::new_credential_proof(_signature_data()),
            None,
        )
    }

    #[test]
    fn test_convert_credential_to_and_from_w3c() {
        let original_legacy_credential = _legacy_credential();
        let w3c_credential =
            credential_to_w3c(&original_legacy_credential, &credential_definition(), None)
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
        let legacy_credential = _legacy_credential();
        let w3c_credential =
            credential_to_w3c(&legacy_credential, &credential_definition(), Some(version))
                .expect("unable to convert credential to w3c form");

        assert_eq!(w3c_credential.context, expected_context.clone());
        assert_eq!(w3c_credential.type_, ANONCREDS_CREDENTIAL_TYPES.clone());
        assert_eq!(
            w3c_credential.credential_subject.attributes,
            CredentialAttributes::from(&legacy_credential.values)
        );

        let proof = w3c_credential
            .get_credential_signature_proof()
            .expect("credential signature proof is not set");

        assert_eq!(proof.schema_id, legacy_credential.schema_id);
        assert_eq!(proof.cred_def_id, legacy_credential.cred_def_id);
        assert_eq!(proof.rev_reg_id, legacy_credential.rev_reg_id);
        assert_eq!(proof.signature, _signature_data().signature);
        assert_eq!(
            proof.signature_correctness_proof,
            _signature_data().signature_correctness_proof
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
