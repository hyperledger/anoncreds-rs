use crate::data_types::credential::{CredentialValuesEncoding, RawCredentialValues};
use crate::data_types::w3c::constants::{ANONCREDS_CONTEXTS, ANONCREDS_TYPES};
use crate::data_types::w3c::credential::{CredentialSchema, CredentialSchemaType, CredentialSubject, W3CCredential};
use crate::data_types::w3c::one_or_many::OneOrMany;
use crate::data_types::w3c::credential_proof::{CredentialProof, CredentialSignature, CredentialSignatureProof};
use crate::Error;
use crate::types::Credential;
use crate::utils::datetime;
use crate::utils::validation::Validatable;

pub fn credential_to_w3c(credential: &Credential) -> Result<W3CCredential, Error> {
    credential.validate()?;

    let credential = credential.try_clone()?;

    // FIXME: As AnonCreds-rs is DID method agnostic, so it does not analyze/handle the values of id fields.
    //  For conversion into W3C Credentials form we need to set issuer_id attribute but legacy credentials do not contain it explicitly.
    //  We only can parse issuer from the legacy form?
    let issuer = credential.cred_def_id.issuer_did();
    let cred_def_id = credential.cred_def_id;
    let schema_id = credential.schema_id;
    let signature = CredentialSignature::new(credential.signature,
                                             credential.signature_correctness_proof,
                                             credential.rev_reg,
                                             credential.witness);
    let proof = CredentialSignatureProof::new(signature);
    let attributes = RawCredentialValues::from(&credential.values);
    let issuance_date = datetime::today();

    let w3c_credential = W3CCredential {
        context: ANONCREDS_CONTEXTS.clone(),
        type_: ANONCREDS_TYPES.clone(),
        issuer,
        issuance_date,
        credential_schema: CredentialSchema {
            type_: CredentialSchemaType::AnonCredsDefinition,
            definition: cred_def_id,
            schema: schema_id,
            revocation_registry: None,
            encoding: CredentialValuesEncoding::Auto,
        },
        credential_subject: CredentialSubject {
            id: None,
            attributes,
        },
        proof: OneOrMany::Many(
            vec![
                CredentialProof::AnonCredsSignatureProof(proof)
            ]
        ),
        ..Default::default()
    };

    Ok(w3c_credential)
}

pub fn credential_from_w3c(w3c_credential: &W3CCredential) -> Result<Credential, Error> {
    w3c_credential.validate()?;

    let schema_id = w3c_credential.credential_schema.schema.clone();
    let cred_def_id = w3c_credential.credential_schema.definition.clone();
    let rev_reg_id = w3c_credential.credential_schema.revocation_registry.clone();
    let proof = w3c_credential.get_credential_signature_proof()?;
    let credential_signature = proof.get_credential_signature()?;
    let values = w3c_credential.credential_subject.attributes.encode(&w3c_credential.credential_schema.encoding)?;

    let credential = Credential {
        schema_id,
        cred_def_id,
        rev_reg_id,
        values,
        signature: credential_signature.signature,
        signature_correctness_proof: credential_signature.signature_correctness_proof,
        rev_reg: None,
        witness: None,
    };

    Ok(credential)
}

#[cfg(test)]
mod tests {
    use crate::data_types::cred_def::CredentialDefinitionId;
    use crate::data_types::schema::SchemaId;
    use crate::types::{CredentialValues, MakeCredentialValues};
    use anoncreds_clsignatures::{
        CredentialSignature as CLCredentialSignature,
        SignatureCorrectnessProof as CLSignatureCorrectnessProof,
    };
    use crate::data_types::issuer_id::IssuerId;
    use crate::data_types::w3c::credential_proof::CredentialSignatureType;
    use crate::ErrorKind;
    use super::*;

    const ISSUER_ID: &str = "mock:uri";
    const SCHEMA_ID: &str = "mock:uri";
    const CRED_DEF_ID: &str = "mock:uri";

    fn _issuer_id() -> IssuerId {
        IssuerId::new_unchecked(ISSUER_ID)
    }

    fn _schema_id() -> SchemaId {
        SchemaId::new_unchecked(SCHEMA_ID)
    }

    fn _cred_def_id() -> CredentialDefinitionId {
        CredentialDefinitionId::new_unchecked(CRED_DEF_ID)
    }

    fn _cred_values() -> CredentialValues {
        let mut make = MakeCredentialValues::default();
        make.add_raw("name", "Alice").unwrap();
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
            schema_id: _schema_id(),
            cred_def_id: _cred_def_id(),
            rev_reg_id: None,
            values: _cred_values(),
            signature: _cl_credential_signature(),
            signature_correctness_proof: _cl_credential_signature_correctness_proof(),
            rev_reg: None,
            witness: None,
        }
    }

    fn _signature_data() -> CredentialSignature {
        CredentialSignature {
            signature: _cl_credential_signature(),
            signature_correctness_proof: _cl_credential_signature_correctness_proof(),
            rev_reg: None,
            witness: None,
        }
    }

    fn _w3c_credential() -> W3CCredential {
        W3CCredential {
            context: ANONCREDS_CONTEXTS.clone(),
            type_: ANONCREDS_TYPES.clone(),
            issuer: _issuer_id(),
            issuance_date: datetime::today(),
            credential_schema: CredentialSchema {
                type_: CredentialSchemaType::AnonCredsDefinition,
                definition: _cred_def_id(),
                schema: _schema_id(),
                revocation_registry: None,
                encoding: CredentialValuesEncoding::Auto,
            },
            credential_subject: CredentialSubject {
                id: None,
                attributes: RawCredentialValues::from(&_cred_values()),
            },
            proof: OneOrMany::One(
                CredentialProof::AnonCredsSignatureProof(
                    CredentialSignatureProof {
                        type_: CredentialSignatureType::CLSignature2023,
                        signature: _signature_data().encode(),
                    }
                )
            ),
            id: None,
            credential_status: None,
            expiration_date: None,
        }
    }

    #[test]
    fn test_convert_credential_to_and_from_w3c() {
        let original_legacy_credential = _legacy_credential();
        let w3c_credential =
            credential_to_w3c(&original_legacy_credential)
                .expect("unable to convert credential to w3c form");
        let legacy_credential =
            credential_from_w3c(&w3c_credential)
                .expect("unable to convert credential to legacy form");
        assert_eq!(
            json!(original_legacy_credential),
            json!(legacy_credential),
        )
    }

    #[test]
    fn test_credential_to_w3c_form() {
        let legacy_credential = _legacy_credential();
        let w3c_credential =
            credential_to_w3c(&legacy_credential)
                .expect("unable to convert credential to w3c form");
        assert_eq!(w3c_credential.context, ANONCREDS_CONTEXTS.clone());
        assert_eq!(w3c_credential.type_, ANONCREDS_TYPES.clone());
        assert_eq!(w3c_credential.credential_schema.schema, legacy_credential.schema_id);
        assert_eq!(w3c_credential.credential_schema.definition, legacy_credential.cred_def_id);
        assert_eq!(w3c_credential.credential_schema.revocation_registry, legacy_credential.rev_reg_id);
        assert_eq!(w3c_credential.credential_schema.encoding, CredentialValuesEncoding::Auto);
        assert_eq!(w3c_credential.credential_subject.attributes, RawCredentialValues::from(&legacy_credential.values));
        let proof =
            w3c_credential
                .get_credential_signature_proof()
                .expect("credential signature proof is not set");
        assert_eq!(proof.signature, _signature_data().encode());
    }

    #[test]
    fn test_credential_from_w3c_form() {
        let w3c_credential = _w3c_credential();
        let legacy_credential =
            credential_from_w3c(&w3c_credential)
                .expect("unable to convert credential from w3c form");
        assert_eq!(legacy_credential.schema_id, w3c_credential.credential_schema.schema);
        assert_eq!(legacy_credential.cred_def_id, w3c_credential.credential_schema.definition);
        assert_eq!(legacy_credential.rev_reg_id, w3c_credential.credential_schema.revocation_registry);
        assert_eq!(legacy_credential.values, _cred_values());
        assert_eq!(legacy_credential.signature, _signature_data().signature);
        assert_eq!(legacy_credential.signature_correctness_proof, _signature_data().signature_correctness_proof);
        assert_eq!(legacy_credential.rev_reg, _signature_data().rev_reg);
    }

    #[test]
    fn test_credential_from_w3c_form_when_no_signature_proof() {
        let mut w3c_credential = _w3c_credential();
        w3c_credential.proof = OneOrMany::default();
        let err = credential_from_w3c(&w3c_credential).unwrap_err();
        assert_eq!(ErrorKind::Input, err.kind());
    }
}