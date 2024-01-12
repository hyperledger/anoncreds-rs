use crate::data_types::cred_def::CredentialDefinitionId;
use crate::data_types::rev_reg_def::RevocationRegistryDefinitionId;
use crate::data_types::schema::SchemaId;
use crate::utils::base64;
use crate::Result;
use anoncreds_clsignatures::{
    AggregatedProof, CredentialSignature, RevocationRegistry, SignatureCorrectnessProof, SubProof,
    Witness,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::json;
use std::collections::HashSet;
use std::fmt::Debug;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataIntegrityProof {
    #[serde(rename = "type")]
    pub(crate) type_: DataIntegrityProofType,
    pub(crate) cryptosuite: CryptoSuite,
    pub(crate) proof_purpose: ProofPurpose,
    pub(crate) verification_method: String,
    pub(crate) proof_value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) challenge: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataIntegrityProofType {
    DataIntegrityProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofPurpose {
    #[serde(rename = "assertionMethod")]
    AssertionMethod,
    #[serde(rename = "authentication")]
    Authentication,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoSuite {
    #[serde(rename = "anoncredsvc-2023")]
    AnonCredsVc2023,
    #[serde(rename = "anoncredspresvc-2023")]
    AnonCredsPresVc2023,
    #[serde(rename = "anoncredspresvp-2023")]
    AnonCredsPresVp2023,
}

impl DataIntegrityProof {
    pub fn new<V: EncodedObject + Serialize>(
        cryptosuite: CryptoSuite,
        proof_purpose: ProofPurpose,
        verification_method: String,
        value: &V,
        challenge: Option<String>,
    ) -> Self {
        DataIntegrityProof {
            type_: DataIntegrityProofType::DataIntegrityProof,
            cryptosuite,
            proof_purpose,
            verification_method,
            proof_value: value.encode(),
            challenge,
        }
    }

    pub(crate) fn new_credential_proof(
        value: &CredentialSignatureProofValue,
    ) -> DataIntegrityProof {
        DataIntegrityProof::new(
            CryptoSuite::AnonCredsVc2023,
            ProofPurpose::AssertionMethod,
            value.cred_def_id.to_string(),
            value,
            None,
        )
    }

    pub(crate) fn new_credential_presentation_proof(
        value: &CredentialPresentationProofValue,
    ) -> DataIntegrityProof {
        DataIntegrityProof::new(
            CryptoSuite::AnonCredsPresVc2023,
            ProofPurpose::AssertionMethod,
            value.cred_def_id.to_string(),
            value,
            None,
        )
    }

    pub(crate) fn new_presentation_proof(
        value: &PresentationProofValue,
        challenge: String,
        verification_method: String,
    ) -> DataIntegrityProof {
        DataIntegrityProof::new(
            CryptoSuite::AnonCredsPresVp2023,
            ProofPurpose::Authentication,
            verification_method,
            value,
            Some(challenge),
        )
    }

    pub fn get_proof_value<V: EncodedObject + DeserializeOwned>(&self) -> Result<V> {
        V::decode(&self.proof_value)
    }

    pub fn get_credential_signature_proof(&self) -> Result<CredentialSignatureProofValue> {
        if self.cryptosuite != CryptoSuite::AnonCredsVc2023 {
            return Err(err_msg!(
                "DataIntegrityProof does not contain {:?} proof",
                CryptoSuite::AnonCredsVc2023
            ));
        }
        if self.proof_purpose != ProofPurpose::AssertionMethod {
            return Err(err_msg!(
                "DataIntegrityProof does not contain {:?} proof",
                ProofPurpose::AssertionMethod
            ));
        }
        self.get_proof_value()
    }

    pub fn get_credential_presentation_proof(&self) -> Result<CredentialPresentationProofValue> {
        if self.cryptosuite != CryptoSuite::AnonCredsPresVc2023 {
            return Err(err_msg!(
                "DataIntegrityProof does not contain {:?} proof",
                CryptoSuite::AnonCredsVc2023
            ));
        }
        if self.proof_purpose != ProofPurpose::AssertionMethod {
            return Err(err_msg!(
                "DataIntegrityProof does not contain {:?} proof",
                ProofPurpose::AssertionMethod
            ));
        }
        self.get_proof_value()
    }

    pub fn get_presentation_proof(&self) -> Result<PresentationProofValue> {
        if self.cryptosuite != CryptoSuite::AnonCredsPresVp2023 {
            return Err(err_msg!(
                "DataIntegrityProof does not contain {:?} proof",
                CryptoSuite::AnonCredsVc2023
            ));
        }
        if self.proof_purpose != ProofPurpose::Authentication {
            return Err(err_msg!(
                "DataIntegrityProof does not contain {:?} proof",
                ProofPurpose::Authentication
            ));
        }
        self.get_proof_value()
    }

    pub fn get_credential_proof_details(&self) -> Result<CredentialProofDetails> {
        match self.cryptosuite {
            CryptoSuite::AnonCredsVc2023 => {
                let proof = self.get_credential_signature_proof()?;
                Ok(CredentialProofDetails {
                    schema_id: proof.schema_id,
                    cred_def_id: proof.cred_def_id,
                    rev_reg_id: proof.rev_reg_id,
                    rev_reg_index: proof.signature.extract_index(),
                    timestamp: None,
                })
            }
            CryptoSuite::AnonCredsPresVc2023 => {
                let proof = self.get_credential_presentation_proof()?;
                Ok(CredentialProofDetails {
                    schema_id: proof.schema_id,
                    cred_def_id: proof.cred_def_id,
                    rev_reg_id: proof.rev_reg_id,
                    rev_reg_index: None,
                    timestamp: proof.timestamp,
                })
            }
            CryptoSuite::AnonCredsPresVp2023 => Err(err_msg!("Unexpected DataIntegrityProof")),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct CredentialSignatureProofValue {
    pub schema_id: SchemaId,
    pub cred_def_id: CredentialDefinitionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rev_reg_id: Option<RevocationRegistryDefinitionId>,
    pub signature: CredentialSignature,
    pub signature_correctness_proof: SignatureCorrectnessProof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rev_reg: Option<RevocationRegistry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<Witness>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialPresentationProofValue {
    pub schema_id: SchemaId,
    pub cred_def_id: CredentialDefinitionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rev_reg_id: Option<RevocationRegistryDefinitionId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    pub mapping: CredentialAttributesMapping,
    pub sub_proof: SubProof,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialAttributesMapping {
    #[serde(default)]
    pub revealed_attributes: HashSet<String>,
    pub revealed_attribute_groups: HashSet<String>,
    #[serde(default)]
    pub unrevealed_attributes: HashSet<String>,
    #[serde(default)]
    pub predicates: HashSet<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PresentationProofValue {
    pub aggregated: AggregatedProof,
}

impl EncodedObject for CredentialSignatureProofValue {}

impl EncodedObject for CredentialPresentationProofValue {}

impl EncodedObject for PresentationProofValue {}

// Credential information aggregated from `CredentialSignatureProof` and `CredentialPresentationProofValue`
// This information is needed for presentation creation and verification
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CredentialProofDetails {
    pub schema_id: SchemaId,
    pub cred_def_id: CredentialDefinitionId,
    pub rev_reg_id: Option<RevocationRegistryDefinitionId>,
    pub rev_reg_index: Option<u32>,
    pub timestamp: Option<u64>,
}

const BASE_HEADER: char = 'u';

pub trait EncodedObject {
    fn encode(&self) -> String
    where
        Self: Serialize,
    {
        let json = json!(self).to_string();
        let serialized = base64::encode(json);
        format!("{}{}", BASE_HEADER, serialized)
    }

    fn decode(string: &str) -> Result<Self>
    where
        Self: DeserializeOwned,
    {
        match string.chars().next() {
            Some(BASE_HEADER) => {
                // ok
            }
            value => return Err(err_msg!("Unexpected multibase base header {:?}", value)),
        }
        let decoded = base64::decode(&string[1..])?;
        let obj: Self = serde_json::from_slice(&decoded)?;
        Ok(obj)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::services::w3c::verifier;
    use crate::w3c::credential_conversion::tests::{cred_def_id, schema_id};
    use rstest::*;

    pub(crate) const PROOF_TIMESTAMP: u64 = 50;

    pub(crate) fn cl_credential_signature() -> CredentialSignature {
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

    pub(crate) fn cl_credential_signature_correctness_proof() -> SignatureCorrectnessProof {
        // clsignatures library does not provide a function to either get default or construct signature correctness proof
        serde_json::from_value(json!({
            "se": "16380378819766384687299800964395104347426132415600670073499502988403571039552426989440730562439872799389359320216622430122149635890650280073919616970308875713611769602805907315796100888051513191790990723115153015179238215201014858697020476301190889292739142646098613335687696678474499610035829049097552703970387216872374849734708764603376911608392816067509505173513379900549958002287975424637744258982508227210821445545063280589183914569333870632968595659796744088289167771635644102920825749994200219186110532662348311959247565066406030309945998501282244986323336410628720691577720308242032279888024250179409222261839",
            "c": "54687071895183924055442269144489786903186459631877792294627879136747836413523"
        })).unwrap()
    }

    pub(crate) fn credential_sub_proof() -> SubProof {
        serde_json::from_value(json!({
            "primary_proof": {
                "eq_proof":{
                    "a_prime":"93850854506025106167175657367900738564840399460457583396522672546367771557204596986051012396385435450263898123125896474854176367786952154894815573554451004746144139656996044265545613968836176711502602815031392209790095794160045376494471161541029201092195175557986308757797292716881081775201092320235240062158880723682328272460090331253190919323449053508332270184449026105339413097644934519533429034485982687030017670766107427442501537423985935074367321676374406375566791092427955935956566771002472855738585522175250186544831364686282512410608147641314561395934098066750903464501612432084069923446054698174905994358631",
                    "e":"162083298053730499878539837415798033696428693449892281052193919207514842725975444071338657195491572547562439622393591965427898285748359108",
                    "m":{
                        "age":"6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126568685843068983890896122000977852186661939211990733462807944627807336518424313388",
                        "height":"6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126574195981378365198960707499125538146253636400775219219390979675126287408712407688",
                        "master_secret":"67940925789970108743024738273926421512152745397724199848594503731042154269417576665420030681245389493783225644817826683796657351721363490290016166310023507132564589104990678182299219306228446316250328302891742457726158298612477188160335451477126201081347058945471957804431939288091328124225198960258432684399",
                        "sex":"6461691768834933403326575020439114193500962122447442182375470664835531264262887123435773676729731478629261405277091910956944655533226659560277758686479462667297473396368211269136"
                    },
                    "m2":"2553030889054034879941219523536672152702359185828546810612564355745759663351165380563310203986319611277915826660660011443138240248924364893067083241825560",
                    "revealed_attrs":{
                        "name":"66682250590915135919393234675423675079281389286836524491448775067034910960723"
                    },
                    "v":"241132863422049783305938040060597331735278274539541049316128678268379301866997158072011728743321723078574060931449243960464715113938435991871547190135480379265493203441002211218757120311064385792274455797457074741542288420192538286547871288116110058144080647854995527978708188991483561739974917309498779192480418427060775726652318167442183177955447797995160859302520108340826199956754805286213211181508112097818654928169122460464135690611512133363376553662825967455495276836834812520601471833287810311342575033448652033691127511180098524259451386027266077398672694996373787324223860522678035901333613641370426224798680813171225438770578377781015860719028452471648107174226406996348525110692233661632116547069810544117288754524961349911209241835217711929316799411645465546281445291569655422683908113895340361971530636987203042713656548617543163562701947578529101436799250628979720035967402306966520999250819096598649121167"
                },
                "ge_proofs":[]
            }
        })).unwrap()
    }

    pub(crate) fn aggregated_proof() -> AggregatedProof {
        serde_json::from_value(json!({
            "c_hash":"12021216631073704187777244636931735457451916077380601269914390379109411655797",
            "c_list":[]
        })).unwrap()
    }

    pub(crate) fn credential_signature_proof() -> CredentialSignatureProofValue {
        CredentialSignatureProofValue {
            schema_id: schema_id(),
            cred_def_id: cred_def_id(),
            rev_reg_id: None,
            signature: cl_credential_signature(),
            signature_correctness_proof: cl_credential_signature_correctness_proof(),
            rev_reg: None,
            witness: None,
        }
    }

    pub(crate) fn credential_pres_proof_value() -> CredentialPresentationProofValue {
        CredentialPresentationProofValue {
            schema_id: schema_id(),
            cred_def_id: cred_def_id(),
            rev_reg_id: Some(verifier::tests::revocation_id()),
            timestamp: Some(PROOF_TIMESTAMP),
            mapping: Default::default(),
            sub_proof: credential_sub_proof(),
        }
    }

    pub(crate) fn presentation_proof_value() -> PresentationProofValue {
        PresentationProofValue {
            aggregated: aggregated_proof(),
        }
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestObject {
        type_: String,
        value: i32,
    }

    impl EncodedObject for TestObject {}

    #[test]
    fn encoded_object_encode_decode_works() {
        let obj = TestObject {
            type_: "Test".to_string(),
            value: 1,
        };
        let encoded = obj.encode();
        assert_eq!("ueyJ0eXBlXyI6IlRlc3QiLCJ2YWx1ZSI6MX0", encoded);
        let decoded = TestObject::decode(&encoded).unwrap();
        assert_eq!(obj, decoded)
    }

    fn credential_proof() -> DataIntegrityProof {
        let credential_proof = credential_signature_proof();
        DataIntegrityProof::new_credential_proof(&credential_proof)
    }

    fn credential_pres_proof() -> DataIntegrityProof {
        let credential_pres_proof = credential_pres_proof_value();
        DataIntegrityProof::new_credential_presentation_proof(&credential_pres_proof)
    }

    fn presentation_proof() -> DataIntegrityProof {
        let presentation_proof = presentation_proof_value();
        DataIntegrityProof::new_presentation_proof(
            &presentation_proof,
            "1".to_string(),
            cred_def_id().to_string(),
        )
    }

    #[rstest]
    #[case(
        credential_proof(),
        ProofPurpose::AssertionMethod,
        CryptoSuite::AnonCredsVc2023
    )]
    #[case(
        credential_pres_proof(),
        ProofPurpose::AssertionMethod,
        CryptoSuite::AnonCredsPresVc2023
    )]
    #[case(
        presentation_proof(),
        ProofPurpose::Authentication,
        CryptoSuite::AnonCredsPresVp2023
    )]
    fn create_poof_cases(
        #[case] proof: DataIntegrityProof,
        #[case] purpose: ProofPurpose,
        #[case] suite: CryptoSuite,
    ) {
        assert_eq!(DataIntegrityProofType::DataIntegrityProof, proof.type_);
        assert_eq!(purpose, proof.proof_purpose);
        assert_eq!(suite, proof.cryptosuite);
        assert_eq!(cred_def_id().to_string(), proof.verification_method);
    }

    #[rstest]
    #[case(credential_proof(), true, false, false)]
    #[case(credential_pres_proof(), false, true, false)]
    #[case(presentation_proof(), false, false, true)]
    fn get_poof_value_cases(
        #[case] proof: DataIntegrityProof,
        #[case] is_credential_signature_proof: bool,
        #[case] is_credential_presentation_proof: bool,
        #[case] is_presentation_proof: bool,
    ) {
        assert_eq!(
            is_credential_signature_proof,
            proof.get_credential_signature_proof().is_ok()
        );
        assert_eq!(
            is_credential_presentation_proof,
            proof.get_credential_presentation_proof().is_ok()
        );
        assert_eq!(
            is_presentation_proof,
            proof.get_presentation_proof().is_ok()
        );
    }
}
