use std::collections::HashMap;
use std::collections::{BTreeMap, BTreeSet};

use super::{BigNumber, GroupOrderElement, PointG1, PointG2};

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct BlindedCredentialSecrets {
    u: BigNumber,
    ur: Option<PointG1>,
    hidden_attributes: BTreeSet<String>,
    committed_attributes: BTreeMap<String, BigNumber>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct BlindedCredentialSecretsCorrectnessProof {
    c: BigNumber,
    v_dash_cap: BigNumber,
    m_caps: BTreeMap<String, BigNumber>,
    r_caps: BTreeMap<String, BigNumber>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct CredentialKeyCorrectnessProof {
    c: BigNumber,
    xz_cap: BigNumber,
    xr_cap: Vec<(String, BigNumber)>,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct CredentialPrimaryPublicKey {
    n: BigNumber,
    s: BigNumber,
    r: HashMap<String /* attr_name */, BigNumber>,
    rctxt: BigNumber,
    z: BigNumber,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct CredentialRevocationPublicKey {
    g: PointG1,
    g_dash: PointG2,
    h: PointG1,
    h0: PointG1,
    h1: PointG1,
    h2: PointG1,
    htilde: PointG1,
    h_cap: PointG2,
    u: PointG2,
    pk: PointG1,
    y: PointG2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CredentialSecretsBlindingFactors {
    v_prime: BigNumber,
    vr_prime: Option<GroupOrderElement>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CredentialSignature {
    p_credential: PrimaryCredentialSignature,
    r_credential: Option<NonRevocationCredentialSignature>, /* will be used to proof is credential revoked preparation */
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NonRevocationCredentialSignature {
    sigma: PointG1,
    c: GroupOrderElement,
    vr_prime_prime: GroupOrderElement,
    witness_signature: WitnessSignature,
    g_i: PointG1,
    i: u32,
    m2: GroupOrderElement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PrimaryCredentialSignature {
    m_2: BigNumber,
    a: BigNumber,
    e: BigNumber,
    v: BigNumber,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SignatureCorrectnessProof {
    se: BigNumber,
    c: BigNumber,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Witness {
    omega: PointG2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WitnessSignature {
    sigma_i: PointG2,
    u_i: PointG2,
    g_i: PointG1,
}
