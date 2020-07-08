mod nonce;

pub use nonce::Nonce;

pub struct BlindedCredentialSecrets;

pub struct BlindedCredentialSecretsCorrectnessProof;

pub struct CredentialKeyCorrectnessProof;

pub struct CredentialPrimaryPublicKey;

pub struct CredentialRevocationPublicKey;

pub struct CredentialSecretsBlindingFactors;

pub struct CredentialSignature;

pub struct MasterSecret;

pub struct Proof;

pub struct RevocationKeyPublic;

pub struct RevocationRegistry;

pub struct RevocationRegistryDelta;

pub struct SignatureCorrectnessProof;

pub struct Witness;

pub struct WitnessSignature;

#[cfg(all(feature = "serde", any(feature = "cl", feature = "cl_native")))]
mod cl {
    use crate::EmbedExtractJson;

    impl EmbedExtractJson for super::BlindedCredentialSecrets {
        type Inner = crate::ursa::cl::BlindedCredentialSecrets;
    }

    impl EmbedExtractJson for super::BlindedCredentialSecretsCorrectnessProof {
        type Inner = crate::ursa::cl::BlindedCredentialSecretsCorrectnessProof;
    }

    impl EmbedExtractJson for super::CredentialKeyCorrectnessProof {
        type Inner = crate::ursa::cl::CredentialKeyCorrectnessProof;
    }

    impl EmbedExtractJson for super::CredentialPrimaryPublicKey {
        type Inner = crate::ursa::cl::CredentialPrimaryPublicKey;
    }

    impl EmbedExtractJson for super::CredentialRevocationPublicKey {
        type Inner = crate::ursa::cl::CredentialRevocationPublicKey;
    }

    impl EmbedExtractJson for super::CredentialSignature {
        type Inner = crate::ursa::cl::CredentialSignature;
    }

    impl EmbedExtractJson for super::MasterSecret {
        type Inner = crate::ursa::cl::MasterSecret;
    }

    impl EmbedExtractJson for super::Proof {
        type Inner = crate::ursa::cl::Proof;
    }

    impl EmbedExtractJson for super::RevocationKeyPublic {
        type Inner = crate::ursa::cl::RevocationKeyPublic;
    }

    impl EmbedExtractJson for super::RevocationRegistry {
        type Inner = crate::ursa::cl::RevocationRegistry;
    }

    impl EmbedExtractJson for super::RevocationRegistryDelta {
        type Inner = crate::ursa::cl::RevocationRegistryDelta;
    }

    impl EmbedExtractJson for super::SignatureCorrectnessProof {
        type Inner = crate::ursa::cl::SignatureCorrectnessProof;
    }

    impl EmbedExtractJson for super::Witness {
        type Inner = crate::ursa::cl::Witness;
    }

    impl EmbedExtractJson for super::WitnessSignature {
        type Inner = crate::ursa::cl::WitnessSignature;
    }
}
