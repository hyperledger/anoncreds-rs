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
    use crate::EmbedExtract;

    impl EmbedExtract for super::BlindedCredentialSecrets {
        type Inner = crate::ursa::cl::BlindedCredentialSecrets;
    }

    impl EmbedExtract for super::BlindedCredentialSecretsCorrectnessProof {
        type Inner = crate::ursa::cl::BlindedCredentialSecretsCorrectnessProof;
    }

    impl EmbedExtract for super::CredentialKeyCorrectnessProof {
        type Inner = crate::ursa::cl::CredentialKeyCorrectnessProof;
    }

    impl EmbedExtract for super::CredentialPrimaryPublicKey {
        type Inner = crate::ursa::cl::CredentialPrimaryPublicKey;
    }

    impl EmbedExtract for super::CredentialRevocationPublicKey {
        type Inner = crate::ursa::cl::CredentialRevocationPublicKey;
    }

    impl EmbedExtract for super::CredentialSignature {
        type Inner = crate::ursa::cl::CredentialSignature;
    }

    impl EmbedExtract for super::MasterSecret {
        type Inner = crate::ursa::cl::MasterSecret;
    }

    impl EmbedExtract for super::Proof {
        type Inner = crate::ursa::cl::Proof;
    }

    impl EmbedExtract for super::RevocationKeyPublic {
        type Inner = crate::ursa::cl::RevocationKeyPublic;
    }

    impl EmbedExtract for super::RevocationRegistry {
        type Inner = crate::ursa::cl::RevocationRegistry;
    }

    impl EmbedExtract for super::RevocationRegistryDelta {
        type Inner = crate::ursa::cl::RevocationRegistryDelta;
    }

    impl EmbedExtract for super::SignatureCorrectnessProof {
        type Inner = crate::ursa::cl::SignatureCorrectnessProof;
    }

    impl EmbedExtract for super::Witness {
        type Inner = crate::ursa::cl::Witness;
    }

    impl EmbedExtract for super::WitnessSignature {
        type Inner = crate::ursa::cl::WitnessSignature;
    }
}
