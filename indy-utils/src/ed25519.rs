use ursa::keys::PublicKey;
use ursa::signatures::ed25519::Ed25519Sha512;

use super::validation::ValidationError;

pub fn vk_to_curve25519(vk: &[u8]) -> Result<Vec<u8>, ValidationError> {
    let vk = PublicKey(vk.to_vec());
    Ok(Ed25519Sha512::ver_key_to_key_exchange(&vk)
        .map_err(|err| invalid!("Error converting to curve25519 key: {}", err))?
        .0
        .clone())
}
