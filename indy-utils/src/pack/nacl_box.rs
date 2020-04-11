use crypto_box::{self as cbox, aead::Aead};
use ursa::blake2::{digest::Input, digest::VariableOutput, VarBlake2b};
use ursa::encryption::random_vec;

use crate::error::{ConversionError, UnexpectedError, ValidationError};
use crate::keys::{KeyType, SignKey};

const CBOX_NONCE_SIZE: usize = 24;

fn crypto_box_key<F, T>(key: F) -> Result<T, ValidationError>
where
    F: AsRef<[u8]>,
    T: From<[u8; cbox::KEY_SIZE]>,
{
    let key = key.as_ref();
    if key.len() != cbox::KEY_SIZE {
        Err(ValidationError::from("Invalid key length"))
    } else {
        let mut key_bytes = [0u8; cbox::KEY_SIZE];
        key_bytes.copy_from_slice(key);
        Ok(T::from(key_bytes))
    }
}

pub fn crypto_box_nonce(
    ephemeral_pk: &[u8],
    recip_pk: &[u8],
) -> Result<[u8; CBOX_NONCE_SIZE], UnexpectedError> {
    let mut key_hash = VarBlake2b::new(CBOX_NONCE_SIZE).map_err(|_| "Error creating hasher")?;
    key_hash.input(ephemeral_pk);
    key_hash.input(recip_pk);
    let mut nonce = [0u8; CBOX_NONCE_SIZE];
    key_hash.variable_result(|hash| nonce.clone_from_slice(hash));
    Ok(nonce)
}

pub fn crypto_box(
    recip_pk: &[u8],
    sender_sk: &[u8],
    message: &[u8],
    nonce: Option<Vec<u8>>,
) -> Result<(Vec<u8>, Vec<u8>), ConversionError> {
    let recip_pk: cbox::PublicKey = crypto_box_key(recip_pk)?;
    let sender_sk: cbox::SecretKey = crypto_box_key(sender_sk)?;
    let box_inst = cbox::SalsaBox::new(&recip_pk, &sender_sk);

    let nonce = if let Some(nonce) = nonce {
        nonce
    } else {
        random_vec(CBOX_NONCE_SIZE).map_err(|_| "Error calculating nonce")?
    };

    let ciphertext = box_inst
        .encrypt(nonce.as_slice().into(), message)
        .map_err(|_| "Error encrypting box")?;
    Ok((ciphertext, nonce))
}

pub fn crypto_box_open(
    recip_sk: &[u8],
    sender_pk: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, ConversionError> {
    let recip_sk: cbox::SecretKey = crypto_box_key(recip_sk)?;
    let sender_pk: cbox::PublicKey = crypto_box_key(sender_pk)?;
    let box_inst = cbox::SalsaBox::new(&sender_pk, &recip_sk);

    let plaintext = box_inst
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| "Error decrypting box")?;
    Ok(plaintext)
}

pub fn crypto_box_seal(recip_pk: &[u8], message: &[u8]) -> Result<Vec<u8>, ConversionError> {
    let sk = SignKey::generate(Some(KeyType::ED25519))?;
    let ephem_sk = sk.key_exchange()?;
    let ephem_sk_x: cbox::SecretKey = crypto_box_key(&ephem_sk)?;
    assert_eq!(ephem_sk_x.to_bytes(), ephem_sk.0.as_slice());
    let ephem_pk_x = ephem_sk_x.public_key();

    let nonce = crypto_box_nonce(ephem_pk_x.as_bytes(), &recip_pk)?.to_vec();
    let (mut boxed, _) = crypto_box(recip_pk, ephem_sk.0.as_slice(), message, Some(nonce))?;

    let mut result = Vec::<u8>::with_capacity(cbox::KEY_SIZE); // FIXME
    result.extend_from_slice(ephem_pk_x.as_bytes());
    result.append(&mut boxed);
    Ok(result)
}

pub fn crypto_box_seal_open(
    recip_pk: &[u8],
    recip_sk: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ConversionError> {
    let ephem_pk = &ciphertext[..32];
    let boxed = &ciphertext[32..];

    let nonce = crypto_box_nonce(&ephem_pk, &recip_pk)?;
    let decode = crypto_box_open(recip_sk, ephem_pk, boxed, &nonce)?;
    Ok(decode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_box() {
        let sk = hex::decode("07d0b594683bdb6af5f4eacb1a392687d580a58db196a752dca316dedb7d251d")
            .unwrap();
        let pk = hex::decode("07d0b594683bdb6af5f4eacb1a392687d580a58db196a752dca316dedb7d251c")
            .unwrap();
        let message = b"hello there";
        // let nonce = b"012345678912012345678912".to_vec();
        let (boxed, nonce) = crypto_box(&pk, &sk, message, None).unwrap();

        let open = crypto_box_open(&sk, &pk, &boxed, &nonce).unwrap();
        assert_eq!(open, message);
    }

    #[test]
    fn test_box_seal() {
        // let sk = SignKey::generate(Some(KeyType::ED25519)).unwrap();
        let sk = SignKey::from_seed(b"000000000000000000000000000Test0").unwrap();
        let pk_x = sk.public_key().unwrap().key_exchange().unwrap();
        let sk_x = sk.key_exchange().unwrap();

        let message = b"hello there";
        let sealed = crypto_box_seal(&pk_x.0, message).unwrap();

        let open = crypto_box_seal_open(&pk_x.0, &sk_x.0, &sealed).unwrap();
        assert_eq!(open, message);
    }
}
