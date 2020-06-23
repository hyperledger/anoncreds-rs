use ursa::encryption::symm::chacha20poly1305::ChaCha20Poly1305;
use ursa::encryption::symm::{Encryptor, SymmetricEncryptor};
use ursa::keys::PrivateKey;

use std::string::ToString;

use super::nacl_box::*;
use super::types::*;
use crate::base64;
use crate::error::ConversionError;
use crate::keys::{EncodedVerKey, KeyEncoding, SignKey};

pub const PROTECTED_HEADER_ENC: &'static str = "xchacha20poly1305_ietf";
pub const PROTECTED_HEADER_TYP: &'static str = "JWM/1.0";
pub const PROTECTED_HEADER_ALG_AUTH: &'static str = "Authcrypt";
pub const PROTECTED_HEADER_ALG_ANON: &'static str = "Anoncrypt";

const TAG_SIZE: usize = 16;

pub fn pack_message<M: AsRef<[u8]>>(
    message: M,
    receiver_list: Vec<EncodedVerKey>,
    sender_key: Option<SignKey>,
) -> Result<Vec<u8>, ConversionError> {
    // break early and error out if no receivers keys are provided
    if receiver_list.is_empty() {
        return Err("No message recipients".into());
    }

    // generate content encryption key that will encrypt `message`
    let cek = PrivateKey(
        ChaCha20Poly1305::key_gen()
            .map_err(|_| "Error creating box encryption key")?
            .to_vec(),
    );

    let base64_protected = if let Some(sender_key) = sender_key {
        // returns authcrypted pack_message format. See Wire message format HIPE for details
        _prepare_protected_authcrypt(&cek, receiver_list, &sender_key)?
    } else {
        // returns anoncrypted pack_message format. See Wire message format HIPE for details
        _prepare_protected_anoncrypt(&cek, receiver_list)?
    };

    // Use AEAD to encrypt `message` with "protected" data as "associated data"
    let nonce = ChaCha20Poly1305::nonce_gen().map_err(|_| "Error creating nonce")?;
    let symm = SymmetricEncryptor::<ChaCha20Poly1305>::new_with_key(cek.as_ref())
        .map_err(|_| "Error creating encryptor")?;
    let ciphertext = symm
        .encrypt(
            nonce.as_ref(),
            base64_protected.as_bytes(),
            message.as_ref(),
        )
        .map_err(|_| "Error encrypting payload")?;
    let iv = base64::encode_urlsafe(nonce);
    let clen = ciphertext.len() - TAG_SIZE;
    let tag = base64::encode_urlsafe(&ciphertext[clen..]);
    let ciphertext = base64::encode_urlsafe(&ciphertext[..clen]);

    _format_pack_message(&base64_protected, &ciphertext, &iv, &tag)
}

fn _prepare_protected_anoncrypt(
    cek: &PrivateKey,
    receiver_list: Vec<EncodedVerKey>,
) -> Result<String, ConversionError> {
    let mut encrypted_recipients_struct: Vec<Recipient> = Vec::with_capacity(receiver_list.len());

    for their_vk in receiver_list {
        // encrypt cek for recipient
        let their_vk_x = their_vk.key_exchange()?;
        let enc_cek = crypto_box_seal(their_vk_x.as_ref(), cek.as_ref())?;

        // create recipient struct and push to encrypted list
        encrypted_recipients_struct.push(Recipient {
            encrypted_key: base64::encode_urlsafe(enc_cek.as_slice()),
            header: Header {
                kid: their_vk.to_string(),
                sender: None,
                iv: None,
            },
        });
    }

    _base64_encode_protected(encrypted_recipients_struct, false)
}

fn _prepare_protected_authcrypt(
    cek: &PrivateKey,
    receiver_list: Vec<EncodedVerKey>,
    sender_key: &SignKey,
) -> Result<String, ConversionError> {
    let mut encrypted_recipients_struct: Vec<Recipient> = vec![];

    let sender_key_x = sender_key.key_exchange()?;
    let sender_pk = sender_key.public_key()?.encode(KeyEncoding::BASE58)?;

    for their_vk in receiver_list {
        let their_vk_x = their_vk.key_exchange()?;

        // encrypt cek for recipient
        let (enc_cek, iv) = crypto_box(their_vk_x.as_ref(), sender_key_x.as_ref(), &cek[..], None)?;

        // encrypt sender key for recipient
        let enc_sender = crypto_box_seal(their_vk_x.as_ref(), sender_pk.encoded_key_bytes())?;

        // create recipient struct and push to encrypted list
        encrypted_recipients_struct.push(Recipient {
            encrypted_key: base64::encode_urlsafe(enc_cek.as_slice()),
            header: Header {
                kid: their_vk.to_string(),
                sender: Some(base64::encode_urlsafe(enc_sender.as_slice())),
                iv: Some(base64::encode_urlsafe(iv.as_slice())),
            },
        });
    }

    _base64_encode_protected(encrypted_recipients_struct, true)
}

fn _base64_encode_protected(
    encrypted_recipients_struct: Vec<Recipient>,
    alg_is_authcrypt: bool,
) -> Result<String, ConversionError> {
    let alg_val = if alg_is_authcrypt {
        String::from(PROTECTED_HEADER_ALG_AUTH)
    } else {
        String::from(PROTECTED_HEADER_ALG_ANON)
    };

    // structure protected and base64URL encode it
    let protected_struct = Protected {
        enc: PROTECTED_HEADER_ENC.to_string(),
        typ: PROTECTED_HEADER_TYP.to_string(),
        alg: alg_val,
        recipients: encrypted_recipients_struct,
    };
    let protected_encoded = serde_json::to_string(&protected_struct)
        .map_err(|err| format!("Failed to serialize protected field {}", err))?;

    Ok(base64::encode_urlsafe(protected_encoded.as_bytes()))
}

fn _format_pack_message(
    base64_protected: &str,
    ciphertext: &str,
    iv: &str,
    tag: &str,
) -> Result<Vec<u8>, ConversionError> {
    // serialize pack message and return as vector of bytes
    let jwe_struct = JWE {
        protected: base64_protected.to_string(),
        iv: iv.to_string(),
        ciphertext: ciphertext.to_string(),
        tag: tag.to_string(),
    };

    Ok(serde_json::to_vec(&jwe_struct)?)
}

pub async fn unpack_message<M: AsRef<[u8]>>(
    message: M,
    lookup: impl KeyLookup,
) -> Result<(Vec<u8>, EncodedVerKey, Option<EncodedVerKey>), ConversionError> {
    let jwe = serde_json::from_slice(message.as_ref())?;
    unpack_jwe(&jwe, lookup).await
}

pub async fn unpack_jwe(
    jwe_struct: &JWE,
    lookup: impl KeyLookup,
) -> Result<(Vec<u8>, EncodedVerKey, Option<EncodedVerKey>), ConversionError> {
    // decode protected data
    let protected_decoded = base64::decode_urlsafe(&jwe_struct.protected)?;
    let protected: Protected = serde_json::from_slice(&protected_decoded)?;

    // extract recipient that matches a key in the wallet
    let (recipient, recip_pk, recip_sk) = unwrap_opt_or_return!(
        _find_unpack_recipient(protected, lookup).await?,
        Err("No matching recipient found".into())
    );
    let is_auth_recipient = recipient.header.sender.is_some() && recipient.header.iv.is_some();

    // get cek and sender data
    let (sender_verkey_option, cek) = if is_auth_recipient {
        let (send, cek) = _unpack_cek_authcrypt(&recipient, &recip_sk)?;
        (Some(send), cek)
    } else {
        let cek = _unpack_cek_anoncrypt(&recipient, &recip_sk)?;
        (None, cek)
    };

    // decrypt message
    let symm = SymmetricEncryptor::<ChaCha20Poly1305>::new_with_key(&cek)
        .map_err(|_| "Error creating encryptor")?;
    let nonce = base64::decode_urlsafe(&jwe_struct.iv)?;
    let mut payload = base64::decode_urlsafe(&jwe_struct.ciphertext)?;
    payload.append(base64::decode_urlsafe(&jwe_struct.tag)?.as_mut());
    let message = symm
        .decrypt(
            nonce.as_slice(),
            jwe_struct.protected.as_bytes(),
            payload.as_slice(),
        )
        .map_err(|_| "Error decrypting message payload")?;

    Ok((message, recip_pk, sender_verkey_option))
}

fn _unpack_cek_authcrypt(
    recipient: &Recipient,
    recip_sk: &SignKey,
) -> Result<(EncodedVerKey, Vec<u8>), ConversionError> {
    let encrypted_key_vec = base64::decode_urlsafe(&recipient.encrypted_key)?;
    let iv = base64::decode_urlsafe(&recipient.header.iv.as_ref().unwrap())?;
    let enc_sender_vk = base64::decode_urlsafe(&recipient.header.sender.as_ref().unwrap())?;

    // decrypt sender_vk
    let recip_pk = recip_sk.public_key()?;
    let sender_vk_vec = crypto_box_seal_open(
        recip_pk.key_exchange()?.as_ref(),
        recip_sk.key_exchange()?.as_ref(),
        &enc_sender_vk,
    )?;
    let sender_vk = EncodedVerKey::from_slice(&sender_vk_vec)?;

    // decrypt cek
    let cek = crypto_box_open(
        recip_sk.key_exchange()?.as_ref(),
        sender_vk.key_exchange()?.as_ref(),
        encrypted_key_vec.as_slice(),
        iv.as_slice(),
    )?;

    Ok((sender_vk, cek))
}

fn _unpack_cek_anoncrypt(
    recipient: &Recipient,
    recip_sk: &SignKey,
) -> Result<Vec<u8>, ConversionError> {
    let encrypted_key = base64::decode_urlsafe(&recipient.encrypted_key)?;

    // decrypt cek
    let recip_pk = ursa::keys::PublicKey(recip_sk.public_key()?.key_bytes());
    let cek = crypto_box_seal_open(recip_pk.as_ref(), recip_sk.as_ref(), &encrypted_key)?;

    Ok(cek)
}

async fn _find_unpack_recipient(
    protected: Protected,
    lookup: impl KeyLookup,
) -> Result<Option<(Recipient, EncodedVerKey, SignKey)>, ConversionError> {
    let mut recip_vks = Vec::<EncodedVerKey>::with_capacity(protected.recipients.len());
    for recipient in &protected.recipients {
        let vk = EncodedVerKey::from_str(&recipient.header.kid)?;
        recip_vks.push(vk);
    }
    if let Some((idx, sk)) = lookup.find(&recip_vks).await {
        let recip = protected.recipients.into_iter().nth(idx).unwrap();
        let vk = recip_vks.into_iter().nth(idx).unwrap();
        Ok(Some((recip, vk, sk)))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use futures_executor::block_on;

    use super::*;

    #[test]
    fn test_pack() {
        let sk = SignKey::from_seed(b"000000000000000000000000000Test1").unwrap();
        let pk = SignKey::from_seed(b"000000000000000000000000000Test2")
            .unwrap()
            .public_key()
            .unwrap()
            .as_base58()
            .unwrap();

        let packed = pack_message(b"hello there", vec![pk], Some(sk));
        assert!(packed.is_ok());
    }

    #[test]
    fn test_round_trip() {
        let sk1 = SignKey::from_seed(b"000000000000000000000000000Test3").unwrap();
        let sk2 = SignKey::from_seed(b"000000000000000000000000000Test4").unwrap();
        let pk2 = sk2.public_key().unwrap().as_base58().unwrap();

        let input_msg = b"hello there";
        let packed = pack_message(&input_msg, vec![pk2.clone()], Some(sk1.clone())).unwrap();

        let lookup = |find_pks: &Vec<EncodedVerKey>| {
            for (idx, pk) in find_pks.into_iter().enumerate() {
                if pk == &pk2 {
                    return Some((idx, sk2.clone()));
                }
            }
            None
        };

        let lookup_fn = key_lookup_fn(lookup);
        let result = unpack_message(&packed, lookup_fn);
        let (msg, _recip_key, _sender_key) = block_on(result).unwrap();
        assert_eq!(msg, input_msg);
    }
}
