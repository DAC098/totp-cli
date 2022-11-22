use chacha20poly1305::{XChaCha20Poly1305, aead::Aead, KeyInit};
use hkdf::Hkdf;
use rand::RngCore;

use crate::error::{Result, Error, ErrorKind};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

pub type Key = [u8; KEY_LEN];
pub type Nonce = [u8; NONCE_LEN];

pub fn make_key<S>(secret: S) -> Result<Key>
where
    S: AsRef<[u8]>
{
    let kdf: Hkdf<sha3::Sha3_256> = Hkdf::new(None, secret.as_ref());
    let mut output = [0u8; KEY_LEN];
    let info: [u8; 0] = [];

    if let Err(_err) = kdf.expand(&info, &mut output) {
        return Err(Error::new(ErrorKind::ChaChaError)
            .with_message("failed to create a valid key length"))
    }

    Ok(output)
}

pub fn make_nonce() -> Result<Nonce> {
    let mut nonce = [0u8; NONCE_LEN];

    rand::rngs::OsRng.fill_bytes(&mut nonce);

    Ok(nonce)
}

pub fn decrypt_data<D>(
    key: &Key,
    nonce: &Nonce,
    data: D
) -> Result<Vec<u8>>
where
    D: AsRef<[u8]>
{
    let cipher = match XChaCha20Poly1305::new_from_slice(key) {
        Ok(c) => c,
        Err(err) => {
            return Err(Error::new(ErrorKind::ChaChaError)
                .with_message("length of provided key is invalid")
                .with_error(err))
        }
    };

    cipher.decrypt(nonce.into(), data.as_ref())
        .map_err(|err| {
            Error::new(ErrorKind::ChaChaError)
                .with_message("failed to decrypt requested data")
                .with_error(err)
        })
}

pub fn encrypt_data<D>(
    key: &Key,
    nonce: &Nonce,
    data: D
) -> Result<Vec<u8>>
where
    D: AsRef<[u8]>
{
    let cipher = match XChaCha20Poly1305::new_from_slice(key) {
        Ok(c) => c,
        Err(err) => {
            return Err(Error::new(ErrorKind::ChaChaError)
                .with_message("length of provided key is invalid")
                .with_error(err))
        }
    };

    cipher.encrypt(nonce.into(), data.as_ref())
        .map_err(|err| {
            Error::new(ErrorKind::ChaChaError)
                .with_message("failed to encrypt requested data")
                .with_error(err)
        })
}