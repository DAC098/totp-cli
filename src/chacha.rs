use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305};
use hkdf::Hkdf;
use rand::TryRngCore;

use crate::error::{Error, ErrorKind, Result};

/// key length required for chacha encryption
pub const KEY_LEN: usize = 32;
/// nonce length required for chacha encryption
pub const NONCE_LEN: usize = 24;

pub type Key = [u8; KEY_LEN];
pub type Nonce = [u8; NONCE_LEN];

/// created a valid key from the variable length secret
///
/// used HKDF with SHA3_256 to create a valid length key for use in chacha
/// encryption
pub fn make_key<S>(secret: S) -> Result<Key>
where
    S: AsRef<[u8]>,
{
    let kdf: Hkdf<sha3::Sha3_256> = Hkdf::new(None, secret.as_ref());
    let mut output = [0u8; KEY_LEN];
    let info: [u8; 0] = [];

    if let Err(_err) = kdf.expand(&info, &mut output) {
        return Err(
            Error::new(ErrorKind::ChaChaError).with_message("failed to create a valid key length")
        );
    }

    Ok(output)
}

/// creates a random nonce of given size for chacha encryption
///
/// uses OsRng to fill the nonce array
pub fn make_nonce() -> Result<Nonce> {
    let mut nonce = [0u8; NONCE_LEN];

    rand::rngs::OsRng.try_fill_bytes(&mut nonce)?;

    Ok(nonce)
}

/// decrypts data using chacha
///
/// with the provided key and nonce, the data given will attempt to be
/// decrypted using XChaCha20Poly1305. returns the decrypted data as a
/// byte vector
pub fn decrypt_data<D>(key: &Key, nonce: &Nonce, data: D) -> Result<Vec<u8>>
where
    D: AsRef<[u8]>,
{
    let cipher = match XChaCha20Poly1305::new_from_slice(key) {
        Ok(c) => c,
        Err(err) => {
            return Err(Error::new(ErrorKind::ChaChaError)
                .with_message("length of provided key is invalid")
                .with_error(err))
        }
    };

    cipher.decrypt(nonce.into(), data.as_ref()).map_err(|err| {
        Error::new(ErrorKind::ChaChaError)
            .with_message("failed to decrypt requested data")
            .with_error(err)
    })
}

/// encrypts data using chacha
///
/// similar to the decrypt in terms of arguments and will, as the name implies,
/// encrypt the given data
pub fn encrypt_data<D>(key: &Key, nonce: &Nonce, data: D) -> Result<Vec<u8>>
where
    D: AsRef<[u8]>,
{
    let cipher = match XChaCha20Poly1305::new_from_slice(key) {
        Ok(c) => c,
        Err(err) => {
            return Err(Error::new(ErrorKind::ChaChaError)
                .with_message("length of provided key is invalid")
                .with_error(err))
        }
    };

    cipher.encrypt(nonce.into(), data.as_ref()).map_err(|err| {
        Error::new(ErrorKind::ChaChaError)
            .with_message("failed to encrypt requested data")
            .with_error(err)
    })
}
