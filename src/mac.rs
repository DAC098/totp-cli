use hmac::{Mac, Hmac};

#[derive(Debug)]
pub enum Error {
    InvalidKeyLength
}

pub type Result<T> = std::result::Result<T, Error>;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidKeyLength => write!(f, "given key is an invalid length")
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl From<hmac::digest::InvalidLength> for Error {
    fn from(_: hmac::digest::InvalidLength) -> Self {
        Error::InvalidKeyLength
    }
}

macro_rules! hmac_methods {
    ($make:ident, $once:ident, $verify:ident, $e:path) => {
        /// create a new hmac
        fn $make(secret: &[u8], data: &[u8])-> Result<Hmac<$e>> {
            let mut mac = Hmac::new_from_slice(secret)?;
            mac.update(data);
            Ok(mac)
        }

        /// a one off hmac
        pub fn $once(secret: &[u8], data: &[u8]) -> Result<Vec<u8>> {
            let result = $make(secret, data)?.finalize();
            let bytes = result.into_bytes();
            Ok(bytes.to_vec())
        }

        // verify a given hmac
        // pub fn $verify(secret: &[u8], data: &[u8], mac: &[u8]) -> Result<bool> {
        //     let result = $make(secret, data)?;

        //     Ok(match result.verify_slice(mac) {
        //         Ok(()) => true,
        //         Err(_e) => false
        //     })
        // }
    };
}

hmac_methods!(make_sha1, one_off_sha1, one_off_verify_sha1, sha1::Sha1);
hmac_methods!(make_sha256, one_off_sha256, one_off_verify_sha256, sha3::Sha3_256);
hmac_methods!(make_sha512, one_off_sha512, one_off_verify_sha512, sha3::Sha3_512);