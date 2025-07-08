use serde::{Deserialize, Serialize};

use super::mac;

/// default step for totp
pub const _DEFAULT_STEP: u64 = 30;
/// default digit legnth for totp
pub const _DEFAULT_DIGITS: u32 = 8;

/// the available algorithms for otp
#[derive(Debug, Clone, Serialize, Deserialize, clap::ValueEnum)]
#[value(rename_all = "UPPER")]
pub enum Algo {
    SHA1,
    SHA256,
    SHA512,
}

impl Algo {
    /// attempts to return an Algo from the given string
    ///
    /// using an error here to be consistent with the TrimFrom impls
    pub fn try_from_str<S>(v: S) -> std::result::Result<Algo, ()>
    where
        S: AsRef<str>,
    {
        match v.as_ref() {
            "SHA1" => Ok(Algo::SHA1),
            "SHA256" => Ok(Algo::SHA256),
            "SHA512" => Ok(Algo::SHA512),
            _ => Err(()),
        }
    }

    /// returns the string representation of the Algo
    pub fn as_str(&self) -> &str {
        match self {
            Algo::SHA1 => "SHA1",
            Algo::SHA256 => "SHA256",
            Algo::SHA512 => "SHA512",
        }
    }

    /// returns the owned string representation of the algo
    pub fn into_string(self) -> String {
        self.as_str().to_owned()
    }
}

impl TryFrom<&str> for Algo {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from_str(value)
    }
}

impl TryFrom<String> for Algo {
    type Error = ();

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from_str(value)
    }
}

impl Into<String> for Algo {
    fn into(self) -> String {
        self.into_string()
    }
}

/// runs the actual mac algorithm specified
fn one_off(algo: &Algo, secret: &[u8], data: &[u8]) -> mac::Result<Vec<u8>> {
    match algo {
        Algo::SHA1 => mac::one_off_sha1(secret, data),
        Algo::SHA256 => mac::one_off_sha256(secret, data),
        Algo::SHA512 => mac::one_off_sha512(secret, data),
    }
}

/// simple string padding given a string and total digits
///
/// this will not truncate the string and will just return if the given string
/// is big enough or is equal to the given digits
fn pad_string(uint_string: String, digits: usize) -> String {
    if uint_string.len() < digits {
        let mut rtn = String::with_capacity(digits);

        for _ in 0..(digits - uint_string.len()) {
            rtn.push('0');
        }

        rtn.push_str(&uint_string);
        rtn
    } else {
        uint_string
    }
}

/// generate integer string for otp algorithms
///
/// creates the integer string for the given algorithm. will pad the string
/// if it is not long enough for the given amount of digits.
pub fn generate_integer_string(
    algorithm: &Algo,
    secret: &[u8],
    digits: u32,
    data: &[u8],
) -> String {
    let hash = one_off(algorithm, secret, data).unwrap();

    let offset = (hash[hash.len() - 1] & 0xf) as usize;
    let binary = ((hash[offset] & 0x7f) as u64) << 24
        | (hash[offset + 1] as u64) << 16
        | (hash[offset + 2] as u64) << 8
        | (hash[offset + 3] as u64);

    let uint_string = (binary % 10u64.pow(digits)).to_string();
    let digits = digits as usize;

    pad_string(uint_string, digits)
}

/// create an hotp hash
pub fn _hotp<S>(secret: S, digits: u32, counter: u64) -> String
where
    S: AsRef<[u8]>,
{
    let counter_bytes = counter.to_be_bytes();

    generate_integer_string(&Algo::SHA1, secret.as_ref(), digits, &counter_bytes)
}

/// create an totp hash
pub fn _totp<S>(algorithm: &Algo, secret: S, digits: u32, step: u64, time: u64) -> String
where
    S: AsRef<[u8]>,
{
    let data = (time / step).to_be_bytes();

    generate_integer_string(algorithm, secret.as_ref(), digits, &data)
}
