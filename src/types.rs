use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::chacha;
use crate::otp;
use crate::error::{Result, Error, ErrorKind};
use crate::cli;

///default algo value for de/serialization
fn default_algo() -> otp::Algo {
    otp::Algo::SHA1
}

/// default digits value for de/serialization
fn default_digits() -> u32 {
    6
}

/// default step value for de/serialization
fn default_step() -> u64 {
    30
}

/// represents a totp credential
/// 
/// secret, algo, digits, and step are all required in order to properly
/// generate totp codes. the issuer and username are also provided to help
/// with identifying each record.
#[derive(Debug, Serialize, Deserialize)]
pub struct TotpRecord {
    pub secret: Vec<u8>,
    #[serde(default = "default_algo")]
    pub algo: otp::Algo,
    #[serde(default = "default_digits")]
    pub digits: u32,
    #[serde(default = "default_step")]
    pub step: u64,
    pub issuer: Option<String>,
    pub username: Option<String>,
}

/// type alias for hashmap records with a string name
pub type TotpRecordDict = HashMap<String, TotpRecord>;

/// accepted file types for a totp file
pub enum TotpFileType {
    JSON,
    YAML,
    TOTP,
}

/// a file that stores totp credentials
/// 
/// stores the path, file type, records, and potential cryptography key for a
/// desired file.
/// 
/// the path is assumed to be fully parsed(?) and lead to the actual location 
/// of the file in the system.
/// 
/// the key is used to decrypt and encrypt the file if necessary, only being 
/// stored so the user does not have to provide the password twice. it is not
/// the actual secret provided but what is generated from [chacha::make_key]
/// function
pub struct TotpFile {
    pub path: std::path::PathBuf,
    pub file_type: TotpFileType,
    pub records: TotpRecordDict,
    pub key: Option<chacha::Key>
}

impl TotpFile {

    /// attempts to parse and decrypt the data stored in the file
    /// 
    /// the nonce is stored in the first 24 bytes of the file. the rest is the
    /// encrypted data
    fn decrypt(key: &chacha::Key, data: Vec<u8>) -> Result<TotpRecordDict> {
        let mut encrypted: Vec<u8> = Vec::with_capacity(data.len() - chacha::NONCE_LEN);
        let mut nonce = [0u8; chacha::NONCE_LEN];
        let mut iter = data.into_iter();

        for i in 0..nonce.len() {
            if let Some(byte) = iter.next() {
                nonce[i] = byte;
            } else {
                return Err(Error::new(ErrorKind::ChaChaError)
                    .with_message("invalid file format for encrypted file"));
            }
        }

        while let Some(byte) = iter.next() {
            encrypted.push(byte);
        }

        let decrypted = chacha::decrypt_data(&key, &nonce, &encrypted)?;
        let records = serde_json::from_slice(&decrypted)?;

        Ok(records)
    }

    /// encrypts the given records
    /// 
    /// it will create a byte vector with the nonce stored in the first 24
    /// bytes and then store the encrypted data in the rest.
    fn encrypt(key: &chacha::Key, records: &TotpRecordDict) -> Result<Vec<u8>> {
        let nonce = chacha::make_nonce()?;
        let data = serde_json::to_vec(records)?;

        let encrypted = chacha::encrypt_data(&key, &nonce, &data)?;
        let mut contents = Vec::with_capacity(nonce.len() + encrypted.len());

        for byte in nonce {
            contents.push(byte);
        }

        for byte in encrypted {
            contents.push(byte);
        }

        Ok(contents)
    }

    /// helper to create an io reader for a given file
    #[inline]
    fn get_reader<P>(path: P) -> Result<impl std::io::Read>
    where
        P: AsRef<std::path::Path>
    {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(path)?;
        Ok(std::io::BufReader::new(file))
    }

    /// helper to create an io writer for a given file
    #[inline]
    fn get_writer<P>(path: P) -> Result<impl std::io::Write>
    where
        P: AsRef<std::path::Path>
    {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)?;
        Ok(std::io::BufWriter::new(file))
    }

    /// creates a TotpFile struct from a given path
    /// 
    /// if the file provided as a totp extension then it will treat it as an
    /// encrpyted file and will prompt the user for the secret used to
    /// encrypt the data on the file
    pub fn from_path<P>(path: P) -> Result<TotpFile>
    where
        P: AsRef<std::path::Path>
    {
        if let Some(ext) = path.as_ref().extension() {
            let ext = ext.to_ascii_lowercase();

            if ext.eq("yaml") || ext.eq("yml") {
                let records = serde_yml::from_reader(Self::get_reader(&path)?)?;

                Ok(TotpFile { 
                    path: path.as_ref().to_owned(),
                    file_type: TotpFileType::YAML,
                    records,
                    key: None,
                })
            } else if ext.eq("json") {
                let records = serde_json::from_reader(Self::get_reader(&path)?)?;

                Ok(TotpFile {
                    path: path.as_ref().to_owned(),
                    file_type: TotpFileType::JSON,
                    records,
                    key: None,
                })
            } else if ext.eq("totp") {
                let key = {
                    let secret = cli::get_input("secret")?;
                    chacha::make_key(&secret)?
                };
                let data = std::fs::read(&path)?;
                let records = Self::decrypt(&key, data)?;

                Ok(TotpFile {
                    path: path.as_ref().to_owned(),
                    file_type: TotpFileType::TOTP,
                    records,
                    key: Some(key),
                })
            } else {
                Err(Error::new(ErrorKind::InvalidExtension)
                    .with_message("unknown file extension given from path"))
            }
        } else {
            Err(Error::new(ErrorKind::InvalidExtension)
                .with_message("no file extension found for given path"))
        }
    }

    /// takes the records of the file and discards the rest
    pub fn take_records(self) -> TotpRecordDict {
        self.records
    }

    /// updates the file with the information stored
    /// 
    /// if the file was decrypted then it will attempt to encrypt the new data
    /// in the previous file
    pub fn update_file(&self) -> Result<()> {
        match self.file_type {
            TotpFileType::YAML => {
                serde_yml::to_writer(Self::get_writer(&self.path)?, &self.records)?;
            },
            TotpFileType::JSON => {
                serde_json::to_writer(Self::get_writer(&self.path)?, &self.records)?;
            },
            TotpFileType::TOTP => {
                let Some(key) = self.key.as_ref() else {
                    return Err(Error::new(ErrorKind::ChaChaError)
                        .with_message("missing key"))
                };

                let contents = Self::encrypt(key, &self.records)?;

                std::fs::write(&self.path, contents)?;
            }
        };

        Ok(())
    }
}
