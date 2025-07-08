use std::io::Write;
use std::path::PathBuf;

use crate::error;
use crate::otp;
use crate::path;

#[derive(Debug, clap::Args)]
pub struct RecordFile {
    /// specifies which file to open and view codes for
    #[arg(short, long = "file")]
    path: Option<PathBuf>,
}

impl RecordFile {
    pub fn get_file(&self) -> error::Result<PathBuf> {
        if let Some(path) = &self.path {
            let rtn = if !path.is_absolute() {
                let cwd = std::env::current_dir()?;

                path::normalize_from(&cwd, &path)
            } else {
                path.clone()
            };

            Ok(rtn)
        } else {
            let cwd = std::env::current_dir()?;

            Ok(cwd.join("records.totp"))
        }
    }
}

#[derive(Debug, Clone)]
pub struct Base32(pub Vec<u8>);

impl std::str::FromStr for Base32 {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match data_encoding::BASE32.decode(s.as_bytes()) {
            Ok(s) => Ok(Self(s)),
            Err(_) => Err("invalid BASE32 string"),
        }
    }
}

impl From<Base32> for Vec<u8> {
    fn from(value: Base32) -> Self {
        value.0
    }
}

/// parses a BASE32 encoded string
pub fn parse_secret<S>(secret: S) -> error::Result<Vec<u8>>
where
    S: AsRef<[u8]>,
{
    match data_encoding::BASE32.decode(secret.as_ref()) {
        Ok(s) => Ok(s),
        Err(err) => Err(error::Error::new(error::ErrorKind::InvalidArgument)
            .with_message("key is an invalid base32 value")
            .with_error(err)),
    }
}

/// parses a string to a valid [Algo]
pub fn parse_algo<A>(algo: A) -> error::Result<otp::Algo>
where
    A: AsRef<str>,
{
    if let Ok(v) = otp::Algo::try_from_str(algo) {
        Ok(v)
    } else {
        Err(error::Error::new(error::ErrorKind::InvalidArgument)
            .with_message("given value for algo is invalid"))
    }
}

/// parses a string to a valid u32
pub fn parse_digits<D>(digits: D) -> error::Result<u32>
where
    D: AsRef<str>,
{
    if let Ok(parsed) = u32::from_str_radix(digits.as_ref(), 10) {
        Ok(parsed)
    } else {
        Err(error::Error::new(error::ErrorKind::InvalidArgument)
            .with_message("digits is not a valid unsiged integer"))
    }
}

/// parses a string to a valid u64
pub fn parse_step<S>(step: S) -> error::Result<u64>
where
    S: AsRef<str>,
{
    if let Ok(parsed) = u64::from_str_radix(step.as_ref(), 10) {
        Ok(parsed)
    } else {
        return Err(error::Error::new(error::ErrorKind::InvalidArgument)
            .with_message("step/period is not a valid unsiged integer"));
    }
}

/// prompts the user for input with a given message
pub fn get_input<M>(message: M) -> error::Result<String>
where
    M: AsRef<str>,
{
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut input = String::new();

    write!(&mut stdout, "{}: ", message.as_ref())?;
    stdout.flush()?;
    stdin.read_line(&mut input)?;

    Ok(input)
}
