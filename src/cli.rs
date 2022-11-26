use std::io::Write;
use std::{path::PathBuf, env::Args};

use crate::error;
use crate::otp;

/// gets the canonicalized version of the given path
pub fn get_full_path(path: PathBuf) -> error::Result<PathBuf> {
    let to_check = if !path.is_absolute() {
        let mut cwd = std::env::current_dir()?;
        cwd.push(path);
        cwd
    } else {
        path
    };

    let rtn = std::fs::canonicalize(to_check)?;

    Ok(rtn)
}

/// default file path for a records file
pub fn get_default_file_path() -> error::Result<PathBuf> {
    let mut cwd = std::env::current_dir()?;
    cwd.push("records.yaml");
    Ok(cwd)
}

/// parses the option command line argument for a file path
pub fn parse_file_path(path: Option<String>) -> error::Result<PathBuf> {
    if let Some(p) = path {
        get_full_path(PathBuf::from(p))
    } else {
        get_default_file_path()
    }
}

/// parses a BASE32 encoded string
pub fn parse_secret<S>(secret: S) -> error::Result<Vec<u8>>
where
    S: AsRef<[u8]>
{
    match data_encoding::BASE32.decode(secret.as_ref()) {
        Ok(s) => Ok(s),
        Err(err) => {
            Err(error::Error::new(error::ErrorKind::InvalidArgument)
                .with_message("key is an invalid base32 value")
                .with_error(err))
        }
    }
}

/// parses a string to a valid [Algo]
pub fn parse_algo<A>(algo: A) -> error::Result<otp::Algo>
where
    A: AsRef<str>
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
    D: AsRef<str>
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
    S: AsRef<str>
{
    if let Ok(parsed) = u64::from_str_radix(step.as_ref(), 10) {
        Ok(parsed)
    } else {
        return Err(error::Error::new(error::ErrorKind::InvalidArgument)
            .with_message("step/period is not a valid unsiged integer"))
    }
}

/// attempts to retrieve the next argument
/// 
/// if the argument is not present then it will return an error indicating the
/// argument is missing and provide the name of the argument
pub fn get_arg_value<N>(args: &mut Args, name: N) -> error::Result<String>
where
    N: AsRef<str>
{
    let Some(v) = args.next() else {
        let mut msg = String::from("missing ");
        msg.push_str(name.as_ref());
        msg.push_str(" argument value");

        return Err(error::Error::new(error::ErrorKind::MissingArgument)
            .with_message(msg))
    };

    Ok(v)
}

/// prompts the user for input with a given message
pub fn get_input<M>(message: M) -> error::Result<String>
where
    M: AsRef<str>
{
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut input = String::new();

    write!(&mut stdout, "{}: ", message.as_ref())?;
    stdout.flush()?;
    stdin.read_line(&mut input)?;

    Ok(input)
}