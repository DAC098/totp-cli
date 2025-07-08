use std::collections::HashMap;
use std::env::Args;
use std::path::PathBuf;

use crate::chacha;
use crate::cli;
use crate::error;
use crate::types;

/// genrates a new encrpyted totp file
///
/// options
///   -d | --directory  the specified directory to create the new file
///   -n | --name       the name of the file REQUIRED
///
/// the user will be prompted to enter in a secret used to encrypt the file
/// specified
pub fn run(mut args: Args) -> error::Result<()> {
    let mut name: Option<String> = None;
    let mut dir: Option<String> = None;

    loop {
        let Some(arg) = args.next() else {
            break;
        };

        match arg.as_str() {
            "-d" | "--directory" => {
                dir = Some(cli::get_arg_value(&mut args, "directory")?);
            }
            "-n" | "--name" => name = Some(cli::get_arg_value(&mut args, "name")?),
            _ => {
                return Err(error::build::invalid_argument(arg));
            }
        }
    }

    let mut file_path = if let Some(d) = dir {
        let path = cli::get_full_path(PathBuf::from(d))?;

        if !path.exists() {
            return Err(error::Error::new(error::ErrorKind::InvalidArgument)
                .with_message("the given directory does not exist"));
        } else if !path.is_dir() {
            return Err(error::Error::new(error::ErrorKind::InvalidArgument)
                .with_message("the given directory is not a valid directory"));
        }

        path
    } else {
        std::env::current_dir()?
    };

    let Some(mut name) = name else {
        return Err(error::Error::new(error::ErrorKind::MissingArgument)
            .with_message("no name was specified"));
    };

    name.push_str(".totp");

    file_path.push(name);

    if file_path.exists() {
        return Err(error::Error::new(error::ErrorKind::InvalidArgument)
            .with_message("the specified file already exists"));
    }

    let secret = cli::get_input("secret")?;
    let key = chacha::make_key(secret)?;

    let totp_file = types::TotpFile {
        path: file_path,
        file_type: types::TotpFileType::TOTP,
        records: HashMap::new(),
        key: Some(key),
    };

    totp_file.update_file()?;

    Ok(())
}
