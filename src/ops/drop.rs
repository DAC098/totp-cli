use std::env::Args;

use crate::error;
use crate::types;
use crate::cli;

/// drops a record from a totp file
/// 
/// options
///   -f | --file  the desired file to drop a record from
///   -n | --name  the name of the record to drop REQUIRED
pub fn run(mut args: Args) -> error::Result<()> {
    let mut file_path: Option<String> = None;
    let mut name: Option<String> = None;

    loop {
        let Some(arg) = args.next() else {
            break;
        };

        match arg.as_str() {
            "-f" | "--file" => {
                file_path = Some(cli::get_arg_value(&mut args, "file")?);
            },
            "-n" | "--name" => {
                name = Some(cli::get_arg_value(&mut args, "name")?);
            },
            _ => {
                return Err(error::build::invalid_argument(arg));
            }
        }
    }

    let path = cli::parse_file_path(file_path)?;
    let mut totp_file = types::TotpFile::from_path(path)?;

    let Some(name) = name else {
        return Err(error::Error::new(error::ErrorKind::MissingArgument)
            .with_message("name was not specified"));
    };

    let Some(_record) = totp_file.records.remove(&name) else {
        return Err(error::build::name_not_found(name));
    };

    totp_file.update_file()?;

    Ok(())
}