use std::env::Args;

use crate::cli;
use crate::error;
use crate::types;

/// renames a record to a new name
///
/// options
///   -f | --file  the dsired file to rename a record in
///   --original   the original name of the record REQUIRED
///   --renamed    the new name of the record REQUIRED
pub fn run(mut args: Args) -> error::Result<()> {
    let mut file_path: Option<String> = None;
    let mut original: Option<String> = None;
    let mut renamed: Option<String> = None;

    loop {
        let Some(arg) = args.next() else {
            break;
        };

        match arg.as_str() {
            "-f" | "--file" => {
                file_path = Some(cli::get_arg_value(&mut args, "file")?);
            }
            "--original" => {
                original = Some(cli::get_arg_value(&mut args, "original")?);
            }
            "--renamed" => {
                renamed = Some(cli::get_arg_value(&mut args, "renamed")?);
            }
            _ => {
                return Err(error::build::invalid_argument(arg));
            }
        }
    }

    let path = cli::parse_file_path(file_path)?;
    let mut totp_file = types::TotpFile::from_path(path)?;

    let Some(original) = original else {
        return Err(error::Error::new(error::ErrorKind::MissingArgument)
            .with_message("original was not specified"));
    };

    let Some(renamed) = renamed else {
        return Err(error::Error::new(error::ErrorKind::MissingArgument)
            .with_message("renamed was not specified"));
    };

    let Some(record) = totp_file.records.remove(&original) else {
        return Err(error::build::name_not_found(original));
    };

    totp_file.records.insert(renamed, record);
    totp_file.update_file()?;

    Ok(())
}
