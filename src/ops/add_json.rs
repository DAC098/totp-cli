use std::env::Args;

use crate::error;
use crate::types;
use crate::cli;
use crate::print;

pub fn run(mut args: Args) -> error::Result<()> {
    let mut view_only = false;
    let mut file_path: Option<String> = None;
    let mut name: Option<String> = None;
    let mut json: Option<String> = None;

    loop {
        let Some(arg) = args.next() else {
            break;
        };

        match arg.as_str() {
            "-f" | "--file" => {
                file_path = Some(cli::get_arg_value(&mut args, "file")?)
            },
            "-n" | "--name" => {
                name = Some(cli::get_arg_value(&mut args, "name")?)
            },
            "-v" | "--view" => {
                view_only = true
            },
            "--json" => {
                json = Some(cli::get_arg_value(&mut args, "json")?)
            },
            _ => {
                return Err(error::build::invalid_argument(arg));
            }
        }
    }

    let path = cli::parse_file_path(file_path)?;
    let mut totp_file = types::TotpFile::from_path(path)?;

    let record: types::TotpRecord = if let Some(j) = json {
        serde_json::from_str(&j)?
    } else {
        return Err(error::Error::new(error::ErrorKind::JsonError)
            .with_message("given invalid json.
make sure that that all required fields are present and all values are valid.

secret: array u8
algo: string \"SHA1\", \"SHA256\", \"SHA512\"
      default \"SHA1\"
digits: u32 default 6
step: u64 default 30
issuer: string optional
username: string optional"));
    };

    let record_key = if let Some(name) = name {
        name
    } else {
        return Err(error::Error::new(error::ErrorKind::MissingArgument)
            .with_message("missing name argument"));
    };

    print::print_totp_record(&record_key, &record);

    if !view_only {
        totp_file.records.insert(record_key, record);
        totp_file.update_file()?;
    }

    Ok(())
}
