use std::env::Args;

use crate::cli;
use crate::error;
use crate::print;
use crate::types;
use crate::util;

/// views records of a totp file
///
/// options
///   -n | --name  name of a specific record to view
///   -f | --file  the desired file to view records from
pub fn run(mut args: Args) -> error::Result<()> {
    let mut name: Option<String> = None;
    let mut file_path: Option<String> = None;

    loop {
        let Some(arg) = args.next() else {
            break;
        };

        match arg.as_str() {
            "-n" | "--name" => {
                name = Some(cli::get_arg_value(&mut args, "name")?);
            }
            "-f" | "--file" => file_path = Some(cli::get_arg_value(&mut args, "file")?),
            _ => {
                return Err(error::build::invalid_argument(arg));
            }
        }
    }

    let path = cli::parse_file_path(file_path)?;
    let totp_file = types::TotpFile::from_path(path)?;

    if let Some(name) = name {
        if let Some(record) = totp_file.records.get(&name) {
            print::print_totp_record(&name, record);
        } else {
            return Err(error::build::name_not_found(name));
        }
    } else {
        let longest_key = util::longest_value(totp_file.records.keys(), Some(80));

        print::print_records_list(&totp_file.records, &longest_key, &print::print_totp_record);
    };

    Ok(())
}
