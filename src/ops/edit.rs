use std::env::Args;

use crate::error;
use crate::types;
use crate::cli;
use crate::print;
use crate::otp;

/// updates a specific record to the desired values
/// 
/// options
///   -n | --name      the name of the record to update REQUIRED
///   -f | --file      the desired file to update a record in
///   -s | --secret    updates secret on record
///   -a | --algo      updates algo on record
///   -d | --digits    updates digits on record
///   -t | --step | -p | --period
///                    updates step on record
///   -i | --issuer    updates issuer on record
///   -u | --username  updates username on record
pub fn run(mut args: Args) -> error::Result<()> {
    let mut file_path: Option<String> = None;
    let mut name: Option<String> = None;
    let mut secret: Option<Vec<u8>> = None;
    let mut algo: Option<otp::Algo> = None;
    let mut digits: Option<u32> = None;
    let mut step: Option<u64> = None;
    let mut issuer: Option<String> = None;
    let mut username: Option<String> = None;

    loop {
        let Some(arg) = args.next() else {
            break;
        };

        match arg.as_str() {
            "-n" | "--name" => {
                name = Some(cli::get_arg_value(&mut args, "name")?);
            },
            "-f" | "--file" => {
                file_path = Some(cli::get_arg_value(&mut args, "file")?);
            },
            "-s" | "--secret" => {
                let value = cli::get_arg_value(&mut args, "secret")?;

                secret = Some(cli::parse_secret(value)?);
            },
            "-a" | "--algo" => {
                let value = cli::get_arg_value(&mut args, "algo")?;

                algo = Some(cli::parse_algo(value)?);
            },
            "-d" | "--digits" => {
                let value = cli::get_arg_value(&mut args, "digits")?;

                digits = Some(cli::parse_digits(value)?);
            },
            "-t" | "--step" | "-p" | "--period" => {
                let value = cli::get_arg_value(&mut args, "step/period")?;

                step = Some(cli::parse_step(value)?);
            },
            "-i" | "--issuer" => {
                issuer = Some(cli::get_arg_value(&mut args, "issuer")?);
            },
            "-u" | "--username" => {
                username = Some(cli::get_arg_value(&mut args, "username")?);
            }
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

    if let Some(record) = totp_file.records.get_mut(&name) {
        if let Some(secret) = secret {
            record.secret = secret;
        }

        if let Some(algo) = algo {
            record.algo = algo;
        }

        if let Some(digits) = digits {
            record.digits = digits;
        }

        if let Some(step) = step {
            record.step = step;
        }

        if issuer.is_some() {
            record.issuer = issuer;
        }

        if username.is_some() {
            record.username = username;
        }

        print::print_totp_record(&name, record);
    } else {
        return Err(error::build::name_not_found(name));
    }

    totp_file.update_file()?;

    Ok(())
}