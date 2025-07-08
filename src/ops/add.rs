use std::env::Args;

use crate::cli;
use crate::error;
use crate::otp;
use crate::print;
use crate::types;

/// adds a new record to a totp file
///
/// options
///   -n | --name      the name of the new record REQUIRED
///   -f | --file      the desired file to store the new record in
///   -s | --secret    a valid BASE43 string REQUIRED
///   -a | --algo      the desired algorithm used to generate codes with.
///                    defaults to SHA1
///   -d | --digits    number of digits to generate for the codes. defaults to
///                    6
///   -t | -p | --step | --period
///                    the step between generating new codes. defaults to 30
///   -i | --issuer    the issuer that the code is for
///   -u | --username  the username associated with the codes
///
/// the manual process of adding new codes to a desired totp file
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
            "-n" | "--name" => name = Some(cli::get_arg_value(&mut args, "name")?),
            "-f" | "--file" => {
                file_path = Some(cli::get_arg_value(&mut args, "file")?);
            }
            "-s" | "--secret" => {
                let value = cli::get_arg_value(&mut args, "secret")?;

                secret = Some(cli::parse_secret(value)?);
            }
            "-a" | "--algo" => {
                let value = cli::get_arg_value(&mut args, "algo")?;

                algo = Some(cli::parse_algo(value)?);
            }
            "-d" | "--digits" => {
                let value = cli::get_arg_value(&mut args, "digits")?;

                digits = Some(cli::parse_digits(value)?);
            }
            "-t" | "--step" | "-p" | "--period" => {
                let value = cli::get_arg_value(&mut args, "step/period")?;

                step = Some(cli::parse_step(value)?);
            }
            "-i" | "--issuer" => {
                issuer = Some(cli::get_arg_value(&mut args, "issuer")?);
            }
            "-u" | "--username" => {
                username = Some(cli::get_arg_value(&mut args, "username")?);
            }
            _ => {
                return Err(error::build::invalid_argument(arg));
            }
        }
    }

    let Some(name) = name else {
        return Err(error::Error::new(error::ErrorKind::MissingArgument)
            .with_message("no name was specified"));
    };

    let Some(secret) = secret else {
        return Err(error::Error::new(error::ErrorKind::MissingArgument)
            .with_message("no secret was specified"));
    };

    let path = cli::parse_file_path(file_path)?;
    let mut totp_file = types::TotpFile::from_path(path)?;

    let record = types::TotpRecord {
        secret,
        algo: algo.unwrap_or(otp::Algo::SHA1),
        digits: digits.unwrap_or(6),
        step: step.unwrap_or(30),
        issuer,
        username,
    };

    print::print_totp_record(&name, &record);

    totp_file.records.insert(name, record);
    totp_file.update_file()?;

    Ok(())
}
