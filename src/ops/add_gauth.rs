use std::env::Args;

use crate::cli;
use crate::error;
use crate::otp;
use crate::print;
use crate::types;

/// adds a new record to a totp file with google authenticator defaults
///
/// it will assign certain values to a specified default for the application
/// - digits = 6
/// - step = 30
/// - algo = SHA1
///
/// options
///   -n | --name    the name of the record. default is "Unknown"
///   -f | --file    the desired file to store the new record in
///   -s | --secret  the secret to assign the new record REQUIRED
pub fn run(mut args: Args) -> error::Result<()> {
    let mut file_path: Option<String> = None;
    let mut secret: Option<Vec<u8>> = None;
    let mut name = "Unknown".to_owned();

    loop {
        let Some(arg) = args.next() else {
            break;
        };

        match arg.as_str() {
            "-n" | "--name" => {
                name = cli::get_arg_value(&mut args, "name")?;
            }
            "-f" | "--file" => {
                file_path = Some(cli::get_arg_value(&mut args, "file")?);
            }
            "-s" | "--secret" => {
                let value = cli::get_arg_value(&mut args, "secret")?;

                secret = Some(cli::parse_secret(value)?);
            }
            _ => {
                return Err(error::build::invalid_argument(arg));
            }
        }
    }

    let Some(secret) = secret else {
        return Err(error::Error::new(error::ErrorKind::MissingArgument)
            .with_message("secret was not specified"));
    };

    let path = cli::parse_file_path(file_path)?;
    let mut totp_file = types::TotpFile::from_path(path)?;

    let record = types::TotpRecord {
        secret,
        digits: 6,
        step: 30,
        algo: otp::Algo::SHA1,
        issuer: None,
        username: None,
    };

    print::print_totp_record(&name, &record);

    totp_file.records.insert(name, record);
    totp_file.update_file()?;

    Ok(())
}
