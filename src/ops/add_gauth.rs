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
#[derive(Debug, clap::Args)]
pub struct AddGauthArgs {
    /// the name of the new record
    #[arg(short, long, default_value = "Unknown")]
    name: String,

    /// the desired secret to assign the new record
    #[arg(short, long)]
    secret: cli::Base32,

    #[command(flatten)]
    file: cli::RecordFile,
}

/// adds a new record to a totp file with google authenticator defaults
pub fn run(AddGauthArgs { name, secret, file }: AddGauthArgs) -> error::Result<()> {
    let mut totp_file = types::TotpFile::from_path(file.get_file()?)?;

    let record = types::TotpRecord {
        secret: secret.into(),
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
