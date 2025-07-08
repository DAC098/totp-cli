use crate::cli;
use crate::error;
use crate::otp;
use crate::print;
use crate::types;

/// adds a new record to a totp file
///
/// the manual process of adding new codes to a desired totp file
#[derive(Debug, clap::Args)]
pub struct AddArgs {
    /// the name of the new record
    #[arg(short, long)]
    name: String,

    /// a valid BASE32 string
    #[arg(short, long)]
    secret: cli::Base32,

    /// the desired algorithm used to generate codes with
    #[arg(short, long, default_value = "SHA1")]
    algo: otp::Algo,

    /// number of digits to generate for the codes
    #[arg(short, long, default_value = "6")]
    digits: u32,

    /// the step between generating new codes
    #[arg(short = 't', long, default_value = "30")]
    step: u64,

    /// the issuer that the code is for
    #[arg(short, long)]
    issuer: Option<String>,

    /// the username associated with the codes
    #[arg(short, long)]
    username: Option<String>,

    #[command(flatten)]
    file: cli::RecordFile,
}

pub fn run(
    AddArgs {
        name,
        secret,
        algo,
        digits,
        step,
        issuer,
        username,
        file,
    }: AddArgs,
) -> error::Result<()> {
    let mut totp_file = types::TotpFile::from_path(file.get_file()?)?;

    let record = types::TotpRecord {
        secret: secret.into(),
        algo,
        digits,
        step,
        issuer,
        username,
    };

    print::print_totp_record(&name, &record);

    totp_file.records.insert(name, record);
    totp_file.update_file()?;

    Ok(())
}
