use crate::cli;
use crate::error;
use crate::otp;
use crate::print;
use crate::types;

/// updates a specific record to the desired values
#[derive(Debug, clap::Args)]
pub struct EditArgs {
    /// name of the record to update
    #[arg(short, long)]
    name: String,

    /// updates the secret
    #[arg(short, long)]
    secret: Option<cli::Base32>,

    /// updates the algo
    #[arg(short, long)]
    algo: Option<otp::Algo>,

    /// updates the digits
    #[arg(short, long)]
    digits: Option<u32>,

    /// updates the step
    #[arg(short = 't', long)]
    step: Option<u64>,

    /// updates the issuer
    #[arg(short, long)]
    issuer: Option<String>,

    /// updates the username
    #[arg(short, long)]
    username: Option<String>,

    #[command(flatten)]
    file: cli::RecordFile,
}

pub fn run(
    EditArgs {
        name,
        secret,
        algo,
        digits,
        step,
        issuer,
        username,
        file,
    }: EditArgs,
) -> error::Result<()> {
    let mut totp_file = types::TotpFile::from_path(file.get_file()?)?;

    if let Some(record) = totp_file.records.get_mut(&name) {
        if let Some(secret) = secret {
            record.secret = secret.into();
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
