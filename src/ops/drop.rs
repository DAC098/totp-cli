use crate::cli;
use crate::error;
use crate::types;

/// drops a record from a totp file
#[derive(Debug, clap::Args)]
pub struct DropArgs {
    /// name of the record to drop
    #[arg(short, long)]
    name: String,

    #[command(flatten)]
    file: cli::RecordFile,
}

pub fn run(DropArgs { name, file }: DropArgs) -> error::Result<()> {
    let mut totp_file = types::TotpFile::from_path(file.get_file()?)?;

    let Some(_record) = totp_file.records.remove(&name) else {
        return Err(error::build::name_not_found(name));
    };

    totp_file.update_file()?;

    Ok(())
}
