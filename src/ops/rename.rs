use crate::cli;
use crate::error;
use crate::types;

/// renames a record to a new name
#[derive(Debug, clap::Args)]
pub struct RenameArgs {
    /// the original name of the record
    #[arg(long)]
    original: String,

    /// the new name of the record
    #[arg(long)]
    renamed: String,

    #[command(flatten)]
    file: cli::RecordFile,
}

pub fn run(
    RenameArgs {
        original,
        renamed,
        file,
    }: RenameArgs,
) -> error::Result<()> {
    let mut totp_file = types::TotpFile::from_path(file.get_file()?)?;

    let Some(record) = totp_file.records.remove(&original) else {
        return Err(error::build::name_not_found(original));
    };

    totp_file.records.insert(renamed, record);
    totp_file.update_file()?;

    Ok(())
}
