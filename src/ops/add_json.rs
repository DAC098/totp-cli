use crate::cli;
use crate::error;
use crate::print;
use crate::types;

/// adds a new record to a totp file using a json string
///
/// the key value pairs of the json are as follows:
/// secret: array u8
/// algo: string "SHA1", "SHA256", "SHA512"
///       default "SHA1"
/// digits: u32 default 6
/// step: u64 default 30
/// issuer: string optional
/// username: string optional",
#[derive(Debug, clap::Args)]
pub struct AddJsonArgs {
    /// the name of the new record
    #[arg(short, long)]
    name: String,

    /// views the record and will not add it to the file
    #[arg(short, long)]
    view_only: bool,

    /// the json string of the record to add
    #[arg(long)]
    json: String,

    #[command(flatten)]
    file: cli::RecordFile,
}

pub fn run(
    AddJsonArgs {
        name,
        view_only,
        json,
        file,
    }: AddJsonArgs,
) -> error::Result<()> {
    let mut totp_file = types::TotpFile::from_path(file.get_file()?)?;

    let record: types::TotpRecord = serde_json::from_str(&json)?;

    print::print_totp_record(&name, &record);

    if !view_only {
        totp_file.records.insert(name, record);
        totp_file.update_file()?;
    }

    Ok(())
}
