use crate::cli;
use crate::error;
use crate::print;
use crate::types;
use crate::util;

/// views records of a totp file
#[derive(Debug, clap::Args)]
pub struct ViewArgs {
    /// name of a specific record to view
    #[arg(short, long)]
    name: Option<String>,

    #[command(flatten)]
    file: cli::RecordFile,
}

pub fn run(ViewArgs { name, file }: ViewArgs) -> error::Result<()> {
    let totp_file = types::TotpFile::from_path(file.get_file()?)?;

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
