use std::collections::HashMap;
use std::path::PathBuf;

use crate::chacha;
use crate::cli;
use crate::error;
use crate::path;
use crate::types;

/// genrates a new encrpyted totp file
///
/// the user will be prompted to enter in a secret used to encrypt the file
/// specified
#[derive(Debug, clap::Args)]
pub struct NewArgs {
    /// name of the file
    #[arg(short, long, default_value = "records")]
    name: String,

    /// directory to create the new file in
    #[arg(short, long)]
    directory: Option<PathBuf>,
}

/// genrates a new encrpyted totp file
pub fn run(
    NewArgs {
        mut name,
        directory,
    }: NewArgs,
) -> error::Result<()> {
    let cwd = std::env::current_dir()?;

    let mut file_path = if let Some(d) = directory {
        let path = path::normalize_from(&cwd, d);

        if let Some(meta) = path::metadata(&path)? {
            if !meta.is_dir() {
                return Err(error::Error::new(error::ErrorKind::InvalidArgument)
                    .with_message("the given directory is not a valid directory"));
            }
        } else {
            return Err(error::Error::new(error::ErrorKind::InvalidArgument)
                .with_message("the given directory does not exist"));
        }

        path
    } else {
        cwd
    };

    name.push_str(".totp");

    file_path.push(name);

    if let Some(_meta) = path::metadata(&file_path)? {
        return Err(error::Error::new(error::ErrorKind::InvalidArgument)
            .with_message("the specified file already exists"));
    }

    let secret = cli::get_input("secret")?;
    let key = chacha::make_key(secret)?;

    let totp_file = types::TotpFile {
        path: file_path,
        file_type: types::TotpFileType::TOTP,
        records: HashMap::new(),
        key: Some(key),
    };

    totp_file.update_file()?;

    Ok(())
}
