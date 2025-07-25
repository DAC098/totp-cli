use std::borrow::Borrow;

use crate::cli;
use crate::error;
use crate::otp;
use crate::print;
use crate::types;

/// adds a new record to a totp file using url format
#[derive(Debug, clap::Args)]
pub struct AddUrlArgs {
    /// name of the new record
    #[arg(short, long)]
    name: Option<String>,

    /// views the record and will not add it to the file
    #[arg(short, long)]
    view_only: bool,

    /// the url to parse
    #[arg(long)]
    url: String,

    #[command(flatten)]
    file: cli::RecordFile,
}

/// adds a new record to a totp file using url format
pub fn run(
    AddUrlArgs {
        mut name,
        view_only,
        url,
        file,
    }: AddUrlArgs,
) -> error::Result<()> {
    let mut totp_file = types::TotpFile::from_path(file.get_file()?)?;

    let url = url::Url::parse(&url)?;

    if url.scheme() != "otpauth" {
        return Err(error::Error::new(error::ErrorKind::UrlError)
            .with_message("unknown scheme provided in url"));
    }

    if let Some(domain) = url.domain() {
        if domain != "totp" {
            return Err(error::Error::new(error::ErrorKind::UrlError)
                .with_message("unknown domain provided in url"));
        }
    } else {
        return Err(
            error::Error::new(error::ErrorKind::UrlError).with_message("no domain provided in url")
        );
    }

    let mut record_key = "Unknown".to_owned();
    let mut record = types::TotpRecord {
        secret: Vec::new(),
        digits: 6,
        step: 30,
        algo: otp::Algo::SHA1,
        issuer: None,
        username: None,
    };

    if let Some(mut split) = url.path_segments() {
        if let Some(first) = split.next() {
            let parsed = match percent_encoding::percent_decode_str(first).decode_utf8() {
                Ok(p) => p,
                Err(e) => {
                    return Err(error::Error::new(error::ErrorKind::UrlError)
                        .with_message("url path contains invalid UTF-8 characters")
                        .with_error(e))
                }
            };

            if let Some((n, u)) = parsed.split_once(':') {
                record.issuer = Some(n.into());
                record.username = Some(u.into());

                if name.is_none() {
                    name = Some(n.to_owned());
                }
            }
        };
    } else {
        println!("path: \"{}\"", url.path());
    }

    if let Some(name) = name {
        record_key = name;
    }

    let query = url.query_pairs();

    for (key, value) in query {
        match key.borrow() {
            "secret" => {
                record.secret = cli::parse_secret(value.as_bytes())?;
            }
            "digits" => {
                record.digits = cli::parse_digits(value)?;
            }
            "step" | "period" => {
                record.step = cli::parse_step(value)?;
            }
            "algorithm" => {
                record.algo = cli::parse_algo(value)?;
            }
            "issuer" => {
                match percent_encoding::percent_decode_str(value.borrow()).decode_utf8() {
                    Ok(i) => {
                        record.issuer = Some(i.into_owned());
                    }
                    Err(err) => {
                        return Err(error::Error::new(error::ErrorKind::UrlError)
                            .with_message("issuer argument contains invalid UTF-8 characters")
                            .with_error(err))
                    }
                };
            }
            _ => {
                println!("unknown url query key: {}", key);
            }
        }
    }

    print::print_totp_record(&record_key, &record);

    if !view_only {
        totp_file.records.insert(record_key, record);
        totp_file.update_file()?;
    }

    Ok(())
}
