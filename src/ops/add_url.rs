use std::borrow::Borrow;
use std::env::Args;

use crate::error;
use crate::types;
use crate::cli;
use crate::print;
use crate::otp;

/// adds a new record to a totp file using url format
/// 
/// options
///   -f | --file  the desired file to store the new record in
///   --url        the url to parse REQUIRED
///   -n | --name  the name of the new record. overrides the url value if
///                present
///   -v | --view  will not add the record and only show the details of the
///                record
pub fn run(mut args: Args) -> error::Result<()> {
    let mut view_only = false;
    let mut file_path: Option<String> = None;
    let mut name: Option<String> = None;
    let mut url: Option<String> = None;

    loop {
        let Some(arg) = args.next() else {
            break;
        };

        match arg.as_str() {
            "-f" | "--file" => {
                file_path = Some(cli::get_arg_value(&mut args, "file")?)
            },
            "--url" => {
                url = Some(cli::get_arg_value(&mut args, "url")?);
            }
            "-n" | "--name" => {
                name = Some(cli::get_arg_value(&mut args, "name")?);
            },
            "-v" | "--view" => {
                view_only = true;
            },
            _ => {
                return Err(error::build::invalid_argument(arg));
            }
        }
    }

    let path = cli::parse_file_path(file_path)?;
    let mut totp_file = types::TotpFile::from_path(path)?;

    let url = if let Some(u) = url {
        url::Url::parse(&u)?
    } else {
        return Err(error::Error::new(error::ErrorKind::MissingArgument)
            .with_message("no otp argument supplied for add op"));
    };

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
        return Err(error::Error::new(error::ErrorKind::UrlError)
            .with_message("no domain provided in url"));
    }

    let mut record_key = "Unknown".to_owned();
    let mut record = types::TotpRecord {
        secret: Vec::new(),
        digits: otp::DEFAULT_DIGITS,
        step: otp::DEFAULT_STEP,
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
            },
            "digits" => {
                record.digits = cli::parse_digits(value)?;
            },
            "step" | "period" => {
                record.step = cli::parse_step(value)?;
            },
            "algorithm" => {
                record.algo = cli::parse_algo(value)?;
            },
            "issuer" => {
                match percent_encoding::percent_decode_str(value.borrow()).decode_utf8() {
                    Ok(i) => {
                        record.issuer = Some(i.into_owned());
                    },
                    Err(err) => {
                        return Err(error::Error::new(error::ErrorKind::UrlError)
                            .with_message("issuer argument contains invalid UTF-8 characters")
                            .with_error(err))
                    }
                };
            },
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