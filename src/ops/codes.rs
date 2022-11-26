use std::env::Args;
use std::time::Duration;
use std::time::Instant;

use crate::error;
use crate::cli;
use crate::types;
use crate::print;
use crate::util;

/// prints generated codes the terminal
/// 
/// options
///   -w | --watch  prints codes to the terminal every second
///   -f | --file   specifies which file to open and view codes for
///   -n | --name   attempts to find the desired records in a given file
pub fn run(mut args: Args) -> error::Result<()> {
    let mut watch = false;
    let mut name: Option<String> = None;
    let mut file_path: Option<String> = None;

    loop {
        let Some(arg) = args.next() else {
            break;
        };

        match arg.as_str() {
            "-w" | "--watch" => {
                watch = true;
            },
            "-f" | "--file" => {
                file_path = Some(cli::get_arg_value(&mut args, "file")?);
            },
            "-n" | "--name" => {
                name = Some(cli::get_arg_value(&mut args, "name")?);
            },
            _ => {
                return Err(error::build::invalid_argument(arg));
            }
        }
    }

    let path = cli::parse_file_path(file_path)?;
    let records = types::TotpFile::from_path(path)?.take_records();

    if let Some(name) = name {
        let Some(record) = records.get(&name) else {
            return Err(error::build::name_not_found(name));
        };

        if watch {
            let longest_key = 80;

            loop {
                let start = Instant::now();

                print!("{esc}[2J{esc}[1;1H", esc = 27 as char);

                print::print_totp_code(&name, record);

                let end = Instant::now();
                let duration = end.duration_since(start);

                println!("\n{}\nfinished: {:#?}", util::pad_key("INFO", &longest_key), duration);

                if let Some(wait) = Duration::from_secs(1).checked_sub(duration) {
                    std::thread::sleep(wait);
                }
            }
        } else {
            print::print_totp_code(&name, &record);
        }
    } else {
        let longest_key = util::longest_value(records.keys(), Some(80));

        if watch {
            loop {
                let start = Instant::now();

                print!("{esc}[2J{esc}[1;1H", esc = 27 as char);

                print::print_records_list(&records, &longest_key, &print::print_totp_code);

                let end = Instant::now();
                let duration = end.duration_since(start);

                println!("\n{}\nfinished: {:#?}", util::pad_key("INFO", &longest_key), duration);

                if let Some(wait) = Duration::from_secs(1).checked_sub(duration) {
                    std::thread::sleep(wait);
                }
            }
        } else {
            print::print_records_list(&records, &longest_key, &print::print_totp_code);
        }
    }

    Ok(())
}