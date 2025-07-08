use std::time::Duration;
use std::time::Instant;

use clap::Args;

use crate::cli;
use crate::error;
use crate::print;
use crate::types;
use crate::util;

/// prints generated codes to the terminal
#[derive(Debug, Args)]
pub struct CodesArgs {
    /// prints codes to the terminal every second
    #[arg(short, long)]
    watch: bool,

    /// attempts to find the desired records in a given file
    #[arg(short, long)]
    name: Option<String>,

    #[command(flatten)]
    file: cli::RecordFile,
}

pub fn run(CodesArgs { watch, name, file }: CodesArgs) -> error::Result<()> {
    let records = types::TotpFile::from_path(file.get_file()?)?.take_records();

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

                println!(
                    "\n{}\nfinished: {:#?}",
                    util::pad_key("INFO", &longest_key),
                    duration
                );

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

                println!(
                    "\n{}\nfinished: {:#?}",
                    util::pad_key("INFO", &longest_key),
                    duration
                );

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
