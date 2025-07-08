use std::time::Instant;

use crate::otp;
use crate::types::{TotpRecord, TotpRecordDict};
use crate::util;

/// prints the gnerated code of a [TotpRecord]
pub fn print_totp_code(_key: &String, record: &TotpRecord) -> () {
    let now = util::unix_epoch_sec_now().unwrap();
    let data = (now / record.step).to_be_bytes();

    let perf_start = Instant::now();
    let code = otp::generate_integer_string(&record.algo, &record.secret, record.digits, &data);
    let perf_end = Instant::now();

    let time_left = record.step - (now % record.step);

    println!(
        "{}\nseconds left: {}s\n    finished: {:#?}",
        code,
        time_left,
        perf_end.duration_since(perf_start)
    );
}

/// prints the whole [TotpRecord]
pub fn print_totp_record(_key: &String, record: &TotpRecord) -> () {
    let b32 = data_encoding::BASE32.encode(&record.secret);
    println!("base32: {}", b32);
    print!(" bytes:");

    for byte in &record.secret {
        print!(" {:02X}", byte);
    }

    println!(
        " ({})\ndigits: {}\n  step: {}s\n  algo: {}",
        record.secret.len(),
        record.digits,
        record.step,
        record.algo.as_str()
    );

    if let Some(issuer) = record.issuer.as_ref() {
        println!("  issuer: {}", issuer);
    }

    if let Some(username) = record.username.as_ref() {
        println!("username: {}", username);
    }
}

/// prints a list of records with their key and desired print function
pub fn print_records_list(
    totp_dict: &TotpRecordDict,
    longest_key: &usize,
    cb: &dyn Fn(&String, &TotpRecord) -> (),
) -> () {
    let mut first = true;

    for (key, record) in totp_dict.iter() {
        if first {
            first = false;
        } else {
            print!("\n");
        }

        println!("{}", util::pad_key(key, longest_key));

        cb(key, record);
    }
}
