use std::time::{SystemTime, UNIX_EPOCH};

pub fn unix_epoch_sec_now() -> Option<u64> {
    let now = SystemTime::now();

    match now.duration_since(UNIX_EPOCH) {
        Ok(dur) => Some(dur.as_secs()),
        Err(_err) => None
    }
}