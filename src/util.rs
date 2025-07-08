use std::time::{SystemTime, UNIX_EPOCH};

/// retrieves the current UNIX EPOCH
pub fn unix_epoch_sec_now() -> Option<u64> {
    let now = SystemTime::now();

    match now.duration_since(UNIX_EPOCH) {
        Ok(dur) => Some(dur.as_secs()),
        Err(_err) => None,
    }
}

/// counts total number of UTF-8 characters in a string
pub fn total_chars(string: &String) -> usize {
    let mut total = 0;

    for _ in string.chars() {
        total += 1;
    }

    total
}

/// attempts to find the longest string in an iterator
///
/// can optionally specify a starting point or default to 0
pub fn longest_value<'a>(iter: impl Iterator<Item = &'a String>, starting: Option<usize>) -> usize {
    let mut longest_key = starting.unwrap_or(0);

    for key in iter {
        let total_chars = total_chars(key);

        if longest_key < total_chars {
            longest_key = total_chars;
        }
    }

    longest_key
}

/// pads the given key to a desired length
///
/// format is "{key} {padding}" with a padding character of '-'
pub fn pad_key<K>(key: K, len: &usize) -> String
where
    K: AsRef<str>,
{
    let key_ref = key.as_ref();
    let mut to_append = len - key_ref.len();
    let mut rtn = String::with_capacity(to_append);
    rtn.push_str(key_ref);

    if to_append > 0 {
        rtn.push(' ');
        to_append -= 1;
    }

    for _ in 0..to_append {
        rtn.push('-');
    }

    rtn
}
