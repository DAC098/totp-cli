use std::{collections::HashMap, env::Args, time::{Instant, Duration}, borrow::Borrow, path::PathBuf, io::Write};

use serde::{Serialize, Deserialize};

mod error;
mod mac;
mod chacha;
mod time;
mod otp;
mod file;

/// represents a totp credential
/// 
/// secret, algo, digits, and step are all required in order to properly
/// generate totp codes. the issuer and username are also provided to help
/// with identifying each record.
#[derive(Debug, Serialize, Deserialize)]
struct TotpRecord {
    secret: Vec<u8>,
    algo: otp::Algo,
    digits: u32,
    step: u64,
    issuer: Option<String>,
    username: Option<String>,
}

/// type alias for hashmap records with a string name
type TotpRecordDict = HashMap<String, TotpRecord>;

/// accepted file types for a totp file
#[derive(PartialEq)]
enum TotpFileType {
    JSON,
    YAML,
    TOTP,
}

/// a file that stores totp credentials
/// 
/// stores the path, file type, records, and potential cryptography key for a
/// desired file.
/// 
/// the path is assumed to be fully parsed(?) and lead to the actual location 
/// of the file in the system.
/// 
/// the key is used to decrypt and encrypt the file if necessary, only being 
/// stored so the user does not have to provide the password twice. it is not
/// the actual secret provided but what is generated from [chacha::make_key]
/// function
struct TotpFile {
    path: std::path::PathBuf,
    file_type: TotpFileType,
    records: TotpRecordDict,
    key: Option<chacha::Key>
}

impl TotpFile {

    /// prompts the user for the secret used to encrypt the file
    /// 
    /// this can probably be pulled out since it is fairly generic
    fn get_secret_stdin() -> error::Result<String> {
        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout();
        let mut input = String::new();

        print!("secret: ");
        stdout.flush()?;
        stdin.read_line(&mut input)?;

        Ok(input)
    }

    /// attempts to parse and decrypt the data stored in the file
    /// 
    /// the nonce is stored in the first 24 bytes of the file. the rest is the
    /// encrypted data
    fn decrypt(key: &chacha::Key, data: Vec<u8>) -> error::Result<TotpRecordDict> {
        let mut encrypted: Vec<u8> = Vec::with_capacity(data.len() - chacha::NONCE_LEN);
        let mut nonce = [0u8; chacha::NONCE_LEN];
        let mut iter = data.into_iter();

        for i in 0..nonce.len() {
            if let Some(byte) = iter.next() {
                nonce[i] = byte;
            } else {
                return Err(error::Error::new(error::ErrorKind::ChaChaError)
                    .with_message("invalid file format for encrypted file"));
            }
        }

        while let Some(byte) = iter.next() {
            encrypted.push(byte);
        }

        let decrypted = chacha::decrypt_data(&key, &nonce, &encrypted)?;
        let records = serde_json::from_slice(&decrypted)?;

        Ok(records)
    }

    /// encrypts the given records
    /// 
    /// it will create a byte vector with the nonce stored in the first 24
    /// bytes and then store the encrypted data in the rest.
    fn encrypt(key: &chacha::Key, records: &TotpRecordDict) -> error::Result<Vec<u8>> {
        let nonce = chacha::make_nonce()?;
        let data = serde_json::to_vec(records)?;

        let encrypted = chacha::encrypt_data(&key, &nonce, &data)?;
        let mut contents = Vec::with_capacity(nonce.len() + encrypted.len());

        for byte in nonce {
            contents.push(byte);
        }

        for byte in encrypted {
            contents.push(byte);
        }

        Ok(contents)
    }

    /// helper to create an io reader for a given file
    #[inline]
    fn get_reader<P>(path: P) -> error::Result<impl std::io::Read>
    where
        P: AsRef<std::path::Path>
    {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(path)?;
        Ok(std::io::BufReader::new(file))
    }

    /// helper to create an io writer for a given file
    #[inline]
    fn get_writer<P>(path: P) -> error::Result<impl std::io::Write>
    where
        P: AsRef<std::path::Path>
    {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)?;
        Ok(std::io::BufWriter::new(file))
    }

    /// creates a TotpFile struct from a given path
    /// 
    /// if the file provided as a totp extension then it will treat it as an
    /// encrpyted file and will prompt the user for the secret used to
    /// encrypt the data on the file
    fn from_path<P>(path: P) -> error::Result<TotpFile>
    where
        P: AsRef<std::path::Path>
    {
        if let Some(ext) = path.as_ref().extension() {
            let ext = ext.to_ascii_lowercase();

            if ext.eq("yaml") || ext.eq("yml") {
                let records = serde_yaml::from_reader(Self::get_reader(&path)?)?;

                Ok(TotpFile { 
                    path: path.as_ref().to_owned(),
                    file_type: TotpFileType::YAML,
                    records,
                    key: None,
                })
            } else if ext.eq("json") {
                let records = serde_json::from_reader(Self::get_reader(&path)?)?;

                Ok(TotpFile {
                    path: path.as_ref().to_owned(),
                    file_type: TotpFileType::JSON,
                    records,
                    key: None,
                })
            } else if ext.eq("totp") {
                let key = {
                    let secret = Self::get_secret_stdin()?;
                    chacha::make_key(&secret)?
                };
                let data = std::fs::read(&path)?;
                let records = Self::decrypt(&key, data)?;

                Ok(TotpFile {
                    path: path.as_ref().to_owned(),
                    file_type: TotpFileType::TOTP,
                    records,
                    key: Some(key),
                })
            } else {
                Err(error::Error::new(error::ErrorKind::InvalidExtension)
                    .with_message("unknown file extension given from path"))
            }
        } else {
            Err(error::Error::new(error::ErrorKind::InvalidExtension)
                .with_message("no file extension found for given path"))
        }
    }

    /// takes the records of the file and discards the rest
    fn take_records(self) -> TotpRecordDict {
        self.records
    }

    /// updates the file with the information stored
    /// 
    /// if the file was decrypted then it will attempt to encrypt the new data
    /// in the previous file
    fn update_file(&self) -> error::Result<()> {
        match self.file_type {
            TotpFileType::YAML => {
                serde_yaml::to_writer(Self::get_writer(&self.path)?, &self.records)?;
            },
            TotpFileType::JSON => {
                serde_json::to_writer(Self::get_writer(&self.path)?, &self.records)?;
            },
            TotpFileType::TOTP => {
                let Some(key) = self.key.as_ref() else {
                    return Err(error::Error::new(error::ErrorKind::ChaChaError)
                        .with_message("missing key"))
                };

                let contents = Self::encrypt(key, &self.records)?;

                std::fs::write(&self.path, contents)?;
            }
        };

        Ok(())
    }
}

fn main() {
    let mut args = std::env::args();
    args.next();

    if let Err(err) = run(args) {
        if let Some(msg) = err.message {
            print!("{}: {}", err.kind, msg);
        } else {
            print!("{}", err.kind);
        }

        if let Some(src) = err.source {
            print!("\n{}", src);
        }

        print!("\n");
    }
}

/// processes the first argument and then runs the desired operation
fn run(mut args: Args) -> error::Result<()> {
    let Some(op) = args.next() else {
        return Err(error::Error::new(error::ErrorKind::InvalidOp)
            .with_message("no operation specified"));
    };

    match op.as_str() {
        "codes" => op_codes(args),
        "new" => op_new(args),
        "add" => op_add(args),
        "add-url" => op_add_url(args),
        "add-gauth" => op_add_gauth(args),
        "view" => op_view(args),
        "edit" => op_edit(args),
        "rename" => op_rename(args),
        "drop" => op_drop(args),
        _ => {
            let mut msg = String::from("given an unknown operation. \"");
            msg.push_str(&op);
            msg.push('"');

            Err(error::Error::new(error::ErrorKind::InvalidOp)
                .with_message(msg))
        }
    }
}

/// common error for providing an invalid argument
fn invalid_argument(arg: String) -> error::Error {
    let mut msg = String::from("given invalid argument. \"");
    msg.push_str(&arg);
    msg.push('"');

    return error::Error::new(error::ErrorKind::InvalidArgument)
        .with_message(msg)
}

/// common error when the desired name was not found
fn name_not_found(name: String) -> error::Error {
    let mut msg = String::from("given name does not exist in file. \"");
    msg.push_str(&name);
    msg.push('"');

    return error::Error::new(error::ErrorKind::InvalidArgument)
        .with_message(msg)
}

/// counts total number of UTF-8 characters in a string
fn total_chars(string: &String) -> usize {
    let mut total = 0;

    for _ in string.chars() {
        total += 1;
    }

    total
}

/// attempts to find the longest string in an iterator
/// 
/// can optionally specify a starting point or default to 0
fn longest_value<'a>(iter: impl Iterator<Item = &'a String>, starting: Option<usize>) -> usize {
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
fn pad_key<K>(key: K, len: &usize) -> String
where
    K: AsRef<str>
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

/// prints the gnerated code of a [TotpRecord]
fn print_totp_code(_key: &String, record: &TotpRecord) -> () {
    let now = time::unix_epoch_sec_now().unwrap();
    let data = (now / record.step).to_be_bytes();

    let perf_start = Instant::now();
    let code = otp::generate_integer_string(&record.algo, &record.secret, record.digits, &data);
    let perf_end = Instant::now();

    let time_left = record.step - (now % record.step);

    println!("{}\nseconds left: {}s\n    finished: {:#?}", code, time_left, perf_end.duration_since(perf_start));
}

/// prints the whole [TotpRecord]
fn print_totp_record(_key: &String, record: &TotpRecord) -> () {
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
fn print_records_list(
    totp_dict: &TotpRecordDict, 
    longest_key: &usize, 
    cb: &dyn Fn(&String, &TotpRecord) -> ()
) -> () {
    let mut first = true;

    for (key, record) in totp_dict.iter() {
        if first {
            first = false;
        } else {
            print!("\n");
        }

        println!("{}", pad_key(key, longest_key));

        cb(key, record);
    }
}

/// gets the canonicalized version of the given path
#[inline]
fn get_full_path(path: PathBuf) -> error::Result<PathBuf> {
    let to_check = if !path.is_absolute() {
        let mut cwd = std::env::current_dir()?;
        cwd.push(path);
        cwd
    } else {
        path
    };

    let rtn = std::fs::canonicalize(to_check)?;

    Ok(rtn)
}

/// default file path for a records file
fn get_default_file_path() -> error::Result<PathBuf> {
    let mut cwd = std::env::current_dir()?;
    cwd.push("records.yaml");
    Ok(cwd)
}

/// parses the option command line argument for a file path
fn parse_file_path(path: Option<String>) -> error::Result<PathBuf> {
    if let Some(p) = path {
        get_full_path(PathBuf::from(p))
    } else {
        get_default_file_path()
    }
}

/// prints generated codes the terminal
/// 
/// options
///   -w | --watch  prints codes to the terminal every second
///   -f | --file   specifies which file to open and view codes for
///   -n | --name   attempts to find the desired records in a given file
fn op_codes(mut args: Args) -> error::Result<()> {
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
                file_path = Some(get_arg_value(&mut args, "file")?);
            },
            "-n" | "--name" => {
                name = Some(get_arg_value(&mut args, "name")?);
            },
            _ => {
                return Err(invalid_argument(arg));
            }
        }
    }

    let path = parse_file_path(file_path)?;
    let records = TotpFile::from_path(path)?.take_records();

    if let Some(name) = name {
        let Some(record) = records.get(&name) else {
            return Err(name_not_found(name));
        };

        if watch {
            let longest_key = 80;

            loop {
                let start = Instant::now();

                print!("{esc}[2J{esc}[1;1H", esc = 27 as char);

                print_totp_code(&name, record);

                let end = Instant::now();
                let duration = end.duration_since(start);

                println!("\n{}\nfinished: {:#?}", pad_key("INFO", &longest_key), duration);

                if let Some(wait) = Duration::from_secs(1).checked_sub(duration) {
                    std::thread::sleep(wait);
                }
            }
        } else {
            print_totp_code(&name, &record);
        }
    } else {
        let longest_key = longest_value(records.keys(), Some(80));

        if watch {
            loop {
                let start = Instant::now();

                print!("{esc}[2J{esc}[1;1H", esc = 27 as char);

                print_records_list(&records, &longest_key, &print_totp_code);

                let end = Instant::now();
                let duration = end.duration_since(start);

                println!("\n{}\nfinished: {:#?}", pad_key("INFO", &longest_key), duration);

                if let Some(wait) = Duration::from_secs(1).checked_sub(duration) {
                    std::thread::sleep(wait);
                }
            }
        } else {
            print_records_list(&records, &longest_key, &print_totp_code);
        }
    }

    Ok(())
}

/// genrates a new encrpyted totp file
/// 
/// options
///   -d | --directory  the specified directory to create the new file
///   -n | --name       the name of the file REQUIRED
/// 
/// the user will be prompted to enter in a secret used to encrypt the file
/// specified
fn op_new(mut args: Args) -> error::Result<()> {
    let mut name: Option<String> = None;
    let mut dir: Option<String> = None;

    loop {
        let Some(arg) = args.next() else {
            break;
        };

        match arg.as_str() {
            "-d" | "--directory" => {
                dir = Some(get_arg_value(&mut args, "directory")?);
            },
            "-n" | "--name" => {
                name = Some(get_arg_value(&mut args, "name")?)
            },
            _ => {
                return Err(invalid_argument(arg));
            }
        }
    }

    let mut file_path = if let Some(d) = dir {
        let path = get_full_path(PathBuf::from(d))?;

        if !path.exists() {
            return Err(error::Error::new(error::ErrorKind::InvalidArgument)
                .with_message("the given directory does not exist"))
        } else if !path.is_dir() {
            return Err(error::Error::new(error::ErrorKind::InvalidArgument)
                .with_message("the given directory is not a valid directory"))
        }

        path
    } else {
        std::env::current_dir()?
    };

    let Some(mut name) = name else {
        return Err(error::Error::new(error::ErrorKind::MissingArgument)
            .with_message("no name was specified"))
    };

    name.push_str(".totp");

    file_path.push(name);

    if file_path.exists() {
        return Err(error::Error::new(error::ErrorKind::InvalidArgument)
            .with_message("the specified file already exists"))
    }

    let secret = TotpFile::get_secret_stdin()?;
    let key = chacha::make_key(secret)?;

    let totp_file = TotpFile {
        path: file_path,
        file_type: TotpFileType::TOTP,
        records: HashMap::new(),
        key: Some(key)
    };

    totp_file.update_file()?;

    Ok(())
}

/// parses a BASE32 encoded string
fn parse_secret<S>(secret: S) -> error::Result<Vec<u8>>
where
    S: AsRef<[u8]>
{
    match data_encoding::BASE32.decode(secret.as_ref()) {
        Ok(s) => Ok(s),
        Err(err) => {
            Err(error::Error::new(error::ErrorKind::InvalidArgument)
                .with_message("key is an invalid base32 value")
                .with_error(err))
        }
    }
}

/// parses a string to a valid [Algo]
fn parse_algo<A>(algo: A) -> error::Result<otp::Algo>
where
    A: AsRef<str>
{
    if let Ok(v) = otp::Algo::try_from_str(algo) {
        Ok(v)
    } else {
        Err(error::Error::new(error::ErrorKind::InvalidArgument)
            .with_message("given value for algo is invalid"))
    }
}

/// parses a string to a valid u32
fn parse_digits<D>(digits: D) -> error::Result<u32>
where
    D: AsRef<str>
{
    if let Ok(parsed) = u32::from_str_radix(digits.as_ref(), 10) {
        Ok(parsed)
    } else {
        Err(error::Error::new(error::ErrorKind::InvalidArgument)
            .with_message("digits is not a valid unsiged integer"))
    }
}

/// parses a string to a valid u64
fn parse_step<S>(step: S) -> error::Result<u64>
where
    S: AsRef<str>
{
    if let Ok(parsed) = u64::from_str_radix(step.as_ref(), 10) {
        Ok(parsed)
    } else {
        return Err(error::Error::new(error::ErrorKind::InvalidArgument)
            .with_message("step/period is not a valid unsiged integer"))
    }
}

/// attempts to retrieve the next argument
/// 
/// if the argument is not present then it will return an error indicating the
/// argument is missing and provide the name of the argument
fn get_arg_value<N>(args: &mut Args, name: N) -> error::Result<String>
where
    N: AsRef<str>
{
    let Some(v) = args.next() else {
        let mut msg = String::from("missing ");
        msg.push_str(name.as_ref());
        msg.push_str(" argument value");

        return Err(error::Error::new(error::ErrorKind::MissingArgument)
            .with_message(msg))
    };

    Ok(v)
}

/// adds a new record to a totp file
/// 
/// options
///   -n | --name      the name of the new record REQUIRED
///   -f | --file      the desired file to store the new record in
///   -s | --secret    a valid BASE43 string REQUIRED
///   -a | --algo      the desired algorithm used to generate codes with. 
///                    defaults to SHA1
///   -d | --digits    number of digits to generate for the codes. defaults to
///                    6
///   -t | -p | --step | --period
///                    the step between generating new codes. defaults to 30
///   -i | --issuer    the issuer that the code is for
///   -u | --username  the username associated with the codes
/// 
/// the manual process of adding new codes to a desired totp file
fn op_add(mut args: Args) -> error::Result<()> {
    let mut file_path: Option<String> = None;
    let mut name: Option<String> = None;
    let mut secret: Option<Vec<u8>> = None;
    let mut algo: Option<otp::Algo> = None;
    let mut digits: Option<u32> = None;
    let mut step: Option<u64> = None;
    let mut issuer: Option<String> = None;
    let mut username: Option<String> = None;

    loop {
        let Some(arg) = args.next() else {
            break;
        };

        match arg.as_str() {
            "-n" | "--name" => {
                name = Some(get_arg_value(&mut args, "name")?)
            }
            "-f" | "--file" => {
                file_path = Some(get_arg_value(&mut args, "file")?);
            },
            "-s" | "--secret" => {
                let value = get_arg_value(&mut args, "secret")?;

                secret = Some(parse_secret(value)?);
            },
            "-a" | "--algo" => {
                let value = get_arg_value(&mut args, "algo")?;

                algo = Some(parse_algo(value)?);
            },
            "-d" | "--digits" => {
                let value = get_arg_value(&mut args, "digits")?;

                digits = Some(parse_digits(value)?);
            },
            "-t" | "--step" | "-p" | "--period" => {
                let value = get_arg_value(&mut args, "step/period")?;

                step = Some(parse_step(value)?);
            },
            "-i" | "--issuer" => {
                issuer = Some(get_arg_value(&mut args, "issuer")?);
            },
            "-u" | "--username" => {
                username = Some(get_arg_value(&mut args, "username")?);
            }
            _ => {
                return Err(invalid_argument(arg));
            }
        }
    }

    let Some(name) = name else {
        return Err(error::Error::new(error::ErrorKind::MissingArgument)
            .with_message("no name was specified"));
    };

    let Some(secret) = secret else {
        return Err(error::Error::new(error::ErrorKind::MissingArgument)
            .with_message("no secret was specified"));
    };

    let path = parse_file_path(file_path)?;
    let mut totp_file = TotpFile::from_path(path)?;

    let record = TotpRecord {
        secret,
        algo: algo.unwrap_or(otp::Algo::SHA1),
        digits: digits.unwrap_or(6),
        step: step.unwrap_or(30),
        issuer,
        username
    };

    print_totp_record(&name, &record);
    
    totp_file.records.insert(name, record);
    totp_file.update_file()?;

    Ok(())
}

/// adds a new record to a totp file using url format
/// 
/// options
///   -f | --file  the desired file to store the new record in
///   --url        the url to parse REQUIRED
///   -n | --name  the name of the new record. overrides the url value if
///                present
///   -v | --view  will not add the record and only show the details of the
///                record
fn op_add_url(mut args: Args) -> error::Result<()> {
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
                file_path = Some(get_arg_value(&mut args, "file")?)
            },
            "--url" => {
                url = Some(get_arg_value(&mut args, "url")?);
            }
            "-n" | "--name" => {
                name = Some(get_arg_value(&mut args, "name")?);
            },
            "-v" | "--view" => {
                view_only = true;
            },
            _ => {
                return Err(invalid_argument(arg));
            }
        }
    }

    let path = parse_file_path(file_path)?;
    let mut totp_file = TotpFile::from_path(path)?;

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
    let mut record = TotpRecord {
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
                record.secret = parse_secret(value.as_bytes())?;
            },
            "digits" => {
                record.digits = parse_digits(value)?;
            },
            "step" | "period" => {
                record.step = parse_step(value)?;
            },
            "algorithm" => {
                record.algo = parse_algo(value)?;
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

    print_totp_record(&record_key, &record);

    if !view_only {
        totp_file.records.insert(record_key, record);
        totp_file.update_file()?;
    }

    Ok(())
}

/// adds a new record to a totp file with google authenticator defaults
/// 
/// it will assign certain values to a specified default for the application
/// - digits = 6
/// - step = 30
/// - algo = SHA1
/// 
/// options
///   -n | --name    the name of the record. default is "Unknown"
///   -f | --file    the desired file to store the new record in
///   -s | --secret  the secret to assign the new record REQUIRED
fn op_add_gauth(mut args: Args) -> error::Result<()> {
    let mut file_path: Option<String> = None;
    let mut secret: Option<Vec<u8>> = None;
    let mut name = "Unknown".to_owned();

    loop {
        let Some(arg) = args.next() else {
            break;
        };

        match arg.as_str() {
            "-n" | "--name" => {
                name = get_arg_value(&mut args, "name")?;
            },
            "-f" | "--file" => {
                file_path = Some(get_arg_value(&mut args, "file")?);
            },
            "-s" | "--secret" => {
                let value = get_arg_value(&mut args, "secret")?;

                secret = Some(parse_secret(value)?);
            },
            _ => {
                return Err(invalid_argument(arg));
            }
        }
    }

    let Some(secret) = secret else {
        return Err(error::Error::new(error::ErrorKind::MissingArgument)
            .with_message("secret was not specified"))
    };

    let path = parse_file_path(file_path)?;
    let mut totp_file = TotpFile::from_path(path)?;

    let record = TotpRecord {
        secret,
        digits: 6,
        step: otp::DEFAULT_STEP,
        algo: otp::Algo::SHA1,
        issuer: None,
        username: None,
    };

    print_totp_record(&name, &record);

    totp_file.records.insert(name, record);
    totp_file.update_file()?;

    Ok(())
}

/// views records of a totp file
/// 
/// options
///   -n | --name  name of a specific record to view
///   -f | --file  the desired file to view records from
fn op_view(mut args: Args) -> error::Result<()> {
    let mut name: Option<String> = None;
    let mut file_path: Option<String> = None;

    loop {
        let Some(arg) = args.next() else {
            break;
        };

        match arg.as_str() {
            "-n" | "--name" => {
                name = Some(get_arg_value(&mut args, "name")?);
            },
            "-f" | "--file" => {
                file_path = Some(get_arg_value(&mut args, "file")?)
            },
            _ => {
                return Err(invalid_argument(arg));
            }
        }
    }

    let path = parse_file_path(file_path)?;
    let totp_file = TotpFile::from_path(path)?;

    if let Some(name) = name {
        if let Some(record) = totp_file.records.get(&name) {
            print_totp_record(&name, record);
        } else {
            return Err(name_not_found(name));
        }
    } else {
        let longest_key = longest_value(totp_file.records.keys(), Some(80));

        print_records_list(&totp_file.records, &longest_key, &print_totp_record);
    };

    Ok(())
}

/// updates a specific record to the desired values
/// 
/// options
///   -n | --name      the name of the record to update REQUIRED
///   -f | --file      the desired file to update a record in
///   -s | --secret    updates secret on record
///   -a | --algo      updates algo on record
///   -d | --digits    updates digits on record
///   -t | --step | -p | --period
///                    updates step on record
///   -i | --issuer    updates issuer on record
///   -u | --username  updates username on record
fn op_edit(mut args: Args) -> error::Result<()> {
    let mut file_path: Option<String> = None;
    let mut name: Option<String> = None;
    let mut secret: Option<Vec<u8>> = None;
    let mut algo: Option<otp::Algo> = None;
    let mut digits: Option<u32> = None;
    let mut step: Option<u64> = None;
    let mut issuer: Option<String> = None;
    let mut username: Option<String> = None;

    loop {
        let Some(arg) = args.next() else {
            break;
        };

        match arg.as_str() {
            "-n" | "--name" => {
                name = Some(get_arg_value(&mut args, "name")?);
            },
            "-f" | "--file" => {
                file_path = Some(get_arg_value(&mut args, "file")?);
            },
            "-s" | "--secret" => {
                let value = get_arg_value(&mut args, "secret")?;

                secret = Some(parse_secret(value)?);
            },
            "-a" | "--algo" => {
                let value = get_arg_value(&mut args, "algo")?;

                algo = Some(parse_algo(value)?);
            },
            "-d" | "--digits" => {
                let value = get_arg_value(&mut args, "digits")?;

                digits = Some(parse_digits(value)?);
            },
            "-t" | "--step" | "-p" | "--period" => {
                let value = get_arg_value(&mut args, "step/period")?;

                step = Some(parse_step(value)?);
            },
            "-i" | "--issuer" => {
                issuer = Some(get_arg_value(&mut args, "issuer")?);
            },
            "-u" | "--username" => {
                username = Some(get_arg_value(&mut args, "username")?);
            }
            _ => {
                return Err(invalid_argument(arg));
            }
        }
    }

    let path = parse_file_path(file_path)?;
    let mut totp_file = TotpFile::from_path(path)?;

    let Some(name) = name else {
        return Err(error::Error::new(error::ErrorKind::MissingArgument)
            .with_message("name was not specified"));
    };

    if let Some(record) = totp_file.records.get_mut(&name) {
        if let Some(secret) = secret {
            record.secret = secret;
        }

        if let Some(algo) = algo {
            record.algo = algo;
        }

        if let Some(digits) = digits {
            record.digits = digits;
        }

        if let Some(step) = step {
            record.step = step;
        }

        if issuer.is_some() {
            record.issuer = issuer;
        }

        if username.is_some() {
            record.username = username;
        }

        print_totp_record(&name, record);
    } else {
        return Err(name_not_found(name));
    }

    totp_file.update_file()?;

    Ok(())
}

/// renames a record to a new name
/// 
/// options
///   -f | --file  the dsired file to rename a record in
///   --original   the original name of the record REQUIRED
///   --renamed    the new name of the record REQUIRED
fn op_rename(mut args: Args) -> error::Result<()> {
    let mut file_path: Option<String> = None;
    let mut original: Option<String> = None;
    let mut renamed: Option<String> = None;

    loop {
        let Some(arg) = args.next() else {
            break;
        };

        match arg.as_str() {
            "-f" | "--file" => {
                file_path = Some(get_arg_value(&mut args, "file")?);
            },
            "--original" => {
                original = Some(get_arg_value(&mut args, "original")?);
            },
            "--renamed" => {
                renamed = Some(get_arg_value(&mut args, "renamed")?);
            },
            _ => {
                return Err(invalid_argument(arg));
            }
        }
    }

    let path = parse_file_path(file_path)?;
    let mut totp_file = TotpFile::from_path(path)?;

    let Some(original) = original else {
        return Err(error::Error::new(error::ErrorKind::MissingArgument)
            .with_message("original was not specified"));
    };

    let Some(renamed) = renamed else {
        return Err(error::Error::new(error::ErrorKind::MissingArgument)
            .with_message("renamed was not specified"));
    };

    let Some(record) = totp_file.records.remove(&original) else {
        return Err(name_not_found(original));
    };

    totp_file.records.insert(renamed, record);
    totp_file.update_file()?;

    Ok(())
}

/// drops a record from a totp file
/// 
/// options
///   -f | --file  the desired file to drop a record from
///   -n | --name  the name of the record to drop REQUIRED
fn op_drop(mut args: Args) -> error::Result<()> {
    let mut file_path: Option<String> = None;
    let mut name: Option<String> = None;

    loop {
        let Some(arg) = args.next() else {
            break;
        };

        match arg.as_str() {
            "-f" | "--file" => {
                file_path = Some(get_arg_value(&mut args, "file")?);
            },
            "-n" | "--name" => {
                name = Some(get_arg_value(&mut args, "name")?);
            },
            _ => {
                return Err(invalid_argument(arg));
            }
        }
    }

    let path = parse_file_path(file_path)?;
    let mut totp_file = TotpFile::from_path(path)?;

    let Some(name) = name else {
        return Err(error::Error::new(error::ErrorKind::MissingArgument)
            .with_message("name was not specified"));
    };

    let Some(_record) = totp_file.records.remove(&name) else {
        return Err(name_not_found(name));
    };

    totp_file.update_file()?;

    Ok(())
}