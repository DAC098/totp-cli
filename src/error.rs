/// the kinds of errors that the application can return
#[derive(Debug)]
pub enum ErrorKind {
    InvalidOp,
    InvalidExtension,
    MissingArgument,
    InvalidArgument,
    IoError,
    JsonError,
    YamlError,
    MacError,
    UrlError,
    ChaChaError,
    RandError,
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorKind::InvalidExtension => f.write_str("InvalidExtension"),
            ErrorKind::InvalidOp => f.write_str("InvalidOp"),
            ErrorKind::MissingArgument => f.write_str("MissingArgument"),
            ErrorKind::InvalidArgument => f.write_str("InvalidArgument"),
            ErrorKind::IoError => f.write_str("IoError"),
            ErrorKind::JsonError => f.write_str("JsonError"),
            ErrorKind::YamlError => f.write_str("YamlError"),
            ErrorKind::MacError => f.write_str("MacError"),
            ErrorKind::UrlError => f.write_str("UrlError"),
            ErrorKind::ChaChaError => f.write_str("ChaChaError"),
            ErrorKind::RandError => f.write_str("RandError"),
        }
    }
}

type BoxDynError = Box<dyn std::error::Error + Send + Sync>;

/// the simple error struct used by the application
///
/// these errors are not really meant to be handled and more for just
/// indicating that there was an error. capable of storing a message
/// and the error the created the struct if provided
pub struct Error {
    pub kind: ErrorKind,
    pub message: Option<String>,
    pub source: Option<BoxDynError>,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn new(kind: ErrorKind) -> Self {
        Error {
            kind,
            message: None,
            source: None,
        }
    }

    pub fn with_error<E>(mut self, source: E) -> Self
    where
        E: Into<BoxDynError>,
    {
        self.source = Some(source.into());
        self
    }

    pub fn with_message<M>(mut self, message: M) -> Self
    where
        M: Into<String>,
    {
        self.message = Some(message.into());
        self
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::new(ErrorKind::IoError).with_error(err)
    }
}

impl From<serde_yml::Error> for Error {
    fn from(err: serde_yml::Error) -> Self {
        Error::new(ErrorKind::YamlError).with_error(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::new(ErrorKind::JsonError).with_error(err)
    }
}

impl From<crate::mac::Error> for Error {
    fn from(err: crate::mac::Error) -> Self {
        Error::new(ErrorKind::MacError).with_error(err)
    }
}

impl From<url::ParseError> for Error {
    fn from(err: url::ParseError) -> Self {
        Error::new(ErrorKind::UrlError).with_error(err)
    }
}

impl From<chacha20poly1305::Error> for Error {
    fn from(err: chacha20poly1305::Error) -> Self {
        Error::new(ErrorKind::ChaChaError).with_error(err)
    }
}

impl From<rand::rand_core::OsError> for Error {
    fn from(err: rand::rand_core::OsError) -> Self {
        Error::new(ErrorKind::RandError).with_error(err)
    }
}

pub mod build {
    use super::{Error, ErrorKind};

    /// common error for providing an invalid argument
    pub fn invalid_argument(arg: String) -> Error {
        let mut msg = String::from("given invalid argument. \"");
        msg.push_str(&arg);
        msg.push('"');

        return Error::new(ErrorKind::InvalidArgument).with_message(msg);
    }

    /// common error when the desired name was not found
    pub fn name_not_found(name: String) -> Error {
        let mut msg = String::from("given name does not exist in file. \"");
        msg.push_str(&name);
        msg.push('"');

        return Error::new(ErrorKind::InvalidArgument).with_message(msg);
    }
}
