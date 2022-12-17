use std::error::Error as StdError;
use std::fmt::{self, Display, Formatter};
use std::result::Result as StdResult;

use crate::ursa::errors::{UrsaCryptoError, UrsaCryptoErrorKind};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    // General errors
    Input,
    IOError,
    InvalidState,
    Unexpected,
    // Credential/proof errors
    CredentialRevoked,
    InvalidUserRevocId,
    ProofRejected,
    RevocationRegistryFull,
}

impl ErrorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Input => "Input error",
            Self::IOError => "IO error",
            Self::InvalidState => "Invalid state",
            Self::Unexpected => "Unexpected error",
            Self::CredentialRevoked => "Credential revoked",
            Self::InvalidUserRevocId => "Invalid revocation accumulator index",
            Self::ProofRejected => "Proof rejected",
            Self::RevocationRegistryFull => "Revocation registry full",
        }
    }
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The standard crate error type
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    pub cause: Option<Box<dyn StdError + Send + Sync + 'static>>,
    pub message: Option<String>,
    // backtrace (when supported)
}

impl Error {
    pub fn from_msg<T: Into<String>>(kind: ErrorKind, msg: T) -> Self {
        Self {
            kind,
            cause: None,
            message: Some(msg.into()),
        }
    }

    pub fn from_opt_msg<T: Into<String>>(kind: ErrorKind, msg: Option<T>) -> Self {
        Self {
            kind,
            cause: None,
            message: msg.map(Into::into),
        }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn with_cause<T: Into<Box<dyn StdError + Send + Sync>>>(mut self, err: T) -> Self {
        self.cause = Some(err.into());
        self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.kind, &self.message) {
            (ErrorKind::Input, None) => write!(f, "{}", self.kind),
            (ErrorKind::Input, Some(msg)) => f.write_str(msg),
            (kind, None) => write!(f, "{kind}"),
            (kind, Some(msg)) => write!(f, "{kind}: {msg}"),
        }?;
        if let Some(ref source) = self.cause {
            write!(f, " [{source}]")?;
        }
        Ok(())
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.cause
            .as_ref()
            .map(|err| unsafe { std::mem::transmute(&**err) })
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.message == other.message
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self {
            kind,
            cause: None,
            message: None,
        }
    }
}

impl From<indy_utils::ValidationError> for Error {
    fn from(err: indy_utils::ValidationError) -> Self {
        Error::from_opt_msg(ErrorKind::Input, err.context)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::from(ErrorKind::IOError).with_cause(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        // FIXME could be input or output...
        Error::from(ErrorKind::Input).with_cause(err)
    }
}

impl From<UrsaCryptoError> for Error {
    fn from(err: UrsaCryptoError) -> Self {
        // let message = format!("Ursa Crypto Error: {}", Fail::iter_causes(&err).map(|e| e.to_string()).collect::<String>());
        let message = err.to_string();
        let kind = match err.kind() {
            UrsaCryptoErrorKind::InvalidState => ErrorKind::InvalidState,
            UrsaCryptoErrorKind::InvalidStructure => ErrorKind::Input,
            UrsaCryptoErrorKind::IOError => ErrorKind::IOError,
            UrsaCryptoErrorKind::InvalidRevocationAccumulatorIndex => ErrorKind::InvalidUserRevocId,
            UrsaCryptoErrorKind::RevocationAccumulatorIsFull => ErrorKind::RevocationRegistryFull,
            UrsaCryptoErrorKind::ProofRejected => ErrorKind::ProofRejected,
            UrsaCryptoErrorKind::CredentialRevoked => ErrorKind::CredentialRevoked,
            UrsaCryptoErrorKind::InvalidParam(_) => ErrorKind::Input,
        };
        Error::from_msg(kind, message)
    }
}

impl<M> From<(ErrorKind, M)> for Error
where
    M: fmt::Display + Send + Sync + 'static,
{
    fn from((kind, msg): (ErrorKind, M)) -> Error {
        Error::from_msg(kind, msg.to_string())
    }
}

macro_rules! err_msg {
    () => {
        $crate::error::Error::from($crate::error::ErrorKind::Input)
    };
    ($kind:ident) => {
        $crate::error::Error::from($crate::error::ErrorKind::$kind)
    };
    ($kind:ident, $($args:tt)+) => {
        $crate::error::Error::from_msg($crate::error::ErrorKind::$kind, format!($($args)+))
    };
    ($($args:tt)+) => {
        $crate::error::Error::from_msg($crate::error::ErrorKind::Input, format!($($args)+))
    };
}

macro_rules! err_map {
    ($($params:tt)*) => {
        |err| err_msg!($($params)*).with_cause(err)
    };
}

pub trait ResultExt<T, E> {
    fn map_err_string(self) -> StdResult<T, String>;
    fn map_input_err<F, M>(self, mapfn: F) -> Result<T>
    where
        F: FnOnce() -> M,
        M: fmt::Display + Send + Sync + 'static;
    fn with_err_msg<M>(self, kind: ErrorKind, msg: M) -> Result<T>
    where
        M: fmt::Display + Send + Sync + 'static;
    fn with_input_err<M>(self, msg: M) -> Result<T>
    where
        M: fmt::Display + Send + Sync + 'static;
}

impl<T, E> ResultExt<T, E> for StdResult<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn map_err_string(self) -> StdResult<T, String> {
        self.map_err(|err| err.to_string())
    }

    fn map_input_err<F, M>(self, mapfn: F) -> Result<T>
    where
        F: FnOnce() -> M,
        M: fmt::Display + Send + Sync + 'static,
    {
        self.map_err(|err| Error::from_msg(ErrorKind::Input, mapfn().to_string()).with_cause(err))
    }

    fn with_err_msg<M>(self, kind: ErrorKind, msg: M) -> Result<T>
    where
        M: fmt::Display + Send + Sync + 'static,
    {
        self.map_err(|err| Error::from_msg(kind, msg.to_string()).with_cause(err))
    }

    #[inline]
    fn with_input_err<M>(self, msg: M) -> Result<T>
    where
        M: fmt::Display + Send + Sync + 'static,
    {
        self.map_err(|err| Error::from_msg(ErrorKind::Input, msg.to_string()).with_cause(err))
    }
}
