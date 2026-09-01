use alloc::string::String;
use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Macho(String),
    Metadata(String),
    NoCode,
    SymbolNotFound(String),
    EmptyFunction,
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Macho(m) => write!(f, "macho: {m}"),
            Self::Metadata(m) => write!(f, "metadata: {m}"),
            Self::NoCode => write!(f, "no executable code"),
            Self::SymbolNotFound(s) => write!(f, "symbol not found: {s}"),
            Self::EmptyFunction => write!(f, "empty function"),
            Self::Other(m) => write!(f, "{m}"),
        }
    }
}

impl From<macho_core::Error> for Error {
    fn from(e: macho_core::Error) -> Self {
        Self::Macho(alloc::format!("{e}"))
    }
}

impl From<apple_metadata::Error> for Error {
    fn from(e: apple_metadata::Error) -> Self {
        Self::Metadata(alloc::format!("{e}"))
    }
}
