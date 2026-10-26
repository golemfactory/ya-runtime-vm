use alloc::string::String;
use core::fmt;

#[derive(Debug)]
pub struct Error {
    pub errno: Option<rustix::io::Errno>,
    message: String,
}
pub type Result<T> = core::result::Result<T, Error>;
impl Error {
    pub fn message(message: String) -> Self {
        Self {
            errno: None,
            message,
        }
    }
    fn context(mut self, context: impl fmt::Display) -> Self {
        self.message = format!("{context}: {}", self.message);
        self
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl core::error::Error for Error {}
impl From<rustix::io::Errno> for Error {
    fn from(errno: rustix::io::Errno) -> Self {
        Self {
            errno: Some(errno),
            message: format!("{errno}"),
        }
    }
}
macro_rules! convert {($($ty:ty),*)=>{$(impl From<$ty> for Error {fn from(e:$ty)->Self {Self::message(format!("{e}"))}})*};}
convert!(
    alloc::string::FromUtf8Error,
    alloc::ffi::NulError,
    core::str::Utf8Error,
    core::num::ParseIntError,
    core::net::AddrParseError,
    core::array::TryFromSliceError,
    ya_vm_agent_protocol::CodecError,
    ya_vm_agent_protocol::FrameSizeError
);

pub trait Context<T> {
    fn context(self, context: impl fmt::Display) -> Result<T>;
    fn with_context(self, context: impl FnOnce() -> String) -> Result<T>;
}
impl<T, E: Into<Error>> Context<T> for core::result::Result<T, E> {
    fn context(self, context: impl fmt::Display) -> Result<T> {
        self.map_err(|e| e.into().context(context))
    }
    fn with_context(self, context: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|e| e.into().context(context()))
    }
}
impl<T> Context<T> for Option<T> {
    fn context(self, context: impl fmt::Display) -> Result<T> {
        self.ok_or_else(|| Error::message(format!("{context}")))
    }
    fn with_context(self, context: impl FnOnce() -> String) -> Result<T> {
        self.ok_or_else(|| Error::message(context()))
    }
}
#[macro_export]
macro_rules! bail {($($arg:tt)*)=>{return Err($crate::error::Error::message(alloc::format!($($arg)*)))};}
#[macro_export]
macro_rules! ensure {($condition:expr,$($arg:tt)*)=>{if !$condition {$crate::bail!($($arg)*);}};}
