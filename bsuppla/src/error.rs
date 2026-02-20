use std::error::Error;
use std::io;

pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

pub fn err(msg: impl Into<String>) -> Box<dyn Error + Send + Sync> {
    io::Error::other(msg.into()).into()
}
