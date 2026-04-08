use std::io::Error;

use thiserror::Error;

pub type ZkResult<T> = core::result::Result<T, ZkError>;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ZkError {
    #[error("Aborted: {}", msg)]
    Aborted { msg: String },
    #[error("Aborted: {}", msg)]
    IoErr { msg: Error },
}

impl ZkError {
    pub fn new_err<T: Into<String>>(e: T) -> Self {
        ZkError::Aborted { msg: e.into() }
    }
    pub fn from_io<T: Into<Error>>(e: T) -> Self {
        ZkError::IoErr { msg: e.into() }
    }
}

impl From<Error> for ZkError {
    fn from(e: Error) -> Self {
        ZkError::from_io(e)
    }
}
