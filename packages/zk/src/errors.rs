use std::{array::TryFromSliceError, io::Error};

use thiserror::Error;

pub type ZkResult<T> = core::result::Result<T, ZkError>;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ZkError {
    #[error("Aborted: {}", err)]
    Aborted { err: String },
    #[error("Aborted: {}", err)]
    IoErr { err: Error },
    #[error("{0}")]
    TryFromSliceError(#[from] TryFromSliceError),
    #[error("Hash doesn't match stored data")]
    IntegrityErr {},
}

impl ZkError {
    pub fn new_err<T: Into<String>>(e: T) -> Self {
        ZkError::Aborted { err: e.into() }
    }
    pub fn from_io<T: Into<Error>>(e: T) -> Self {
        ZkError::IoErr { err: e.into() }
    }
}

impl From<Error> for ZkError {
    fn from(e: Error) -> Self {
        ZkError::from_io(e)
    }
}
