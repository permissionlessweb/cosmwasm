use std::{array::TryFromSliceError, io::Error};

use halo2_proofs::plonk;
use thiserror::Error;

pub type ZkResult<T> = core::result::Result<T, ZkError>;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ZkError {
    #[error("Aborted: {}", err)]
    Aborted { err: String },
    #[error("Invalid Scalar")]
    InvalidScalar,
    #[error("CurveMismatch")]
    CurveMismatch,
    #[error("UnsupportedCurve: {0}")]
    UnsupportedCurve(u32),
    #[error("Aborted: {}", err)]
    IoErr { err: Error },
    #[error("{0}")]
    TryFromSliceError(#[from] TryFromSliceError),
    #[error("{0}")]
    PlonkError(#[from] plonk::Error),
    #[error("calculated hash doesn't match stored hash")]
    IntegrityErr {},
}

impl ZkError {
    pub fn new_err<T: Into<String>>(e: T) -> Self {
        ZkError::Aborted { err: e.into() }
    }
    pub fn new_io<T: Into<Error>>(e: T) -> Self {
        ZkError::IoErr { err: e.into() }
    }
}

impl From<Error> for ZkError {
    fn from(e: Error) -> Self {
        ZkError::new_io(e)
    }
}
