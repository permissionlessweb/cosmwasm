mod vesta;
pub(crate) use vesta::{VestaInstance, VestaVerifyingKey};

use crate::{ZkError, ZkResult};

pub trait ConstraintSystemTrait: Send + Sync + std::fmt::Debug + 'static {
  
    fn write(&self) -> ZkResult<()>;
}
pub trait VerifyingKeyTrait: Send + Sync + 'static {
    fn curve_id(&self) -> u32;
    // fn cs(&self) -> impl ConstraintSystemTrait;
    fn verify(
        &self,
        proof: &crate::Proof,
        instances: &[impl Into<crate::AnyInstance>],
    ) -> ZkResult<()>;
    // fn to_bytes(&self) -> ZkResult<Vec<u8>>;
    fn read() -> ZkResult<()>;
    fn write(&self) -> ZkResult<()>;
}

pub trait InstanceTrait: Send + Sync + std::fmt::Debug + 'static {
    fn curve_id(&self) -> u32;
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait ZkCurve: 'static + Clone + Copy + Send + Sync + std::fmt::Debug {
    type Scalar: group::ff::PrimeField + From<u64> + Send + Sync;
    type Affine: pasta_curves::arithmetic::CurveAffine<ScalarExt = Self::Scalar>;

    type Params;
    type Instance;
    type VerifyingKey;
    type ProvingKey;
    type ConstraintSystem;

    const ID: u32;

    fn scalar_from_bytes(bytes: &[u8; 32]) -> Option<Self::Scalar>;
    fn scalar_to_bytes(s: &Self::Scalar) -> [u8; 32];
}

// / Circuit type identifier for VK deserialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CurveType {
    Pasta,
}

impl TryFrom<u8> for CurveType {
    type Error = ZkError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(CurveType::Pasta),
            _ => Err(ZkError::new_err("bad CurveType")),
        }
    }
}
impl Into<u8> for CurveType {
    fn into(self) -> u8 {
        match self {
            CurveType::Pasta => 0,
        }
    }
}
