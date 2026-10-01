use cosmwasm_schema::{cw_serde, QueryResponses};

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    /// Recurse `depth` Wasm frames inside `deep`, plus the export and wrapper.
    Recurse { depth: u64 },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// Same recursion as execute, in a read-only call.
    #[returns(DepthResponse)]
    MaxDepth { depth: u64 },
}

#[cw_serde]
pub struct DepthResponse {
    pub requested: u64,
    pub executed: u64,
    /// Fold of the per-frame scalars. Returned so those locals stay live.
    pub checksum: u64,
}
