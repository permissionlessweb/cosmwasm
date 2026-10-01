use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
};

use crate::error::ContractError;
use crate::msg::{DepthResponse, ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::recurse::recurse;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    Ok(Response::new().add_attribute("action", "instantiate"))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Recurse { depth } => {
            let (executed, checksum) = recurse(depth);
            Ok(Response::new()
                .add_attribute("action", "recurse")
                .add_attribute("requested", depth.to_string())
                .add_attribute("executed", executed.to_string())
                .add_attribute("checksum", checksum.to_string()))
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::MaxDepth { depth } => {
            let (executed, checksum) = recurse(depth);
            to_json_binary(&DepthResponse {
                requested: depth,
                executed,
                checksum,
            })
        }
    }
}
