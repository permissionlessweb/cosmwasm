// source: https://gist.github.com/reecepbcups/457241fd91e33f762eda4981325c3aeb
pub mod contract;
pub mod error;
pub mod msg;
pub mod recurse;

pub use crate::error::ContractError;

#[cfg(test)]
mod tests {
    use super::contract::{execute, instantiate, query};
    use super::msg::{DepthResponse, ExecuteMsg, InstantiateMsg, QueryMsg};
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::{from_json, Addr};

    #[test]
    fn shallow_recursion_survives() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let sender = Addr::unchecked("sender");
        let info = message_info(&sender, &[]);
        instantiate(deps.as_mut(), env.clone(), info.clone(), InstantiateMsg {}).unwrap();
        let res = execute(
            deps.as_mut(),
            env,
            info,
            ExecuteMsg::Recurse { depth: 100 },
        )
        .unwrap();
        let executed = res
            .attributes
            .iter()
            .find(|a| a.key == "executed")
            .unwrap()
            .value
            .clone();
        // executed = depth + 1 (the n == 0 base frame)
        assert_eq!(executed, "101");
    }

    #[test]
    fn query_reports_executed_frames() {
        let deps = mock_dependencies();
        let env = mock_env();
        let bin = query(deps.as_ref(), env, QueryMsg::MaxDepth { depth: 64 }).unwrap();
        let resp: DepthResponse = from_json(bin).unwrap();
        assert_eq!(resp.requested, 64);
        assert_eq!(resp.executed, 65);
    }
}
