#[cfg(test)]
mod tests;

use anyhow::Result as AnyResult;

use crate::msg::VKeyType;
use crate::state::{
    MaciParameters, MessageData, Period, PubKey, QuinaryTreeRoot, RoundInfo, VotingTime, Whitelist,
    WhitelistConfig,
};
use crate::utils::uint256_from_hex_string;
use crate::{
    contract::{execute, instantiate, query},
    msg::*,
};
use cosmwasm_std::{Addr, Coin, StdResult, Timestamp, Uint128, Uint256};
use cw_multi_test::{App, AppResponse, ContractWrapper, Executor};
use num_bigint::BigUint;

pub fn uint256_from_decimal_string(decimal_string: &str) -> Uint256 {
    assert!(
        decimal_string.len() <= 77,
        "the decimal length can't abrove 77"
    );

    let decimal_number = BigUint::parse_bytes(decimal_string.as_bytes(), 10)
        .expect("Failed to parse decimal string");

    let byte_array = decimal_number.to_bytes_be();

    let hex_string = hex::encode(byte_array);
    uint256_from_hex_string(&hex_string)
}
pub const MOCK_CONTRACT_ADDR: &str = "cosmos2contract";
// pub const ARCH_DEMON: &str = "aconst";
// pub const ARCH_DECIMALS: u8 = 18;

#[derive(Clone, Debug, Copy)]
pub struct MaciCodeId(u64);

impl MaciCodeId {
    pub fn store_code(app: &mut App) -> Self {
        let contract = ContractWrapper::new(execute, instantiate, query);
        let code_id = app.store_code(Box::new(contract));
        Self(code_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn instantiate_with_no_voting_time(
        self,
        app: &mut App,
        sender: Addr,
        // round_info: Option<RoundInfo>,
        // whitelist: Option<Whitelist>,
        // voting_time: Option<VotingTime>,
        label: &str,
    ) -> AnyResult<MaciContract> {
        let round_info = RoundInfo {
            title: String::from("test_round"),
            description: "".to_string(),
            link: "".to_string(),
        };
        let circuit_type = Uint256::from_u128(0u128);
        MaciContract::instantiate(
            app,
            self,
            sender,
            round_info,
            None,
            None,
            circuit_type,
            label,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn instantiate_with_voting_time(
        self,
        app: &mut App,
        sender: Addr,
        user1: Addr,
        user2: Addr,
        label: &str,
    ) -> AnyResult<MaciContract> {
        let round_info = RoundInfo {
            title: String::from("HackWasm Berlin"),
            description: String::from("Hack In Brelin"),
            link: String::from("https://baidu.com"),
        };
        let whitelist = Some(Whitelist {
            users: vec![
                WhitelistConfig {
                    addr: user1.to_string(),
                    balance: Uint256::from_u128(100u128),
                },
                WhitelistConfig {
                    addr: user2.to_string(),
                    balance: Uint256::from_u128(80u128),
                },
            ],
        });
        let voting_time = Some(VotingTime {
            start_time: Some(Timestamp::from_nanos(1571797424879000000)),
            end_time: Some(Timestamp::from_nanos(1571797429879300000)),
        });
        let circuit_type = Uint256::from_u128(0u128);
        MaciContract::instantiate(
            app,
            self,
            sender,
            round_info,
            whitelist,
            voting_time,
            circuit_type,
            label,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn instantiate_with_wrong_voting_time(
        self,
        app: &mut App,
        sender: Addr,
        user1: Addr,
        user2: Addr,
        label: &str,
    ) -> AnyResult<MaciContract> {
        let round_info = RoundInfo {
            title: String::from("HackWasm Berlin"),
            description: String::from("Hack In Brelin"),
            link: String::from("https://baidu.com"),
        };
        let whitelist = Some(Whitelist {
            users: vec![
                WhitelistConfig {
                    addr: user1.to_string(),
                    balance: Uint256::from_u128(100u128),
                },
                WhitelistConfig {
                    addr: user2.to_string(),
                    balance: Uint256::from_u128(80u128),
                },
            ],
        });
        let voting_time = Some(VotingTime {
            start_time: Some(Timestamp::from_nanos(1571797429879300000)),
            end_time: Some(Timestamp::from_nanos(1571797424879000000)),
        });
        let circuit_type = Uint256::from_u128(0u128);
        MaciContract::instantiate(
            app,
            self,
            sender,
            round_info,
            whitelist,
            voting_time,
            circuit_type,
            label,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn instantiate_with_start_time(
        self,
        app: &mut App,
        sender: Addr,
        user1: Addr,
        user2: Addr,
        label: &str,
    ) -> AnyResult<MaciContract> {
        let round_info = RoundInfo {
            title: String::from("HackWasm Berlin"),
            description: String::from("Hack In Brelin"),
            link: String::from("https://baidu.com"),
        };
        let whitelist = Some(Whitelist {
            users: vec![
                WhitelistConfig {
                    addr: user1.to_string(),
                    balance: Uint256::from_u128(100u128),
                },
                WhitelistConfig {
                    addr: user2.to_string(),
                    balance: Uint256::from_u128(80u128),
                },
            ],
        });
        let voting_time = Some(VotingTime {
            start_time: Some(Timestamp::from_nanos(1571797424879000000)),
            end_time: None,
        });

        let circuit_type = Uint256::from_u128(0u128);
        MaciContract::instantiate(
            app,
            self,
            sender,
            round_info,
            whitelist,
            voting_time,
            circuit_type,
            label,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn instantiate_with_end_time(
        self,
        app: &mut App,
        sender: Addr,
        user1: Addr,
        user2: Addr,
        label: &str,
    ) -> AnyResult<MaciContract> {
        let round_info = RoundInfo {
            title: String::from("HackWasm Berlin"),
            description: String::from("Hack In Brelin"),
            link: String::from("https://baidu.com"),
        };
        let whitelist = Some(Whitelist {
            users: vec![
                WhitelistConfig {
                    addr: user1.to_string(),
                    balance: Uint256::from_u128(100u128),
                },
                WhitelistConfig {
                    addr: user2.to_string(),
                    balance: Uint256::from_u128(80u128),
                },
            ],
        });
        let voting_time = Some(VotingTime {
            start_time: None,
            end_time: Some(Timestamp::from_nanos(1571797429879300000)),
        });

        let circuit_type = Uint256::from_u128(0u128);
        MaciContract::instantiate(
            app,
            self,
            sender,
            round_info,
            whitelist,
            voting_time,
            circuit_type,
            label,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn instantiate_with_voting_time_and_no_whitelist(
        self,
        app: &mut App,
        sender: Addr,
        label: &str,
    ) -> AnyResult<MaciContract> {
        let round_info = RoundInfo {
            title: String::from("HackWasm Berlin"),
            description: String::from("Hack In Brelin"),
            link: String::from("https://baidu.com"),
        };
        let voting_time = Some(VotingTime {
            start_time: Some(Timestamp::from_nanos(1571797424879000000)),
            end_time: Some(Timestamp::from_nanos(1571797429879300000)),
        });

        let circuit_type = Uint256::from_u128(0u128);
        MaciContract::instantiate(
            app,
            self,
            sender,
            round_info,
            None,
            voting_time,
            circuit_type,
            label,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn instantiate_with_voting_time_isqv(
        self,
        app: &mut App,
        sender: Addr,
        user1: Addr,
        user2: Addr,
        label: &str,
    ) -> AnyResult<MaciContract> {
        let round_info = RoundInfo {
            title: String::from("HackWasm Berlin"),
            description: String::from("Hack In Brelin"),
            link: String::from("https://baidu.com"),
        };
        let whitelist = Some(Whitelist {
            users: vec![
                WhitelistConfig {
                    addr: user1.to_string(),
                    balance: Uint256::from_u128(100u128),
                },
                WhitelistConfig {
                    addr: user2.to_string(),
                    balance: Uint256::from_u128(80u128),
                },
            ],
        });
        let voting_time = Some(VotingTime {
            start_time: Some(Timestamp::from_nanos(1571797424879000000)),
            end_time: Some(Timestamp::from_nanos(1571797429879300000)),
        });
        let circuit_type = Uint256::from_u128(1u128);
        MaciContract::instantiate(
            app,
            self,
            sender,
            round_info,
            whitelist,
            voting_time,
            circuit_type,
            label,
        )
    }
}

impl From<MaciCodeId> for u64 {
    fn from(code_id: MaciCodeId) -> Self {
        code_id.0
    }
}

#[derive(Debug, Clone)]
pub struct MaciContract(Addr);

// implement the contract real function, e.g. instantiate, functions in exec, query modules
impl MaciContract {
    pub fn addr(&self) -> Addr {
        self.0.clone()
    }

    #[allow(clippy::too_many_arguments)]
    #[track_caller]
    pub fn instantiate(
        app: &mut App,
        code_id: MaciCodeId,
        sender: Addr,
        round_info: RoundInfo,
        whitelist: Option<Whitelist>,
        voting_time: Option<VotingTime>,
        circuit_type: Uint256,
        label: &str,
    ) -> AnyResult<Self> {
        let parameters = MaciParameters {
            state_tree_depth: Uint256::from_u128(2u128),
            int_state_tree_depth: Uint256::from_u128(1u128),
            message_batch_size: Uint256::from_u128(5u128),
            vote_option_tree_depth: Uint256::from_u128(1u128),
        };
        let init_msg = InstantiateMsg {
                            parameters,
                            coordinator: PubKey {
                                x: uint256_from_decimal_string("3557592161792765812904087712812111121909518311142005886657252371904276697771"),
                                y: uint256_from_decimal_string("4363822302427519764561660537570341277214758164895027920046745209970137856681")
                            },
                            process_vkey: VKeyType {
                                vk_alpha1: "2d4d9aa7e302d9df41749d5507949d05dbea33fbb16c643b22f599a2be6df2e214bedd503c37ceb061d8ec60209fe345ce89830a19230301f076caff004d1926".to_string(),
                                vk_beta_2: "0967032fcbf776d1afc985f88877f182d38480a653f2decaa9794cbc3bf3060c0e187847ad4c798374d0d6732bf501847dd68bc0e071241e0213bc7fc13db7ab304cfbd1e08a704a99f5e847d93f8c3caafddec46b7a0d379da69a4d112346a71739c1b1a457a8c7313123d24d2f9192f896b7c63eea05a9d57f06547ad0cec8".to_string(),
                                vk_gamma_2: "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa".to_string(),
                                vk_delta_2: "2178a9c3805dd82071b2b28bb4c0ffc8178cad913c8c990b98b4863284dc3a5d175c0be554fc060c27c551e5e32effef015b918a0f5a2dc1b92909b8272719301c521d5f6542db5ea4775a42d32159c356a696599c1a3df011ec00559ae1c2b60d860f7e6513a7d20feaeaca401863e35a0f691dd7d30ce06d07946840de1ec8".to_string(),
                                vk_ic0: "19126a54a9b6d0d415f892c246485cb2889487cf9c4a8cd88dab5e1140e1d0630d1d76ef4652df8887c9dc557aa57f25e221db7e5b2e4cf618a362bece107f5c".to_string(),
                                vk_ic1: "0632e625fefc7172e8aec1070c4d32b90b6c482f6f3806773a4c55a03877c2d716cfd935eb3e3883f580c93f56adbf3a253ce3c208c52fb784f9d8fec139c617".to_string(),
                            },
                            qtr_lib: QuinaryTreeRoot {
                                zeros: [
                                    uint256_from_decimal_string("0"),
                                    uint256_from_decimal_string(
                                        "14655542659562014735865511769057053982292279840403315552050801315682099828156",
                                    ),
                                    uint256_from_decimal_string(
                                        "19261153649140605024552417994922546473530072875902678653210025980873274131905",
                                    ),
                                    uint256_from_decimal_string(
                                        "21526503558325068664033192388586640128492121680588893182274749683522508994597",
                                    ),
                                    uint256_from_decimal_string(
                                        "20017764101928005973906869479218555869286328459998999367935018992260318153770",
                                    ),
                                    uint256_from_decimal_string(
                                        "16998355316577652097112514691750893516081130026395813155204269482715045879598",
                                    ),
                                    uint256_from_decimal_string(
                                        "2612442706402737973181840577010736087708621987282725873936541279764292204086",
                                    ),
                                    uint256_from_decimal_string(
                                        "17716535433480122581515618850811568065658392066947958324371350481921422579201",
                                    ),
                                    uint256_from_decimal_string(
                                        "17437916409890180001398333108882255895598851862997171508841759030332444017770",
                                    ),
                                ],
                            },
                            tally_vkey: VKeyType {
                            vk_alpha1: "2d4d9aa7e302d9df41749d5507949d05dbea33fbb16c643b22f599a2be6df2e214bedd503c37ceb061d8ec60209fe345ce89830a19230301f076caff004d1926".to_string(),
                            vk_beta_2: "0967032fcbf776d1afc985f88877f182d38480a653f2decaa9794cbc3bf3060c0e187847ad4c798374d0d6732bf501847dd68bc0e071241e0213bc7fc13db7ab304cfbd1e08a704a99f5e847d93f8c3caafddec46b7a0d379da69a4d112346a71739c1b1a457a8c7313123d24d2f9192f896b7c63eea05a9d57f06547ad0cec8".to_string(),
                            vk_gamma_2: "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa".to_string(),
                            vk_delta_2: "2e9fad39728c543c5213599111e1a44b01720c999a6785e8136c3e3b3bf8e07e248e1933d477969ca6e27cb7a74bca18cac7e3bbdf9371be5c54fe151f6376a30955609ec69b89329322a2f435b706ca248d1312c7513853a50ef37ed0f7826c25a5c57bf07789d89e538bc24017cf2722811f21480b0bb8030ed0028ecb7cd8".to_string(),
                            vk_ic0: "1bc1a1a3444256469c07cd6f4d1cfd9f7c9ddce596a306e0af077ca9e9c0fe9602db2a9aecef76a9dc4c19bf88c0099b04fc75410cc9004f0966440825e3790a".to_string(),
                            vk_ic1: "05b8b475f2bfedba4fa04ab1972006da9764c2c3e6fb65d6dd0aac938fd298112a560e13770b06a3f709a49fddf016331ea205fa125026993f6666eff69f4def".to_string()
                            },
                            max_vote_options: Uint256::from_u128(5u128),
                            round_info,
                            whitelist,
                            voting_time,
                            circuit_type
        };

        app.instantiate_contract(
            code_id.0,
            Addr::unchecked(sender),
            &init_msg,
            &[],
            label,
            None,
        )
        .map(Self::from)
    }

    #[track_caller]
    pub fn sign_up(&self, app: &mut App, sender: Addr, pubkey: PubKey) -> AnyResult<AppResponse> {
        app.execute_contract(sender, self.addr(), &ExecuteMsg::SignUp { pubkey }, &[])
    }

    #[track_caller]
    pub fn publish_message(
        &self,
        app: &mut App,
        sender: Addr,
        message: MessageData,
        enc_pub_key: PubKey,
    ) -> AnyResult<AppResponse> {
        app.execute_contract(
            sender,
            self.addr(),
            &ExecuteMsg::PublishMessage {
                message,
                enc_pub_key,
            },
            &[],
        )
    }

    #[track_caller]
    pub fn set_round_info(&self, app: &mut App, sender: Addr) -> AnyResult<AppResponse> {
        app.execute_contract(
            sender,
            self.addr(),
            &ExecuteMsg::SetRoundInfo {
                round_info: RoundInfo {
                    title: String::from("TestRound2"),
                    description: String::from(""),
                    link: String::from("https://github.com"),
                },
            },
            &[],
        )
    }

    #[track_caller]
    pub fn set_empty_round_info(&self, app: &mut App, sender: Addr) -> AnyResult<AppResponse> {
        app.execute_contract(
            sender,
            self.addr(),
            &ExecuteMsg::SetRoundInfo {
                round_info: RoundInfo {
                    title: String::from(""),
                    description: String::from("Hello"),
                    link: String::from("https://github.com"),
                },
            },
            &[],
        )
    }

    #[track_caller]
    pub fn set_whitelist(&self, app: &mut App, sender: Addr) -> AnyResult<AppResponse> {
        app.execute_contract(
            sender,
            self.addr(),
            &ExecuteMsg::SetWhitelists {
                whitelists: Whitelist {
                    users: vec![
                        WhitelistConfig {
                            addr: user1().to_string(),
                            balance: Uint256::from_u128(100u128),
                        },
                        WhitelistConfig {
                            addr: user2().to_string(),
                            balance: Uint256::from_u128(80u128),
                        },
                    ],
                },
            },
            &[],
        )
    }

    #[track_caller]
    pub fn set_vote_option_map(&self, app: &mut App, sender: Addr) -> AnyResult<AppResponse> {
        app.execute_contract(
            sender,
            self.addr(),
            &ExecuteMsg::SetVoteOptionsMap {
                vote_option_map: vec![
                    String::from("did_not_vote"),
                    String::from("yes"),
                    String::from("no"),
                    String::from("no_with_veto"),
                    String::from("abstain"),
                ],
            },
            &[],
        )
    }

    #[track_caller]
    pub fn start_voting(&self, app: &mut App, sender: Addr) -> AnyResult<AppResponse> {
        app.execute_contract(sender, self.addr(), &ExecuteMsg::StartVotingPeriod {}, &[])
    }

    #[track_caller]
    pub fn stop_voting(&self, app: &mut App, sender: Addr) -> AnyResult<AppResponse> {
        app.execute_contract(
            sender,
            self.addr(),
            &ExecuteMsg::StopVotingPeriod {
                // max_vote_options: Uint256::from_u128(5u128),
            },
            &[],
        )
    }

    #[track_caller]
    pub fn start_process(&self, app: &mut App, sender: Addr) -> AnyResult<AppResponse> {
        app.execute_contract(sender, self.addr(), &ExecuteMsg::StartProcessPeriod {}, &[])
    }

    #[track_caller]
    pub fn process_message(
        &self,
        app: &mut App,
        sender: Addr,
        new_state_commitment: Uint256,
        proof: ProofType,
    ) -> AnyResult<AppResponse> {
        app.execute_contract(
            sender,
            self.addr(),
            &ExecuteMsg::ProcessMessage {
                new_state_commitment,
                proof,
            },
            &[],
        )
    }

    #[track_caller]
    pub fn stop_processing(&self, app: &mut App, sender: Addr) -> AnyResult<AppResponse> {
        app.execute_contract(
            sender,
            self.addr(),
            &ExecuteMsg::StopProcessingPeriod {},
            &[],
        )
    }

    #[track_caller]
    pub fn process_tally(
        &self,
        app: &mut App,
        sender: Addr,
        new_tally_commitment: Uint256,
        proof: ProofType,
    ) -> AnyResult<AppResponse> {
        app.execute_contract(
            sender,
            self.addr(),
            &ExecuteMsg::ProcessTally {
                new_tally_commitment,
                proof,
            },
            &[],
        )
    }

    #[track_caller]
    pub fn stop_tallying(
        &self,
        app: &mut App,
        sender: Addr,
        results: Vec<Uint256>,
        salt: Uint256,
    ) -> AnyResult<AppResponse> {
        app.execute_contract(
            sender,
            self.addr(),
            &ExecuteMsg::StopTallyingPeriod { results, salt },
            &[],
        )
    }

    #[track_caller]
    pub fn grant(&self, app: &mut App, sender: Addr, sent: &[Coin]) -> AnyResult<AppResponse> {
        app.execute_contract(
            sender,
            self.addr(),
            &ExecuteMsg::Grant {
                max_amount: Uint128::from(10000000000000u128),
            },
            sent,
        )
    }

    #[track_caller]
    pub fn revoke(&self, app: &mut App, sender: Addr) -> AnyResult<AppResponse> {
        app.execute_contract(sender, self.addr(), &ExecuteMsg::Revoke {}, &[])
    }

    #[track_caller]
    pub fn bond(&self, app: &mut App, sender: Addr, sent: &[Coin]) -> AnyResult<AppResponse> {
        app.execute_contract(sender, self.addr(), &ExecuteMsg::Bond {}, sent)
    }

    #[track_caller]
    pub fn withdraw(&self, app: &mut App, sender: Addr) -> AnyResult<AppResponse> {
        app.execute_contract(
            sender,
            self.addr(),
            &ExecuteMsg::Withdraw { amount: None },
            &[],
        )
    }

    pub fn msg_length(&self, app: &App) -> StdResult<Uint256> {
        app.wrap()
            .query_wasm_smart(self.addr(), &QueryMsg::GetMsgChainLength {})
    }
    pub fn num_sign_up(&self, app: &App) -> StdResult<Uint256> {
        app.wrap()
            .query_wasm_smart(self.addr(), &QueryMsg::GetNumSignUp {})
    }

    pub fn vote_option_map(&self, app: &App) -> StdResult<Vec<String>> {
        app.wrap()
            .query_wasm_smart(self.addr(), &QueryMsg::VoteOptionMap {})
    }

    pub fn max_vote_options(&self, app: &App) -> StdResult<Uint256> {
        app.wrap()
            .query_wasm_smart(self.addr(), &QueryMsg::MaxVoteOptions {})
    }

    pub fn get_all_result(&self, app: &App) -> StdResult<Uint256> {
        app.wrap()
            .query_wasm_smart(self.addr(), &QueryMsg::GetAllResult {})
    }

    pub fn get_voting_time(&self, app: &App) -> StdResult<VotingTime> {
        app.wrap()
            .query_wasm_smart(self.addr(), &QueryMsg::GetVotingTime {})
    }

    pub fn get_period(&self, app: &App) -> StdResult<Period> {
        app.wrap()
            .query_wasm_smart(self.addr(), &QueryMsg::GetPeriod {})
    }

    pub fn get_round_info(&self, app: &App) -> StdResult<RoundInfo> {
        app.wrap()
            .query_wasm_smart(self.addr(), &QueryMsg::GetRoundInfo {})
    }

    pub fn query_total_feegrant(&self, app: &App) -> StdResult<Uint128> {
        app.wrap()
            .query_wasm_smart(self.addr(), &QueryMsg::QueryTotalFeeGrant {})
    }
}

impl From<Addr> for MaciContract {
    fn from(value: Addr) -> Self {
        Self(value)
    }
}

pub fn user1() -> Addr {
    Addr::unchecked("0")
}

pub fn user2() -> Addr {
    Addr::unchecked("1")
}

pub fn owner() -> Addr {
    Addr::unchecked("dora1qdagdkg9me4253h9qyvx83sd4gpta6rzh2fa0j")
}

// pub fn parent() -> Addr {
//     Addr::unchecked("inj1g9v8suckezwx93zypckd4xg03r26h6ejlmsptz")
// }
