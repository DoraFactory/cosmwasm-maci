#[cfg(test)]
mod tests;

use anyhow::Result as AnyResult;

use crate::msg::Groth16VKeyType;
use crate::state::{
    MaciParameters, MessageData, Period, PubKey, QuinaryTreeRoot, RoundInfo, VotingPowerMode,
    VotingTime,
};
use crate::utils::uint256_from_hex_string;
use crate::{
    contract::{execute, instantiate, query},
    msg::*,
};
use cosmwasm_std::testing::{MockApi, MockStorage};
use cosmwasm_std::{Addr, Coin, Empty, StdResult, Timestamp, Uint128, Uint256};
use serde::{Deserialize, Serialize};
// use cosmwasm_std::{Addr, Coin, StdResult, Timestamp, Uint128, Uint256};
use cw_multi_test::{
    no_init, AppBuilder, AppResponse, BankKeeper, ContractWrapper, DistributionKeeper, Executor,
    FailingModule, GovFailingModule, IbcFailingModule, StakeKeeper, StargateAccepting, WasmKeeper,
};
// use cw_multi_test::{App, AppResponse, ContractWrapper, Executor};
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

pub type App<ExecC = Empty, QueryC = Empty> = cw_multi_test::App<
    BankKeeper,
    MockApi,
    MockStorage,
    FailingModule<ExecC, QueryC, Empty>,
    WasmKeeper<ExecC, QueryC>,
    StakeKeeper,
    DistributionKeeper,
    IbcFailingModule,
    GovFailingModule,
    StargateAccepting,
>;

pub fn create_app() -> App {
    AppBuilder::new()
        .with_stargate(StargateAccepting)
        .build(no_init)
}

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
        MaciContract::instantiate(app, self, sender, round_info, None, circuit_type, label)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn instantiate_with_voting_time(
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
            voting_time,
            circuit_type,
            label,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn instantiate_with_voting_time_plonk(
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
        MaciContract::instantiate_plonk(
            app,
            self,
            sender,
            round_info,
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
        label: &str,
    ) -> AnyResult<MaciContract> {
        let round_info = RoundInfo {
            title: String::from("HackWasm Berlin"),
            description: String::from("Hack In Brelin"),
            link: String::from("https://baidu.com"),
        };

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
        label: &str,
    ) -> AnyResult<MaciContract> {
        let round_info = RoundInfo {
            title: String::from("HackWasm Berlin"),
            description: String::from("Hack In Brelin"),
            link: String::from("https://baidu.com"),
        };

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
        label: &str,
    ) -> AnyResult<MaciContract> {
        let round_info = RoundInfo {
            title: String::from("HackWasm Berlin"),
            description: String::from("Hack In Brelin"),
            link: String::from("https://baidu.com"),
        };

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
        let circuit_type = Uint256::from_u128(1u128);
        MaciContract::instantiate(
            app,
            self,
            sender,
            round_info,
            voting_time,
            circuit_type,
            label,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn instantiate_with_wrong_circuit_type(
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
        let circuit_type = Uint256::from_u128(2u128);
        MaciContract::instantiate(
            app,
            self,
            sender,
            round_info,
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
        voting_time: Option<VotingTime>,
        circuit_type: Uint256,
        label: &str,
    ) -> AnyResult<Self> {
        let init_msg = InstantiateMsg {
            coordinator: PubKey {
                x: uint256_from_decimal_string(
                    "3557592161792765812904087712812111121909518311142005886657252371904276697771",
                ),
                y: uint256_from_decimal_string(
                    "4363822302427519764561660537570341277214758164895027920046745209970137856681",
                ),
            },
            certification_system: Uint256::from_u128(0u128),
            // max_vote_options: Uint256::from_u128(5u128),
            vote_option_map: vec![
                "1".to_string(),
                "2".to_string(),
                "3".to_string(),
                "4".to_string(),
                "5".to_string(),
            ],
            round_info,
            voting_time,
            circuit_type,
            whitelist_backend_pubkey: whitelist_pubkey(),
            whitelist_ecosystem: whitelist_ecosystem(),
            whitelist_snapshot_height: whitelist_snapshot_height(),
            whitelist_voting_power_args: VotingPowerArgs {
                mode: whitelist_voting_power_mode(),
                slope: whitelist_slope(),
                threshold: whitelist_threshold(),
            },
            feegrant_operator: owner(),
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

    #[allow(clippy::too_many_arguments)]
    #[track_caller]
    pub fn instantiate_plonk(
        app: &mut App,
        code_id: MaciCodeId,
        sender: Addr,
        round_info: RoundInfo,
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
            coordinator: PubKey {
                x: uint256_from_decimal_string(
                    "3557592161792765812904087712812111121909518311142005886657252371904276697771",
                ),
                y: uint256_from_decimal_string(
                    "4363822302427519764561660537570341277214758164895027920046745209970137856681",
                ),
            },
            certification_system: Uint256::from_u128(1u128), // plonk system
            vote_option_map: vec![
                "1".to_string(),
                "2".to_string(),
                "3".to_string(),
                "4".to_string(),
                "5".to_string(),
            ],
            round_info,
            voting_time,
            circuit_type,
            whitelist_backend_pubkey: whitelist_pubkey(),
            whitelist_ecosystem: whitelist_ecosystem(),
            whitelist_snapshot_height: whitelist_snapshot_height(),
            whitelist_voting_power_args: VotingPowerArgs {
                mode: whitelist_voting_power_mode(),
                slope: whitelist_slope(),
                threshold: whitelist_threshold(),
            },
            feegrant_operator: owner(),
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
    pub fn sign_up(
        &self,
        app: &mut App,
        sender: Addr,
        pubkey: PubKey,
        amount: Uint256,
        certificate: String,
    ) -> AnyResult<AppResponse> {
        app.execute_contract(
            sender,
            self.addr(),
            &ExecuteMsg::SignUp {
                pubkey,
                amount,
                certificate,
            },
            &[],
        )
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

    // #[track_caller]
    // pub fn set_whitelist(&self, app: &mut App, sender: Addr) -> AnyResult<AppResponse> {
    //     app.execute_contract(
    //         sender,
    //         self.addr(),
    //         &ExecuteMsg::SetWhitelists {
    //             whitelists: Whitelist {
    //                 users: vec![
    //                     WhitelistBase {
    //                         addr: user1().to_string(),
    //                         balance: Uint256::from_u128(100u128),
    //                     },
    //                     WhitelistBase {
    //                         addr: user2().to_string(),
    //                         balance: Uint256::from_u128(80u128),
    //                     },
    //                 ],
    //             },
    //         },
    //         &[],
    //     )
    // }

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
    pub fn set_vote_option_map_with_list(&self, app: &mut App, sender: Addr, vote_option_map: Vec<String>) -> AnyResult<AppResponse> {
        app.execute_contract(
            sender,
            self.addr(),
            &ExecuteMsg::SetVoteOptionsMap {
                vote_option_map,
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
        proof: Groth16ProofType,
    ) -> AnyResult<AppResponse> {
        app.execute_contract(
            sender,
            self.addr(),
            &ExecuteMsg::ProcessMessage {
                new_state_commitment,
                groth16_proof: Some(proof),
                plonk_proof: None,
            },
            &[],
        )
    }

    #[track_caller]
    pub fn process_message_plonk(
        &self,
        app: &mut App,
        sender: Addr,
        new_state_commitment: Uint256,
        proof: PlonkProofType,
    ) -> AnyResult<AppResponse> {
        app.execute_contract(
            sender,
            self.addr(),
            &ExecuteMsg::ProcessMessage {
                new_state_commitment,
                groth16_proof: None,
                plonk_proof: Some(proof),
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
        proof: Groth16ProofType,
    ) -> AnyResult<AppResponse> {
        app.execute_contract(
            sender,
            self.addr(),
            &ExecuteMsg::ProcessTally {
                new_tally_commitment,
                groth16_proof: Some(proof),
                plonk_proof: None,
            },
            &[],
        )
    }

    #[track_caller]
    pub fn process_tally_plonk(
        &self,
        app: &mut App,
        sender: Addr,
        new_tally_commitment: Uint256,
        proof: PlonkProofType,
    ) -> AnyResult<AppResponse> {
        app.execute_contract(
            sender,
            self.addr(),
            &ExecuteMsg::ProcessTally {
                new_tally_commitment,
                groth16_proof: None,
                plonk_proof: Some(proof),
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

    // #[track_caller]
    // pub fn grant(&self, app: &mut App, sender: Addr, sent: &[Coin]) -> AnyResult<AppResponse> {
    //     app.execute_contract(
    //         sender,
    //         self.addr(),
    //         &ExecuteMsg::Grant {
    //             max_amount: Uint128::from(10000000000000u128),
    //         },
    //         sent,
    //     )
    // }

    // #[track_caller]
    // pub fn revoke(&self, app: &mut App, sender: Addr) -> AnyResult<AppResponse> {
    //     app.execute_contract(sender, self.addr(), &ExecuteMsg::Revoke {}, &[])
    // }

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

    pub fn query_is_whitelist(
        &self,
        app: &App,
        sender: String,
        amount: Uint256,
        certificate: String,
    ) -> StdResult<bool> {
        app.wrap().query_wasm_smart(
            self.addr(),
            &QueryMsg::IsWhiteList {
                sender,
                amount,
                certificate,
            },
        )
    }

    pub fn query_white_balance_of(
        &self,
        app: &App,
        sender: String,
        amount: Uint256,
        certificate: String,
    ) -> StdResult<Uint256> {
        app.wrap().query_wasm_smart(
            self.addr(),
            &QueryMsg::WhiteBalanceOf {
                sender,
                amount,
                certificate,
            },
        )
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

pub fn user3() -> Addr {
    Addr::unchecked("2")
}

pub fn owner() -> Addr {
    Addr::unchecked("dora1qdagdkg9me4253h9qyvx83sd4gpta6rzh2fa0j")
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Certificate {
    pub certificate: String,
    pub amount: Uint256,
}

pub fn match_user_certificate(index: usize) -> Certificate {
    match index {
        0 => user1_certificate(),
        1 => user2_certificate(),
        _ => panic!("Invalid index"),
    }
}

pub fn user1_certificate() -> Certificate {
    Certificate {
        certificate: "/3aY9IIFNNUtwLVHz1i+q+3Hc72yW1XYtFn1SnBZ6GsNUoZpdRTH7gUXz6cyKcJdHviA+pXmebNVXsw0xi1Gdg==".to_string(),
        amount: Uint256::from_u128(100000000u128),
    }
}

pub fn user2_certificate() -> Certificate {
    Certificate {
        certificate: "WX+mefbste0fmQZyxfuPjKjFmea7bTJALptAtrUlqwcKi780BtWN3vTENsvVUVmd5a0lYJXNJ5Cqyjigj6JzOQ==".to_string(),
        amount: Uint256::from_u128(80000000u128),
    }
}

pub fn user2_certificate_before() -> Certificate {
    Certificate {
        certificate: "9N+0uBmu7b2Sr2ibC0ViOQ00z7LZwrTJDZmoGit8TScDDzbjXUmOkB4hLKSnLEORX7ITYbeG9409VL3OLCZdag==".to_string(),
        amount: Uint256::from_u128(100000000u128),
    }
}

pub fn user3_certificate_before() -> Certificate {
    Certificate {
        certificate: "9N+0uBmu7b2Sr2ibC0ViOQ00z7LZwrTJDZmoGit8TScDDzbjXUmOkB4hLKSnLEORX7ITYbeG9409VL3OLCZdag==".to_string(),
        amount: Uint256::from_u128(0u128),
    }
}

pub fn whitelist_pubkey() -> String {
    "AoYo/zENN/JquagPdG0/NMbWBBYxOM8BVN677mBXJKJQ".to_string()
}

pub fn whitelist_ecosystem() -> String {
    String::from("cosmoshub")
}

pub fn whitelist_snapshot_height() -> Uint256 {
    Uint256::from(7166000u128)
}

pub fn whitelist_slope() -> Uint256 {
    Uint256::from_u128(1000000u128)
}

pub fn whitelist_threshold() -> Uint256 {
    Uint256::from_u128(1000000u128)
}

pub fn whitelist_voting_power_mode() -> VotingPowerMode {
    VotingPowerMode::Slope
}
