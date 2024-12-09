#[cfg(test)]
mod tests;

use anyhow::Result as AnyResult;

use crate::msg::Groth16VKeyType;
use crate::state::{
    MaciParameters, MessageData, Period, PubKey, QuinaryTreeRoot, RoundInfo, VotingTime,
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
                            groth16_process_vkey: Some(Groth16VKeyType {
                                vk_alpha1: "2d4d9aa7e302d9df41749d5507949d05dbea33fbb16c643b22f599a2be6df2e214bedd503c37ceb061d8ec60209fe345ce89830a19230301f076caff004d1926".to_string(),
                                vk_beta_2: "0967032fcbf776d1afc985f88877f182d38480a653f2decaa9794cbc3bf3060c0e187847ad4c798374d0d6732bf501847dd68bc0e071241e0213bc7fc13db7ab304cfbd1e08a704a99f5e847d93f8c3caafddec46b7a0d379da69a4d112346a71739c1b1a457a8c7313123d24d2f9192f896b7c63eea05a9d57f06547ad0cec8".to_string(),
                                vk_gamma_2: "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa".to_string(),
                                vk_delta_2: "2178a9c3805dd82071b2b28bb4c0ffc8178cad913c8c990b98b4863284dc3a5d175c0be554fc060c27c551e5e32effef015b918a0f5a2dc1b92909b8272719301c521d5f6542db5ea4775a42d32159c356a696599c1a3df011ec00559ae1c2b60d860f7e6513a7d20feaeaca401863e35a0f691dd7d30ce06d07946840de1ec8".to_string(),
                                vk_ic0: "19126a54a9b6d0d415f892c246485cb2889487cf9c4a8cd88dab5e1140e1d0630d1d76ef4652df8887c9dc557aa57f25e221db7e5b2e4cf618a362bece107f5c".to_string(),
                                vk_ic1: "0632e625fefc7172e8aec1070c4d32b90b6c482f6f3806773a4c55a03877c2d716cfd935eb3e3883f580c93f56adbf3a253ce3c208c52fb784f9d8fec139c617".to_string(),
                            }),
                            groth16_tally_vkey: Some(Groth16VKeyType {
                                vk_alpha1: "2d4d9aa7e302d9df41749d5507949d05dbea33fbb16c643b22f599a2be6df2e214bedd503c37ceb061d8ec60209fe345ce89830a19230301f076caff004d1926".to_string(),
                                vk_beta_2: "0967032fcbf776d1afc985f88877f182d38480a653f2decaa9794cbc3bf3060c0e187847ad4c798374d0d6732bf501847dd68bc0e071241e0213bc7fc13db7ab304cfbd1e08a704a99f5e847d93f8c3caafddec46b7a0d379da69a4d112346a71739c1b1a457a8c7313123d24d2f9192f896b7c63eea05a9d57f06547ad0cec8".to_string(),
                                vk_gamma_2: "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa".to_string(),
                                vk_delta_2: "2e9fad39728c543c5213599111e1a44b01720c999a6785e8136c3e3b3bf8e07e248e1933d477969ca6e27cb7a74bca18cac7e3bbdf9371be5c54fe151f6376a30955609ec69b89329322a2f435b706ca248d1312c7513853a50ef37ed0f7826c25a5c57bf07789d89e538bc24017cf2722811f21480b0bb8030ed0028ecb7cd8".to_string(),
                                vk_ic0: "1bc1a1a3444256469c07cd6f4d1cfd9f7c9ddce596a306e0af077ca9e9c0fe9602db2a9aecef76a9dc4c19bf88c0099b04fc75410cc9004f0966440825e3790a".to_string(),
                                vk_ic1: "05b8b475f2bfedba4fa04ab1972006da9764c2c3e6fb65d6dd0aac938fd298112a560e13770b06a3f709a49fddf016331ea205fa125026993f6666eff69f4def".to_string()
                            }),
                            plonk_process_vkey: None,
                            plonk_tally_vkey: None,
                            certification_system: Uint256::from_u128(0u128),
                            max_vote_options: Uint256::from_u128(5u128),
                            round_info,
                            voting_time,
                            circuit_type,
                            whitelist_backend_pubkey: whitelist_pubkey(),
                            whitelist_ecosystem: whitelist_ecosystem(),
                            whitelist_snapshot_height: whitelist_snapshot_height(),
                            whitelist_slope: whitelist_slope(),
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
                                parameters,
                                coordinator: PubKey {
                                    x: uint256_from_decimal_string("3557592161792765812904087712812111121909518311142005886657252371904276697771"),
                                    y: uint256_from_decimal_string("4363822302427519764561660537570341277214758164895027920046745209970137856681")
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
                                groth16_process_vkey: None,
                                groth16_tally_vkey: None,
                                plonk_process_vkey: Some(PlonkVKeyType {
                                    n: 1048575,
                                    num_inputs: 1,
                                    selector_commitments: [
                                        "29b0f4a90bea69583a8fca1e74d23adf739d605af605a0e0971fac548df976fb2e10a42dfca2325684c1bca5fabbf9d7022fc8b997ea478f1052dd8808d99e44".to_string(),
                                          "119002055b6c2f98314ef408e4a917a6678f114ca991185749289f171f61efc32b3a931c700271b82d22c2073af9b7fffcb7bfa644ea09102d9ef8482410a991".to_string(),
                                          "10c5f32870d26f8e26d2eaae2705557b18210b2355677172e1bef5fe684120891f8317185390ddbb22ecb922d37e03c3cc524c84f65c8045f2324b0f164cfbdb".to_string(),
                                          "115a5f9af5d438d3261cfa31b7050b931b7d22647f628a43af41a41dcd44cb8d2e99368eb15cdc6d1f16faf9db0db4825613d6893c776aef456705bdc76eb728".to_string(),
                                          "1a61cc5f0fbe92fbc8c9bd58928ce467f63e4771e4d517966afbaf220ea069a91cec3231c370be07fee8d9ec01660d054c549b034715855ffa652ad5b67ced86".to_string(),
                                          "19e0d095a343115f6e7ad7ae1f51e375cd648fb35451cb2d5a8cf3bafbb25d0525efdc2cc5b5600ee0ae954dca3bf67c8277d470161fe23b4be7a5bcdf641e68".to_string()
                                          ].to_vec(),
                                    next_step_selector_commitments: [
                                        "246ce82e01ed312e81492f132da2ee16bc13cc0024fbcc668de30173ad59067f0f072a892451cc495f5d9b8b99c8dc29be1d42d3004aed45fd5b2cd32a420016".to_string()
                                      ].to_vec(),
                                    permutation_commitments: [
                                        "19c4143f41738480adc5ae49922d31b8a5afaa1d25ced5c20b869c0e1ccad91920c267c53d33907318cd194ba2ea08a85f250779765ba4121f7a0edfe1afe22b".to_string(),
                                            "114bda14aa702a0815e3f91318a08a2798244420fd6675c8fc3cc2b0232298890d2eb3c1f27a83f4a3be777524d6cc65aa435e0a472fae8d1158e0a6ded685d0".to_string(),
                                            "289f0b046968d2c095d05350e43996756fc85d2deb0e267a069615f0889a249413bdbe6f09edb4db956b8f3fc4488c4681cd52469dc0d419dab99a65b88309f7".to_string(),
                                            "16dd74a2089960aac0d68309d5e81c6b45c29fafe4d42c922c06eb633ed48d551d347d1f43ee9b137772eefc43a6dcdf5ac35ee1615bc8f7c243bce071c410a9".to_string()
                                            ].to_vec(),
                                    non_residues: [    "0000000000000000000000000000000000000000000000000000000000000005".to_string(),
                                    "0000000000000000000000000000000000000000000000000000000000000007".to_string(),
                                    "000000000000000000000000000000000000000000000000000000000000000a".to_string()
                                      ].to_vec(),
                                    g2_elements: [
                                        "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa".to_string(),
                                        "260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c10118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b004fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe422febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55".to_string()
                                      ].to_vec()
                                }),
                                plonk_tally_vkey: Some(PlonkVKeyType {
                                    n: 524287,
                                    num_inputs: 1,
                                    selector_commitments: [
                                      "18c2bb75c8ed53a5d15a56cc91c56f14c832419994ce7187c7c98b5e622cac0808b773f05e09822d8d267646198a78359ea2aa6fbaeb01317142f99fd11da6c0".to_string(),
                                      "181499098243a5968f5490b7759aa15f0f769f24f3f4219b69f96913cf4fb23c1cd7b3f109196d7577390fd2e6d3930a71b0559aff756f3ca43eef66ce7333f4".to_string(),
                                      "07ba2bdd452503fb16b56ea2940e95a98118c9dd120ae192680fe2b80bdb26f10ac6cdc7cb12b581a8c64d45b5af3d253c4282405eed3fd4d091ae05aac45cb6".to_string(),
                                      "1caf01f1775eeafa78a11202e926ee92be997ce040f9c6fbce161348a40aeda70d9f15738cccf538083784e566ceef651d000223ae810c980e2d5d98b91b4665".to_string(),
                                      "2c377c69cae1d591af413da2fd986ef3dca595d0c5817ee4932b92169d37c52d1218ce63dde705ebd1dc66d9b62daca287e4fdf6800b69204e5b78bfe84365a1".to_string(),
                                      "175dd4ff280e39f0e080c181f853845e40c4b91709a93e4398d24befc9cf556903675361817e031e86bd896ff1dd7bc1cc31ca920a101499db0c58d77f0730ec".to_string()
                                      ].to_vec(),
                                    next_step_selector_commitments: [
                                      "12d76999d26137d433f7119ab34f3fc63cfedb9172052cfb34acfc3cdc570f511aba802ebe92b87f913496314b938cf526078280a68826c90b686b90420c7742".to_string()
                                      ].to_vec(),
                                    permutation_commitments: [
                                      "167b05c0132399e7126e8d16efb224b1c6729942048fc7e730fd1451116e0a6e05acaf2a6d2c88cc25610474b651c8cdcb7e8e14e59ddfad819123e888c4b1b6".to_string(),
                                      "25aed62de4b701dc645e076543e2553c306010f2776c74edae55ea5253d9540403d042c4cb699cc04b2bb63d3c3edc0c85b049a84dc2fd44369f957d81363563".to_string(),
                                      "0e77fb0b0e84da1d955da3d66dbb8fa3988f22e999a34bc4ac537a0f9187ac40156f8d7cb6d005fd85a0178d794f941b4e84832fd389a37c2a78112dac09b758".to_string(),
                                      "051d3d906d457eaa9eff77a296dfa1760fd9ea379eec60487be38de91545ca2c1fcf457d6ac31afee10951245b0cc1e2c7674596f65955d189d48b6938fb3594".to_string()
                                      ].to_vec(),
                                    non_residues: [
                                      "0000000000000000000000000000000000000000000000000000000000000005".to_string(),
                                      "0000000000000000000000000000000000000000000000000000000000000007".to_string(),
                                      "000000000000000000000000000000000000000000000000000000000000000a".to_string()
                                      ].to_vec(),
                                    g2_elements: [
                                      "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa".to_string(),
                                      "260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c10118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b004fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe422febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55".to_string()
                                      ].to_vec()
                                }),
                                certification_system: Uint256::from_u128(1u128), // plonk system
                                max_vote_options: Uint256::from_u128(5u128),
                                round_info,
                                voting_time,
                                circuit_type,
                                whitelist_backend_pubkey: whitelist_pubkey(),
                                whitelist_ecosystem: whitelist_ecosystem(),
                                whitelist_snapshot_height: whitelist_snapshot_height(),
                                whitelist_slope: whitelist_slope(),
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
