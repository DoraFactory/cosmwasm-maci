#[cfg(test)]
mod test_module {
    use crate::error::ContractError;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{from_binary, Coin, Deps, DepsMut, MessageInfo, Response, Uint256};
    use num_bigint::BigUint;
    use serde::{Deserialize, Serialize};
    use serde_json;
    use std::fs;
    use std::io::Read;

    use crate::contract::{execute, instantiate, query};
    use crate::msg::{ExecuteMsg, InstantiateMsg, ProofType, QueryMsg};

    use crate::msg::VKeyType;
    use crate::state::{
        MaciParameters, Message, Period, PeriodStatus, PubKey, QuinaryTreeRoot, Whitelist,
        WhitelistConfig,
    };
    use crate::utils::uint256_from_hex_string;

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

    fn assert_period_state(deps: Deps, expected: Period) {
        let res = query(deps, mock_env(), QueryMsg::GetPeriod {}).unwrap();
        let value: Period = from_binary(&res).unwrap();
        assert_eq!(value, expected);
    }

    fn mock_init(deps: DepsMut, parameters: MaciParameters) {
        let user_1 = mock_info(&0usize.to_string(), &[]);
        let user_2 = mock_info(&1usize.to_string(), &[]);

        let msg = InstantiateMsg {
            round_description: String::from("HackWasm Berlin"),
            parameters,
            coordinator: PubKey {
                x: uint256_from_decimal_string("3557592161792765812904087712812111121909518311142005886657252371904276697771"),
                y: uint256_from_decimal_string("4363822302427519764561660537570341277214758164895027920046745209970137856681")
            },
            process_vkey: VKeyType {
                vk_alpha1: "2d4d9aa7e302d9df41749d5507949d05dbea33fbb16c643b22f599a2be6df2e214bedd503c37ceb061d8ec60209fe345ce89830a19230301f076caff004d1926".to_string(),
                vk_beta_2: "0967032fcbf776d1afc985f88877f182d38480a653f2decaa9794cbc3bf3060c0e187847ad4c798374d0d6732bf501847dd68bc0e071241e0213bc7fc13db7ab304cfbd1e08a704a99f5e847d93f8c3caafddec46b7a0d379da69a4d112346a71739c1b1a457a8c7313123d24d2f9192f896b7c63eea05a9d57f06547ad0cec8".to_string(),
                vk_gamma_2: "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa".to_string(),
                vk_delta_2: "22271cda8c78ebfb3b15c4c6cde9e05231f0a0d90ab80e641ffe7b16233205472864fb9deedbbe0855d09deee7f3b51729c8e6b7bdd72e8b98def08e5c9029b119eef68c7b12c16a9f39f911aa6905c6bdae9e7412c68f6b0bef1e96377f3a732978c67e4e4ba33564d910e2a15325a9974acf1d3c8a187069426e4f0963485f".to_string(),
                vk_ic0: "054c5d7a72add567d812099efec32628d4fde2bc1efd867e2e38b3d369aca16a2837e4ed0ae0a93ae6ff09866b87bb80d014dfff263b0833fefd182ef034e663".to_string(),
                vk_ic1: "0493f44e067e7c3100565e6a4119f5f10a4dce5f714bc88aabce04b4770c48ba07b9ec8a559bcb7176d7bfe8bbe8ae2731c7c7683911dca2fc9709884db50b83".to_string(),
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
                vk_delta_2: "2be07265a2a43e683a7ac880a23ea9f34588c440e9df12e712b9e830c5263b8f1cebe7adb70a095f552063c31a9d9a5051c9d4998b9e3b336ffa79ea00da373822817d0b7fc2294c9d3e3974fd5a7a8a01435c4dff095d588c2a3f73737d19b51349dbdca1b6fcd3b7d929a97e06fe55041a062c550d8f7ed3d912f8ed47d2ef".to_string(),
                vk_ic0: "1bc1a1a3444256469c07cd6f4d1cfd9f7c9ddce596a306e0af077ca9e9c0fe9602db2a9aecef76a9dc4c19bf88c0099b04fc75410cc9004f0966440825e3790a".to_string(),
                vk_ic1: "05b8b475f2bfedba4fa04ab1972006da9764c2c3e6fb65d6dd0aac938fd298112a560e13770b06a3f709a49fddf016331ea205fa125026993f6666eff69f4def".to_string(),
            },
            whitelist: Whitelist {
                users: vec![
                    WhitelistConfig {
                        addr: user_1.sender.to_string(),
                        balance: Uint256::from_u128(100u128),
                    },
                    WhitelistConfig {
                        addr: user_2.sender.to_string(),
                        balance: Uint256::from_u128(80u128),
                    },
                ]
            }
        };

        let info = mock_info("creator", &[]);
        let _res = instantiate(deps, mock_env(), info, msg)
            .expect("contract successfully handles InstantiateMsg");
    }

    #[test]
    fn proper_init() {
        let mut deps = mock_dependencies();

        let parameters = MaciParameters {
            state_tree_depth: Uint256::from_u128(2u128),
            int_state_tree_depth: Uint256::from_u128(1u128),
            message_batch_size: Uint256::from_u128(5u128),
            vote_option_tree_depth: Uint256::from_u128(1u128),
        };

        mock_init(deps.as_mut(), parameters);
        assert_period_state(
            deps.as_ref(),
            Period {
                status: PeriodStatus::Voting,
            },
        );
    }

    fn batch_mock_sign_up(deps: DepsMut, pubkey: PubKey, info: MessageInfo) {
        let msg = ExecuteMsg::SignUp { pubkey };
        let _res =
            execute(deps, mock_env(), info, msg).expect("contract handles set zkeys parameters");
    }

    fn batch_publish_message(deps: DepsMut, message: Message, enc_pub_key: PubKey, sent: &[Coin]) {
        let info = mock_info("alice_key", sent);

        let msg = ExecuteMsg::PublishMessage {
            message,
            enc_pub_key,
        };
        let _res =
            execute(deps, mock_env(), info, msg).expect("contract handles set zkeys parameters");
    }

    fn mock_stop_voting(deps: DepsMut, sent: &[Coin]) {
        let info = mock_info("creator", sent); // only admin can stop voting

        let msg = ExecuteMsg::StopVotingPeriod {
            max_vote_options: Uint256::from_u128(5u128),
        };
        let _res =
            execute(deps, mock_env(), info, msg).expect("contract handles set zkeys parameters");
    }

    fn mock_process_message(
        deps: DepsMut,
        new_state_commitment: Uint256,
        proof: ProofType,
        sent: &[Coin],
    ) -> Result<Response, ContractError> {
        let info = mock_info("creator", sent); // only admin can stop voting

        let msg = ExecuteMsg::ProcessMessage {
            new_state_commitment,
            proof,
        };

        // let _res = execute(deps, mock_env(), info, msg);
        return execute(deps, mock_env(), info, msg);
    }

    fn mock_stop_processing(deps: DepsMut, sent: &[Coin]) {
        let info = mock_info("creator", sent); // only admin can stop voting

        let msg = ExecuteMsg::StopProcessingPeriod {};

        let _res = execute(deps, mock_env(), info, msg);
    }

    fn mock_process_tally(
        deps: DepsMut,
        new_tally_commitment: Uint256,
        proof: ProofType,
        sent: &[Coin],
    ) -> Result<Response, ContractError> {
        let info = mock_info("creator", sent); // only admin can stop voting

        let msg = ExecuteMsg::ProcessTally {
            new_tally_commitment,
            proof,
        };

        return execute(deps, mock_env(), info, msg);
        // assert_eq!(execute(deps, mock_env(), info, msg), Err(ContractError::HexDecodingError {}));
    }

    fn mock_stop_tallying(deps: DepsMut, results: Vec<Uint256>, salt: Uint256, sent: &[Coin]) {
        let info = mock_info("creator", sent); // only admin can stop voting

        let msg = ExecuteMsg::StopTallyingPeriod { results, salt };

        let _res = execute(deps, mock_env(), info, msg);
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MsgData {
        input_hash: String,
        packed_vals: String,
        batch_start_hash: String,
        batch_end_hash: String,
        msgs: Vec<Vec<String>>,
        coord_priv_key: String,
        coord_pub_key: Vec<String>,
        enc_pub_keys: Vec<Vec<String>>,
        current_state_root: String,
        current_state_leaves: Vec<Vec<String>>,
        current_state_leaves_path_elements: Vec<Vec<Vec<String>>>,
        current_state_commitment: String,
        current_state_salt: String,
        new_state_commitment: String,
        new_state_salt: String,
        current_vote_weights: Vec<String>,
        current_vote_weights_path_elements: Vec<Vec<Vec<String>>>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TallyData {
        state_root: String,
        state_salt: String,
        packed_vals: String,
        state_commitment: String,
        current_tally_commitment: String,
        new_tally_commitment: String,
        input_hash: String,
        state_leaf: Vec<Vec<String>>,
        state_path_elements: Vec<Vec<String>>,
        votes: Vec<Vec<String>>,
        current_results: Vec<String>,
        current_results_root_salt: String,
        new_results_root_salt: String,
    }

    #[test]
    fn test_all_round() {
        let mut deps = mock_dependencies();

        let parameters = MaciParameters {
            state_tree_depth: Uint256::from_u128(2u128),
            int_state_tree_depth: Uint256::from_u128(1u128),
            message_batch_size: Uint256::from_u128(5u128),
            vote_option_tree_depth: Uint256::from_u128(1u128),
        };

        mock_init(deps.as_mut(), parameters.clone());

        let msg_file_path = "./src/test/msg_test.json";

        let mut msg_file = fs::File::open(msg_file_path).expect("Failed to open file");
        let mut msg_content = String::new();

        msg_file
            .read_to_string(&mut msg_content)
            .expect("Failed to read file");

        let data: MsgData = serde_json::from_str(&msg_content).expect("Failed to parse JSON");

        for i in 0..data.msgs.len() {
            if i < parameters.state_tree_depth.to_string().parse().unwrap() {
                let user = mock_info(&i.to_string(), &[]);

                let pubkey = PubKey {
                    x: uint256_from_decimal_string(&data.current_state_leaves[i][0]),
                    y: uint256_from_decimal_string(&data.current_state_leaves[i][1]),
                };

                let balance = uint256_from_decimal_string(&data.current_state_leaves[i][2]);
                println!("---------- signup ---------- {:?}", i);
                println!("user {:?}", user.sender.to_string());
                println!("pubkey {:?}", pubkey);
                println!("blance {:?}\n", balance);
                batch_mock_sign_up(
                    deps.as_mut(),
                    pubkey,
                    user, // &[coin(balance.to_string().parse().unwrap(), "token")],
                );
            }
            let message = Message {
                data: [
                    uint256_from_decimal_string(&data.msgs[i][0]),
                    uint256_from_decimal_string(&data.msgs[i][1]),
                    uint256_from_decimal_string(&data.msgs[i][2]),
                    uint256_from_decimal_string(&data.msgs[i][3]),
                    uint256_from_decimal_string(&data.msgs[i][4]),
                    uint256_from_decimal_string(&data.msgs[i][5]),
                    uint256_from_decimal_string(&data.msgs[i][6]),
                ],
            };

            let enc_pub = PubKey {
                x: uint256_from_decimal_string(&data.enc_pub_keys[i][0]),
                y: uint256_from_decimal_string(&data.enc_pub_keys[i][1]),
            };

            println!("------------- publish message -------------");
            println!("message {:?}", message);
            println!("enc_pub {:?}\n", enc_pub);
            batch_publish_message(deps.as_mut(), message, enc_pub, &[]);
        }
        mock_stop_voting(deps.as_mut(), &[]);
        let new_state_commitment = uint256_from_decimal_string(&data.new_state_commitment);
        let proof = ProofType {
            a: "2e2f3ec86864aaf9ff5936b7aa7c50797eb7b70d4d73fb2d97fdc8e9c0e03583149b169f45d10395042c3f7b44d3fbc4e997b0ac0549b474e19eadeca9a4f141".to_string(),
            b: "213a21f9042d926a01116583e90a956264e368fabdc26e49638d7faaa09ee9f20ff0eb1a87dd3fc412cedb749823d2f97c0247ae4df89003e0dacd5bc195c990107b7a645d618143c91d78b6a456c71c690f469ea5b0b808e89a3228f92147b2108008e3de0fa8b1ff576cfc92047be60bd7a43e76d1e651bba1b494d58c6170".to_string(),
            c: "2385dc34f583a5d34bea5f9083e4788326b7b07054dc85a414fd07fba31c1e76068f86ff1d85f70c55bb4737d1f77744ee73c41d6d4cbc727b624e09ef5fffa0".to_string()
        };
        println!("process_message proof {:?}", proof);
        println!(
            "process_message new state commitment {:?}",
            new_state_commitment
        );

        assert_ne!(
            mock_process_message(deps.as_mut(), new_state_commitment, proof, &[]),
            Err(ContractError::InvalidProof {
                step: String::from("Process")
            })
        );

        let tally_path = "./src/test/tally_test.json";
        let mut tally_file = fs::File::open(tally_path).expect("Failed to open file");
        let mut tally_content = String::new();
        tally_file
            .read_to_string(&mut tally_content)
            .expect("Failed to read file");

        let tally_data: TallyData =
            serde_json::from_str(&tally_content).expect("Failed to parse JSON");

        let new_tally_commitment = uint256_from_decimal_string(&tally_data.new_tally_commitment);

        let tally_proof = ProofType {
            a: "0bae3bc2485c2cd6a3bfdf16e7d8a5b93710c3bdcf9410d725aae938ccbebca12b1021be36b6c1d96db410d52369a0e51249da0a1b41497af53bb227ae1e674e".to_string(),
            b: "1ff4ed89d5aefdca176419a76a82d2359f334d9bc479daa6ca11201076745749220fc921f3e77889779969467456beec42cdb5c874e3961a7a0f29b75899417929d1f4d3bb2ca8cfa15b1a1c893f0daa9304131f7512841174b2d2deeb30462e2f8eed8ab95da0c502c740216f89553f1b37ee2d34110c04363a34093337044b".to_string(),
            c: "0c054469563868b8878f72628cb3db437137e3d39fa8b74e344e573fedef8fcb1794cd30a661746438034f71e49349ac16357ebd8c1afc8be7585f4aa5366534".to_string()
        };

        mock_stop_processing(deps.as_mut(), &[]);

        assert_ne!(
            mock_process_tally(deps.as_mut(), new_tally_commitment, tally_proof, &[]),
            Err(ContractError::InvalidProof {
                step: String::from("Tally")
            })
        );

        let results: Vec<Uint256> = tally_data
            .current_results
            .iter()
            .map(|input| uint256_from_decimal_string(input))
            .collect();

        let salt = uint256_from_decimal_string(&tally_data.new_results_root_salt);
        mock_stop_tallying(deps.as_mut(), results, salt, &[]);
    }
}
