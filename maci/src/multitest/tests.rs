#[cfg(test)]
mod test {
    use crate::error::ContractError;
    use crate::msg::{Groth16ProofType};
    use crate::multitest::{
        create_app, owner, uint256_from_decimal_string, user1, user2, MaciCodeId,
    };
    use crate::state::{MessageData, Period, PeriodStatus, PubKey, RoundInfo};
    use cosmwasm_std::{coins, Addr, Uint128, Uint256};
    use cw_multi_test::{next_block, AppBuilder, StargateAccepting};
    use serde::{Deserialize, Serialize};
    use serde_json;
    use std::fs;
    use std::io::Read;

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

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ResultData {
        results: Vec<String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct UserPubkeyData {
        pubkeys: Vec<Vec<String>>,
    }

    #[test]
    fn instantiate_with_no_voting_time_should_works() {
        let msg_file_path = "./src/test/msg_test.json";

        let mut msg_file = fs::File::open(msg_file_path).expect("Failed to open file");
        let mut msg_content = String::new();

        msg_file
            .read_to_string(&mut msg_content)
            .expect("Failed to read file");

        let data: MsgData = serde_json::from_str(&msg_content).expect("Failed to parse JSON");

        let mut app = create_app();

        let code_id = MaciCodeId::store_code(&mut app);
        let label = "Dora Maci";
        let contract = code_id
            .instantiate_with_no_voting_time(&mut app, owner(), label)
            .unwrap();

        // check winner
        let num_sign_up = contract.num_sign_up(&app).unwrap();
        assert_eq!(num_sign_up, Uint256::from_u128(0u128));
        app.update_block(next_block);

        _ = contract.set_vote_option_map(&mut app, owner());
        app.update_block(next_block);
        _ = contract.set_whitelist(&mut app, owner());

        let test_pubkey = PubKey {
            x: uint256_from_decimal_string(&data.current_state_leaves[0][0]),
            y: uint256_from_decimal_string(&data.current_state_leaves[0][1]),
        };
        let sign_up_error = contract
            .sign_up(
                &mut app,
                Addr::unchecked(0.to_string()),
                test_pubkey.clone(),
            )
            .unwrap_err();
        assert_eq!(
            ContractError::PeriodError {},
            sign_up_error.downcast().unwrap()
        ); // 不能在voting环节之前进行signup

        _ = contract.start_voting(&mut app, owner());
        app.update_block(next_block);

        let set_whitelist_only_in_pending = contract.set_whitelist(&mut app, owner()).unwrap_err();
        assert_eq!(
            // 注册之后不能再进行注册
            ContractError::PeriodError {},
            set_whitelist_only_in_pending.downcast().unwrap()
        );
        let msg_file_path = "./src/test/msg_test.json";

        let mut msg_file = fs::File::open(msg_file_path).expect("Failed to open file");
        let mut msg_content = String::new();

        msg_file
            .read_to_string(&mut msg_content)
            .expect("Failed to read file");

        let data: MsgData = serde_json::from_str(&msg_content).expect("Failed to parse JSON");

        let result_file_path = "./src/test/result.json";
        let mut result_file = fs::File::open(result_file_path).expect("Failed to open file");
        let mut result_content = String::new();
        result_file
            .read_to_string(&mut result_content)
            .expect("Failed to read file");

        let result_data: ResultData =
            serde_json::from_str(&result_content).expect("Failed to parse JSON");

        let pubkey_file_path = "./src/test/user_pubkey.json";

        let mut pubkey_file = fs::File::open(pubkey_file_path).expect("Failed to open file");
        let mut pubkey_content = String::new();

        pubkey_file
            .read_to_string(&mut pubkey_content)
            .expect("Failed to read file");
        let pubkey_data: UserPubkeyData =
            serde_json::from_str(&pubkey_content).expect("Failed to parse JSON");

        for i in 0..data.msgs.len() {
            if i < Uint256::from_u128(2u128).to_string().parse().unwrap() {
                let pubkey = PubKey {
                    x: uint256_from_decimal_string(&pubkey_data.pubkeys[i][0]),
                    y: uint256_from_decimal_string(&pubkey_data.pubkeys[i][1]),
                };

                println!("---------- signup ---------- {:?}", i);
                let _ = contract.sign_up(&mut app, Addr::unchecked(i.to_string()), pubkey);
                app.update_block(next_block);
            }
            let message = MessageData {
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
            _ = contract.publish_message(&mut app, user2(), message, enc_pub);
            app.update_block(next_block);
        }
        assert_eq!(
            contract.num_sign_up(&app).unwrap(),
            Uint256::from_u128(2u128)
        );

        assert_eq!(
            contract.msg_length(&app).unwrap(),
            Uint256::from_u128(3u128)
        );

        // let sign_up_after_voting_end_error = contract
        //     .sign_up(
        //         &mut app,
        //         Addr::unchecked(0.to_string()),
        //         test_pubkey.clone(),
        //     )
        //     .unwrap_err();
        // assert_eq!(
        //     // 注册之后不能再进行注册
        //     ContractError::Unauthorized {},
        //     sign_up_after_voting_end_error.downcast().unwrap()
        // );

        // Stop Voting Period
        _ = contract.stop_voting(&mut app, owner());

        let sign_up_after_voting_end_error = contract
            .sign_up(
                &mut app,
                Addr::unchecked(3.to_string()),
                test_pubkey.clone(),
            )
            .unwrap_err();
        assert_eq!(
            // 不能投票环节结束之后不能进行sign up
            ContractError::PeriodError {},
            sign_up_after_voting_end_error.downcast().unwrap()
        );

        let stop_voting_after_voting_end_error =
            contract.stop_voting(&mut app, owner()).unwrap_err();
        assert_eq!(
            ContractError::AlreadySetVotingTime {
                time_name: String::from("end_time")
            },
            stop_voting_after_voting_end_error.downcast().unwrap()
        );
        app.update_block(next_block);

        _ = contract.start_process(&mut app, owner());
        println!(
            "after start process: {:?}",
            contract.get_period(&app).unwrap()
        );
        assert_eq!(
            Period {
                status: PeriodStatus::Processing
            },
            contract.get_period(&app).unwrap()
        );

        app.update_block(next_block);

        let new_state_commitment = uint256_from_decimal_string(&data.new_state_commitment);
        let proof = Groth16ProofType {
                a: "27fb48285bc59bc74c9197857856cf5f3dcce55f22b83589e399240b8469e45725c5495e3ebcdd3bc04620fd13fed113c31d19a685f7f037daf02dde02d26e4f".to_string(),
                b: "0d1bd72809defb6e85ea48de4c28e9ec9dcd2bc5111acdb66b5cdb38ccf6d4e32bdeac48a806c2fd6cef8e09bfde1983961693c8d4a513777ba26b07f2abacba1efb7600f04e786d93f321c6df732eb0043548cfe12fa8a5aea848a500ef5b9728dbc747fc76993c16dadf2c8ef68f3d757afa6d4caf9a767c424ec0d7ff4932".to_string(),
                c: "2062c6bee5dad15af1ebcb0e623b27f7d29775774cc92b2a7554d1801af818940309fa215204181d3a1fef15d162aa779b8900e2b84d8b8fa22a20b65652eb46".to_string()
            };
        println!("process_message proof {:?}", proof);
        println!(
            "process_message new state commitment {:?}",
            new_state_commitment
        );
        _ = contract
            .process_message(&mut app, owner(), new_state_commitment, proof)
            .unwrap();

        _ = contract.stop_processing(&mut app, owner());

        let tally_path = "./src/test/tally_test.json";
        let mut tally_file = fs::File::open(tally_path).expect("Failed to open file");
        let mut tally_content = String::new();
        tally_file
            .read_to_string(&mut tally_content)
            .expect("Failed to read file");

        let tally_data: TallyData =
            serde_json::from_str(&tally_content).expect("Failed to parse JSON");

        let new_tally_commitment = uint256_from_decimal_string(&tally_data.new_tally_commitment);

        let tally_proof = Groth16ProofType {
            a: "2554bb7be658b5261bbcacef022d86dc55360f936a1473aa5c70c5b20083d7370deb7df6a8d0e74ae7f8b310725f3063407679fd99d23a7ad77b7d1bff5572d5".to_string(),
            b: "0fa4de46a0fc9d269314bbac4fb8f3425780bcde9b613a5252400216dadc3b5809f1d59c5f84892444c89712ab087cd708dcec5b77c108d9db73a8821be6720302f4820fec3af0e29b8a8aaf83db039d46703795d6275f934a14e8edc040e18f2dab2b05decd1b5bdb18631b9a8106714ceb5cf9fa6f4a4325cf4289a4025fc7".to_string(),
            c: "0d6a9f2eb8cfb28368bf6976f2925a3fb8ac0ead8dc95fc9a79318d0518f24801dced0525cbb2f15f24198bfe3f77c1065120be9dcbc3d10c77ca5861c410910".to_string()
        };

        _ = contract
            .process_tally(&mut app, owner(), new_tally_commitment, tally_proof)
            .unwrap();
        println!("------ tally");
        let results: Vec<Uint256> = result_data
            .results
            .iter()
            .map(|input| uint256_from_decimal_string(input))
            .collect();

        let salt = uint256_from_decimal_string(&tally_data.new_results_root_salt);
        _ = contract.stop_tallying(&mut app, owner(), results, salt);

        let all_result = contract.get_all_result(&app);
        println!("all_result: {:?}", all_result);

        _ = contract.set_round_info(&mut app, owner());

        let new_round_info = contract.get_round_info(&app).unwrap();
        assert_eq!(
            new_round_info,
            RoundInfo {
                title: String::from("TestRound2"),
                description: String::from(""),
                link: String::from("https://github.com"),
            }
        );

        let error_set_empty_round_info = contract
            .set_empty_round_info(&mut app, owner())
            .unwrap_err();
        assert_eq!(
            ContractError::TitleIsEmpty {},
            error_set_empty_round_info.downcast().unwrap()
        );

        let error_no_admin_set_round_info = contract.set_round_info(&mut app, user1()).unwrap_err();
        assert_eq!(
            ContractError::Unauthorized {},
            error_no_admin_set_round_info.downcast().unwrap()
        );
    }

    #[test]
    fn instantiate_with_voting_time_should_works() {
        let msg_file_path = "./src/test/msg_test.json";

        let mut msg_file = fs::File::open(msg_file_path).expect("Failed to open file");
        let mut msg_content = String::new();

        msg_file
            .read_to_string(&mut msg_content)
            .expect("Failed to read file");

        let data: MsgData = serde_json::from_str(&msg_content).expect("Failed to parse JSON");

        let result_file_path = "./src/test/result.json";
        let mut result_file = fs::File::open(result_file_path).expect("Failed to open file");
        let mut result_content = String::new();
        result_file
            .read_to_string(&mut result_content)
            .expect("Failed to read file");

        let result_data: ResultData =
            serde_json::from_str(&result_content).expect("Failed to parse JSON");

        let pubkey_file_path = "./src/test/user_pubkey.json";

        let mut pubkey_file = fs::File::open(pubkey_file_path).expect("Failed to open file");
        let mut pubkey_content = String::new();

        pubkey_file
            .read_to_string(&mut pubkey_content)
            .expect("Failed to read file");
        let pubkey_data: UserPubkeyData =
            serde_json::from_str(&pubkey_content).expect("Failed to parse JSON");

        let mut app = create_app();
        let code_id = MaciCodeId::store_code(&mut app);
        let label = "Group";
        let contract = code_id
            .instantiate_with_voting_time(&mut app, owner(), user1(), user2(), label)
            .unwrap();

        let start_voting_error = contract.start_voting(&mut app, owner()).unwrap_err();

        assert_eq!(
            ContractError::AlreadySetVotingTime {
                time_name: String::from("start_time")
            },
            start_voting_error.downcast().unwrap()
        );

        let num_sign_up = contract.num_sign_up(&app).unwrap();
        assert_eq!(num_sign_up, Uint256::from_u128(0u128));

        let vote_option_map = contract.vote_option_map(&app).unwrap();
        let max_vote_options = contract.max_vote_options(&app).unwrap();
        assert_eq!(vote_option_map, vec!["", "", "", "", ""]);
        assert_eq!(max_vote_options, Uint256::from_u128(5u128));
        _ = contract.set_vote_option_map(&mut app, owner());
        let new_vote_option_map = contract.vote_option_map(&app).unwrap();
        assert_eq!(
            new_vote_option_map,
            vec![
                String::from("did_not_vote"),
                String::from("yes"),
                String::from("no"),
                String::from("no_with_veto"),
                String::from("abstain"),
            ]
        );
        // assert_eq!(num_sign_up, Uint256::from_u128(0u128));

        let test_pubkey = PubKey {
            x: uint256_from_decimal_string(&data.current_state_leaves[0][0]),
            y: uint256_from_decimal_string(&data.current_state_leaves[0][1]),
        };
        let sign_up_error = contract
            .sign_up(
                &mut app,
                Addr::unchecked(0.to_string()),
                test_pubkey.clone(),
            )
            .unwrap_err();
        assert_eq!(
            ContractError::PeriodError {},
            sign_up_error.downcast().unwrap()
        ); // 不能在voting环节之前进行signup

        _ = contract.set_vote_option_map(&mut app, owner());

        app.update_block(next_block); // Start Voting
        let set_whitelist_only_in_pending = contract.set_whitelist(&mut app, owner()).unwrap_err();
        assert_eq!(
            // 注册之后不能再进行注册
            ContractError::PeriodError {},
            set_whitelist_only_in_pending.downcast().unwrap()
        );
        let set_vote_option_map_error =
            contract.set_vote_option_map(&mut app, owner()).unwrap_err();
        assert_eq!(
            ContractError::PeriodError {},
            set_vote_option_map_error.downcast().unwrap()
        );

        let error_start_process_in_voting = contract.start_process(&mut app, owner()).unwrap_err();
        assert_eq!(
            ContractError::PeriodError {},
            error_start_process_in_voting.downcast().unwrap()
        );
        assert_eq!(
            Period {
                status: PeriodStatus::Pending
            },
            contract.get_period(&app).unwrap()
        );

        for i in 0..data.msgs.len() {
            if i < Uint256::from_u128(2u128).to_string().parse().unwrap() {
                let pubkey = PubKey {
                    x: uint256_from_decimal_string(&pubkey_data.pubkeys[i][0]),
                    y: uint256_from_decimal_string(&pubkey_data.pubkeys[i][1]),
                };

                println!("---------- signup ---------- {:?}", i);
                let _ = contract.sign_up(&mut app, Addr::unchecked(i.to_string()), pubkey);
            }
            let message = MessageData {
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
            _ = contract.publish_message(&mut app, user2(), message, enc_pub);
        }

        // let sign_up_after_voting_end_error = contract
        //     .sign_up(
        //         &mut app,
        //         Addr::unchecked(0.to_string()),
        //         test_pubkey.clone(),
        //     )
        //     .unwrap_err();
        // assert_eq!(
        //     // 注册之后不能再进行注册
        //     ContractError::Unauthorized {},
        //     sign_up_after_voting_end_error.downcast().unwrap()
        // );

        assert_eq!(
            contract.num_sign_up(&app).unwrap(),
            Uint256::from_u128(2u128)
        );

        assert_eq!(
            contract.msg_length(&app).unwrap(),
            Uint256::from_u128(3u128)
        );

        // Stop Voting Period
        app.update_block(next_block);

        let sign_up_after_voting_end_error = contract
            .sign_up(
                &mut app,
                Addr::unchecked(3.to_string()),
                test_pubkey.clone(),
            )
            .unwrap_err();
        assert_eq!(
            // 不能投票环节结束之后不能进行sign up
            ContractError::PeriodError {},
            sign_up_after_voting_end_error.downcast().unwrap()
        );

        let stop_voting_error = contract.stop_voting(&mut app, owner()).unwrap_err();
        assert_eq!(
            ContractError::AlreadySetVotingTime {
                time_name: String::from("end_time")
            },
            stop_voting_error.downcast().unwrap()
        );
        app.update_block(next_block);

        _ = contract.start_process(&mut app, owner());
        assert_eq!(
            Period {
                status: PeriodStatus::Processing
            },
            contract.get_period(&app).unwrap()
        );

        println!(
            "after start process: {:?}",
            contract.get_period(&app).unwrap()
        );

        let new_state_commitment = uint256_from_decimal_string(&data.new_state_commitment);
        let proof = Groth16ProofType {
            a: "27fb48285bc59bc74c9197857856cf5f3dcce55f22b83589e399240b8469e45725c5495e3ebcdd3bc04620fd13fed113c31d19a685f7f037daf02dde02d26e4f".to_string(),
            b: "0d1bd72809defb6e85ea48de4c28e9ec9dcd2bc5111acdb66b5cdb38ccf6d4e32bdeac48a806c2fd6cef8e09bfde1983961693c8d4a513777ba26b07f2abacba1efb7600f04e786d93f321c6df732eb0043548cfe12fa8a5aea848a500ef5b9728dbc747fc76993c16dadf2c8ef68f3d757afa6d4caf9a767c424ec0d7ff4932".to_string(),
            c: "2062c6bee5dad15af1ebcb0e623b27f7d29775774cc92b2a7554d1801af818940309fa215204181d3a1fef15d162aa779b8900e2b84d8b8fa22a20b65652eb46".to_string()
        };
        println!("process_message proof {:?}", proof);
        println!(
            "process_message new state commitment {:?}",
            new_state_commitment
        );
        _ = contract
            .process_message(&mut app, owner(), new_state_commitment, proof)
            .unwrap();

        _ = contract.stop_processing(&mut app, owner());
        println!(
            "after stop process: {:?}",
            contract.get_period(&app).unwrap()
        );

        let error_start_process_in_talling = contract.start_process(&mut app, owner()).unwrap_err();
        assert_eq!(
            ContractError::PeriodError {},
            error_start_process_in_talling.downcast().unwrap()
        );
        assert_eq!(
            Period {
                status: PeriodStatus::Tallying
            },
            contract.get_period(&app).unwrap()
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

        let tally_proof = Groth16ProofType {
            a: "2554bb7be658b5261bbcacef022d86dc55360f936a1473aa5c70c5b20083d7370deb7df6a8d0e74ae7f8b310725f3063407679fd99d23a7ad77b7d1bff5572d5".to_string(),
            b: "0fa4de46a0fc9d269314bbac4fb8f3425780bcde9b613a5252400216dadc3b5809f1d59c5f84892444c89712ab087cd708dcec5b77c108d9db73a8821be6720302f4820fec3af0e29b8a8aaf83db039d46703795d6275f934a14e8edc040e18f2dab2b05decd1b5bdb18631b9a8106714ceb5cf9fa6f4a4325cf4289a4025fc7".to_string(),
            c: "0d6a9f2eb8cfb28368bf6976f2925a3fb8ac0ead8dc95fc9a79318d0518f24801dced0525cbb2f15f24198bfe3f77c1065120be9dcbc3d10c77ca5861c410910".to_string()
        };

        _ = contract
            .process_tally(&mut app, owner(), new_tally_commitment, tally_proof)
            .unwrap();

        let results: Vec<Uint256> = result_data
            .results
            .iter()
            .map(|input| uint256_from_decimal_string(input))
            .collect();

        let salt = uint256_from_decimal_string(&tally_data.new_results_root_salt);
        _ = contract.stop_tallying(&mut app, owner(), results, salt);

        let all_result = contract.get_all_result(&app);
        println!("all_result: {:?}", all_result);
        let error_start_process = contract.start_process(&mut app, owner()).unwrap_err();
        assert_eq!(
            ContractError::PeriodError {},
            error_start_process.downcast().unwrap()
        );

        assert_eq!(
            Period {
                status: PeriodStatus::Ended
            },
            contract.get_period(&app).unwrap()
        );
    }

    #[test]
    fn instantiate_with_start_time_should_works() {
        let msg_file_path = "./src/test/msg_test.json";

        let mut msg_file = fs::File::open(msg_file_path).expect("Failed to open file");
        let mut msg_content = String::new();

        msg_file
            .read_to_string(&mut msg_content)
            .expect("Failed to read file");

        let data: MsgData = serde_json::from_str(&msg_content).expect("Failed to parse JSON");

        let result_file_path = "./src/test/result.json";
        let mut result_file = fs::File::open(result_file_path).expect("Failed to open file");
        let mut result_content = String::new();
        result_file
            .read_to_string(&mut result_content)
            .expect("Failed to read file");

        let result_data: ResultData =
            serde_json::from_str(&result_content).expect("Failed to parse JSON");

        let pubkey_file_path = "./src/test/user_pubkey.json";

        let mut pubkey_file = fs::File::open(pubkey_file_path).expect("Failed to open file");
        let mut pubkey_content = String::new();

        pubkey_file
            .read_to_string(&mut pubkey_content)
            .expect("Failed to read file");
        let pubkey_data: UserPubkeyData =
            serde_json::from_str(&pubkey_content).expect("Failed to parse JSON");

        let mut app = create_app();
        let code_id = MaciCodeId::store_code(&mut app);
        let label = "Group";
        let contract = code_id
            .instantiate_with_start_time(&mut app, owner(), user1(), user2(), label)
            .unwrap();

        let start_voting_error = contract.start_voting(&mut app, owner()).unwrap_err();

        assert_eq!(
            ContractError::AlreadySetVotingTime {
                time_name: String::from("start_time")
            },
            start_voting_error.downcast().unwrap()
        );

        // check winner
        let num_sign_up = contract.num_sign_up(&app).unwrap();
        assert_eq!(num_sign_up, Uint256::from_u128(0u128));

        let test_pubkey = PubKey {
            x: uint256_from_decimal_string(&data.current_state_leaves[0][0]),
            y: uint256_from_decimal_string(&data.current_state_leaves[0][1]),
        };
        let sign_up_error = contract
            .sign_up(
                &mut app,
                Addr::unchecked(0.to_string()),
                test_pubkey.clone(),
            )
            .unwrap_err();
        assert_eq!(
            ContractError::PeriodError {},
            sign_up_error.downcast().unwrap()
        ); // 不能在voting环节之前进行signup

        _ = contract.set_vote_option_map(&mut app, owner());

        let stop_voting_before_start_error = contract.stop_voting(&mut app, owner()).unwrap_err();
        assert_eq!(
            ContractError::PeriodError {},
            stop_voting_before_start_error.downcast().unwrap()
        );

        app.update_block(next_block); // Start Voting
        let set_vote_option_map_error =
            contract.set_vote_option_map(&mut app, owner()).unwrap_err();

        assert_eq!(
            ContractError::PeriodError {},
            set_vote_option_map_error.downcast().unwrap()
        );

        for i in 0..data.msgs.len() {
            if i < Uint256::from_u128(2u128).to_string().parse().unwrap() {
                let pubkey = PubKey {
                    x: uint256_from_decimal_string(&pubkey_data.pubkeys[i][0]),
                    y: uint256_from_decimal_string(&pubkey_data.pubkeys[i][1]),
                };

                println!("---------- signup ---------- {:?}", i);
                let _ = contract.sign_up(&mut app, Addr::unchecked(i.to_string()), pubkey);
            }
            let message = MessageData {
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
            _ = contract.publish_message(&mut app, user2(), message, enc_pub);
        }

        assert_eq!(
            contract.num_sign_up(&app).unwrap(),
            Uint256::from_u128(2u128)
        );

        assert_eq!(
            contract.msg_length(&app).unwrap(),
            Uint256::from_u128(3u128)
        );

        // let sign_up_after_voting_end_error = contract
        //     .sign_up(
        //         &mut app,
        //         Addr::unchecked(0.to_string()),
        //         test_pubkey.clone(),
        //     )
        //     .unwrap_err();
        // assert_eq!(
        //     // 注册之后不能再进行注册
        //     ContractError::Unauthorized {},
        //     sign_up_after_voting_end_error.downcast().unwrap()
        // );

        // Stop Voting Period
        // app.update_block(next_block);
        _ = contract.stop_voting(&mut app, owner());

        let sign_up_after_voting_end_error = contract
            .sign_up(
                &mut app,
                Addr::unchecked(3.to_string()),
                test_pubkey.clone(),
            )
            .unwrap_err();
        assert_eq!(
            // 不能投票环节结束之后不能进行sign up
            ContractError::PeriodError {},
            sign_up_after_voting_end_error.downcast().unwrap()
        );

        let stop_voting_after_voting_end_error =
            contract.stop_voting(&mut app, owner()).unwrap_err();
        assert_eq!(
            ContractError::AlreadySetVotingTime {
                time_name: String::from("end_time")
            },
            stop_voting_after_voting_end_error.downcast().unwrap()
        );

        app.update_block(next_block);
        _ = contract.start_process(&mut app, owner());
        println!(
            "after start process: {:?}",
            contract.get_period(&app).unwrap()
        );

        let new_state_commitment = uint256_from_decimal_string(&data.new_state_commitment);
        let proof = Groth16ProofType {
            a: "27fb48285bc59bc74c9197857856cf5f3dcce55f22b83589e399240b8469e45725c5495e3ebcdd3bc04620fd13fed113c31d19a685f7f037daf02dde02d26e4f".to_string(),
            b: "0d1bd72809defb6e85ea48de4c28e9ec9dcd2bc5111acdb66b5cdb38ccf6d4e32bdeac48a806c2fd6cef8e09bfde1983961693c8d4a513777ba26b07f2abacba1efb7600f04e786d93f321c6df732eb0043548cfe12fa8a5aea848a500ef5b9728dbc747fc76993c16dadf2c8ef68f3d757afa6d4caf9a767c424ec0d7ff4932".to_string(),
            c: "2062c6bee5dad15af1ebcb0e623b27f7d29775774cc92b2a7554d1801af818940309fa215204181d3a1fef15d162aa779b8900e2b84d8b8fa22a20b65652eb46".to_string()
        };
        println!("process_message proof {:?}", proof);
        println!(
            "process_message new state commitment {:?}",
            new_state_commitment
        );
        _ = contract
            .process_message(&mut app, owner(), new_state_commitment, proof)
            .unwrap();

        _ = contract.stop_processing(&mut app, owner());
        println!(
            "after stop process: {:?}",
            contract.get_period(&app).unwrap()
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

        let tally_proof = Groth16ProofType {
            a: "2554bb7be658b5261bbcacef022d86dc55360f936a1473aa5c70c5b20083d7370deb7df6a8d0e74ae7f8b310725f3063407679fd99d23a7ad77b7d1bff5572d5".to_string(),
            b: "0fa4de46a0fc9d269314bbac4fb8f3425780bcde9b613a5252400216dadc3b5809f1d59c5f84892444c89712ab087cd708dcec5b77c108d9db73a8821be6720302f4820fec3af0e29b8a8aaf83db039d46703795d6275f934a14e8edc040e18f2dab2b05decd1b5bdb18631b9a8106714ceb5cf9fa6f4a4325cf4289a4025fc7".to_string(),
            c: "0d6a9f2eb8cfb28368bf6976f2925a3fb8ac0ead8dc95fc9a79318d0518f24801dced0525cbb2f15f24198bfe3f77c1065120be9dcbc3d10c77ca5861c410910".to_string()
        };

        _ = contract
            .process_tally(&mut app, owner(), new_tally_commitment, tally_proof)
            .unwrap();

        let results: Vec<Uint256> = result_data
            .results
            .iter()
            .map(|input| uint256_from_decimal_string(input))
            .collect();

        let salt = uint256_from_decimal_string(&tally_data.new_results_root_salt);
        _ = contract.stop_tallying(&mut app, owner(), results, salt);

        let all_result = contract.get_all_result(&app);
        println!("all_result: {:?}", all_result);
    }

    #[test]
    fn instantiate_with_end_time_should_works() {
        let msg_file_path = "./src/test/msg_test.json";

        let mut msg_file = fs::File::open(msg_file_path).expect("Failed to open file");
        let mut msg_content = String::new();

        msg_file
            .read_to_string(&mut msg_content)
            .expect("Failed to read file");

        let data: MsgData = serde_json::from_str(&msg_content).expect("Failed to parse JSON");

        let result_file_path = "./src/test/result.json";
        let mut result_file = fs::File::open(result_file_path).expect("Failed to open file");
        let mut result_content = String::new();
        result_file
            .read_to_string(&mut result_content)
            .expect("Failed to read file");

        let result_data: ResultData =
            serde_json::from_str(&result_content).expect("Failed to parse JSON");

        let pubkey_file_path = "./src/test/user_pubkey.json";

        let mut pubkey_file = fs::File::open(pubkey_file_path).expect("Failed to open file");
        let mut pubkey_content = String::new();

        pubkey_file
            .read_to_string(&mut pubkey_content)
            .expect("Failed to read file");
        let pubkey_data: UserPubkeyData =
            serde_json::from_str(&pubkey_content).expect("Failed to parse JSON");

        let mut app = create_app();
        let code_id = MaciCodeId::store_code(&mut app);
        let label = "Group";
        let contract = code_id
            .instantiate_with_end_time(&mut app, owner(), user1(), user2(), label)
            .unwrap();

        _ = contract.start_voting(&mut app, owner());

        let start_voting_error = contract.start_voting(&mut app, owner()).unwrap_err();
        assert_eq!(
            ContractError::AlreadySetVotingTime {
                time_name: String::from("start_time")
            },
            start_voting_error.downcast().unwrap()
        );

        // check winner
        let num_sign_up = contract.num_sign_up(&app).unwrap();
        assert_eq!(num_sign_up, Uint256::from_u128(0u128));

        let test_pubkey = PubKey {
            x: uint256_from_decimal_string(&data.current_state_leaves[0][0]),
            y: uint256_from_decimal_string(&data.current_state_leaves[0][1]),
        };
        let sign_up_error = contract
            .sign_up(
                &mut app,
                Addr::unchecked(0.to_string()),
                test_pubkey.clone(),
            )
            .unwrap_err();
        assert_eq!(
            ContractError::PeriodError {},
            sign_up_error.downcast().unwrap()
        ); // 不能在voting环节之前进行signup

        _ = contract.set_vote_option_map(&mut app, owner());

        let stop_voting_before_start_error = contract.stop_voting(&mut app, owner()).unwrap_err();
        assert_eq!(
            ContractError::AlreadySetVotingTime {
                time_name: String::from("end_time")
            },
            stop_voting_before_start_error.downcast().unwrap()
        );

        app.update_block(next_block); // Start Voting
        let set_vote_option_map_error =
            contract.set_vote_option_map(&mut app, owner()).unwrap_err();

        assert_eq!(
            ContractError::PeriodError {},
            set_vote_option_map_error.downcast().unwrap()
        );

        for i in 0..data.msgs.len() {
            if i < Uint256::from_u128(2u128).to_string().parse().unwrap() {
                let pubkey = PubKey {
                    x: uint256_from_decimal_string(&pubkey_data.pubkeys[i][0]),
                    y: uint256_from_decimal_string(&pubkey_data.pubkeys[i][1]),
                };

                println!("---------- signup ---------- {:?}", i);
                let _ = contract.sign_up(&mut app, Addr::unchecked(i.to_string()), pubkey);
            }
            let message = MessageData {
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
            _ = contract.publish_message(&mut app, user2(), message, enc_pub);
        }

        assert_eq!(
            contract.num_sign_up(&app).unwrap(),
            Uint256::from_u128(2u128)
        );

        assert_eq!(
            contract.msg_length(&app).unwrap(),
            Uint256::from_u128(3u128)
        );

        // let sign_up_after_voting_end_error = contract
        //     .sign_up(
        //         &mut app,
        //         Addr::unchecked(0.to_string()),
        //         test_pubkey.clone(),
        //     )
        //     .unwrap_err();
        // assert_eq!(
        //     // 注册之后不能再进行注册
        //     ContractError::Unauthorized {},
        //     sign_up_after_voting_end_error.downcast().unwrap()
        // );

        // Stop Voting Period
        app.update_block(next_block);
        // _ = contract.stop_voting(&mut app, owner());

        let sign_up_after_voting_end_error = contract
            .sign_up(
                &mut app,
                Addr::unchecked(3.to_string()),
                test_pubkey.clone(),
            )
            .unwrap_err();
        assert_eq!(
            // 不能投票环节结束之后不能进行sign up
            ContractError::PeriodError {},
            sign_up_after_voting_end_error.downcast().unwrap()
        );

        let stop_voting_after_voting_end_error =
            contract.stop_voting(&mut app, owner()).unwrap_err();
        assert_eq!(
            ContractError::AlreadySetVotingTime {
                time_name: String::from("end_time")
            },
            stop_voting_after_voting_end_error.downcast().unwrap()
        );
        app.update_block(next_block);

        _ = contract.start_process(&mut app, owner());
        println!(
            "after start process: {:?}",
            contract.get_period(&app).unwrap()
        );

        let new_state_commitment = uint256_from_decimal_string(&data.new_state_commitment);
        let proof = Groth16ProofType {
            a: "27fb48285bc59bc74c9197857856cf5f3dcce55f22b83589e399240b8469e45725c5495e3ebcdd3bc04620fd13fed113c31d19a685f7f037daf02dde02d26e4f".to_string(),
            b: "0d1bd72809defb6e85ea48de4c28e9ec9dcd2bc5111acdb66b5cdb38ccf6d4e32bdeac48a806c2fd6cef8e09bfde1983961693c8d4a513777ba26b07f2abacba1efb7600f04e786d93f321c6df732eb0043548cfe12fa8a5aea848a500ef5b9728dbc747fc76993c16dadf2c8ef68f3d757afa6d4caf9a767c424ec0d7ff4932".to_string(),
            c: "2062c6bee5dad15af1ebcb0e623b27f7d29775774cc92b2a7554d1801af818940309fa215204181d3a1fef15d162aa779b8900e2b84d8b8fa22a20b65652eb46".to_string()
        };
        println!("process_message proof {:?}", proof);
        println!(
            "process_message new state commitment {:?}",
            new_state_commitment
        );
        _ = contract
            .process_message(&mut app, owner(), new_state_commitment, proof)
            .unwrap();

        _ = contract.stop_processing(&mut app, owner());
        println!(
            "after stop process: {:?}",
            contract.get_period(&app).unwrap()
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

        let tally_proof = Groth16ProofType {
            a: "2554bb7be658b5261bbcacef022d86dc55360f936a1473aa5c70c5b20083d7370deb7df6a8d0e74ae7f8b310725f3063407679fd99d23a7ad77b7d1bff5572d5".to_string(),
            b: "0fa4de46a0fc9d269314bbac4fb8f3425780bcde9b613a5252400216dadc3b5809f1d59c5f84892444c89712ab087cd708dcec5b77c108d9db73a8821be6720302f4820fec3af0e29b8a8aaf83db039d46703795d6275f934a14e8edc040e18f2dab2b05decd1b5bdb18631b9a8106714ceb5cf9fa6f4a4325cf4289a4025fc7".to_string(),
            c: "0d6a9f2eb8cfb28368bf6976f2925a3fb8ac0ead8dc95fc9a79318d0518f24801dced0525cbb2f15f24198bfe3f77c1065120be9dcbc3d10c77ca5861c410910".to_string()
        };

        _ = contract
            .process_tally(&mut app, owner(), new_tally_commitment, tally_proof)
            .unwrap();

        let results: Vec<Uint256> = result_data
            .results
            .iter()
            .map(|input| uint256_from_decimal_string(input))
            .collect();

        let salt = uint256_from_decimal_string(&tally_data.new_results_root_salt);
        _ = contract.stop_tallying(&mut app, owner(), results, salt);

        let all_result = contract.get_all_result(&app);
        println!("all_result: {:?}", all_result);
    }

    #[test]
    fn instantiate_with_wrong_voting_time_error() {
        let mut app = create_app();
        let code_id = MaciCodeId::store_code(&mut app);
        let label = "Group";
        let contract = code_id
            .instantiate_with_wrong_voting_time(&mut app, owner(), user1(), user2(), label)
            .unwrap_err();

        // let start_voting_error = contract.start_voting(&mut app, owner()).unwrap_err();

        assert_eq!(ContractError::WrongTimeSet {}, contract.downcast().unwrap());
    }

    #[test]
    fn instantiate_with_voting_time_isqv_should_works() {
        let msg_file_path = "./src/test/qv_test/msg.json";

        let mut msg_file = fs::File::open(msg_file_path).expect("Failed to open file");
        let mut msg_content = String::new();

        msg_file
            .read_to_string(&mut msg_content)
            .expect("Failed to read file");

        let data: MsgData = serde_json::from_str(&msg_content).expect("Failed to parse JSON");

        let result_file_path = "./src/test/qv_test/result.json";
        let mut result_file = fs::File::open(result_file_path).expect("Failed to open file");
        let mut result_content = String::new();
        result_file
            .read_to_string(&mut result_content)
            .expect("Failed to read file");

        let result_data: ResultData =
            serde_json::from_str(&result_content).expect("Failed to parse JSON");

        let pubkey_file_path = "./src/test/user_pubkey.json";

        let mut pubkey_file = fs::File::open(pubkey_file_path).expect("Failed to open file");
        let mut pubkey_content = String::new();

        pubkey_file
            .read_to_string(&mut pubkey_content)
            .expect("Failed to read file");
        let pubkey_data: UserPubkeyData =
            serde_json::from_str(&pubkey_content).expect("Failed to parse JSON");

        let mut app = create_app();
        let code_id = MaciCodeId::store_code(&mut app);
        let label = "Group";
        let contract = code_id
            .instantiate_with_voting_time_isqv(&mut app, owner(), user1(), user2(), label)
            .unwrap();

        let start_voting_error = contract.start_voting(&mut app, owner()).unwrap_err();

        assert_eq!(
            ContractError::AlreadySetVotingTime {
                time_name: String::from("start_time")
            },
            start_voting_error.downcast().unwrap()
        );

        let num_sign_up = contract.num_sign_up(&app).unwrap();
        assert_eq!(num_sign_up, Uint256::from_u128(0u128));

        let vote_option_map = contract.vote_option_map(&app).unwrap();
        let max_vote_options = contract.max_vote_options(&app).unwrap();
        assert_eq!(vote_option_map, vec!["", "", "", "", ""]);
        assert_eq!(max_vote_options, Uint256::from_u128(5u128));
        _ = contract.set_vote_option_map(&mut app, owner());
        let new_vote_option_map = contract.vote_option_map(&app).unwrap();
        assert_eq!(
            new_vote_option_map,
            vec![
                String::from("did_not_vote"),
                String::from("yes"),
                String::from("no"),
                String::from("no_with_veto"),
                String::from("abstain"),
            ]
        );
        // assert_eq!(num_sign_up, Uint256::from_u128(0u128));

        let test_pubkey = PubKey {
            x: uint256_from_decimal_string(&data.current_state_leaves[0][0]),
            y: uint256_from_decimal_string(&data.current_state_leaves[0][1]),
        };
        let sign_up_error = contract
            .sign_up(
                &mut app,
                Addr::unchecked(0.to_string()),
                test_pubkey.clone(),
            )
            .unwrap_err();
        assert_eq!(
            ContractError::PeriodError {},
            sign_up_error.downcast().unwrap()
        ); // 不能在voting环节之前进行signup

        _ = contract.set_vote_option_map(&mut app, owner());

        app.update_block(next_block); // Start Voting
        let set_whitelist_only_in_pending = contract.set_whitelist(&mut app, owner()).unwrap_err();
        assert_eq!(
            // 注册之后不能再进行注册
            ContractError::PeriodError {},
            set_whitelist_only_in_pending.downcast().unwrap()
        );
        let set_vote_option_map_error =
            contract.set_vote_option_map(&mut app, owner()).unwrap_err();
        assert_eq!(
            ContractError::PeriodError {},
            set_vote_option_map_error.downcast().unwrap()
        );

        let error_start_process_in_voting = contract.start_process(&mut app, owner()).unwrap_err();
        assert_eq!(
            ContractError::PeriodError {},
            error_start_process_in_voting.downcast().unwrap()
        );
        assert_eq!(
            Period {
                status: PeriodStatus::Pending
            },
            contract.get_period(&app).unwrap()
        );

        for i in 0..data.msgs.len() {
            if i < Uint256::from_u128(2u128).to_string().parse().unwrap() {
                let pubkey = PubKey {
                    x: uint256_from_decimal_string(&pubkey_data.pubkeys[i][0]),
                    y: uint256_from_decimal_string(&pubkey_data.pubkeys[i][1]),
                };

                println!("---------- signup ---------- {:?}", i);
                let _ = contract.sign_up(&mut app, Addr::unchecked(i.to_string()), pubkey);
            }
            let message = MessageData {
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
            _ = contract.publish_message(&mut app, user2(), message, enc_pub);
        }

        // let sign_up_after_voting_end_error = contract
        //     .sign_up(
        //         &mut app,
        //         Addr::unchecked(0.to_string()),
        //         test_pubkey.clone(),
        //     )
        //     .unwrap_err();
        // assert_eq!(
        //     // 注册之后不能再进行注册
        //     ContractError::Unauthorized {},
        //     sign_up_after_voting_end_error.downcast().unwrap()
        // );

        assert_eq!(
            contract.num_sign_up(&app).unwrap(),
            Uint256::from_u128(2u128)
        );

        assert_eq!(
            contract.msg_length(&app).unwrap(),
            Uint256::from_u128(3u128)
        );

        // Stop Voting Period
        app.update_block(next_block);

        let sign_up_after_voting_end_error = contract
            .sign_up(
                &mut app,
                Addr::unchecked(3.to_string()),
                test_pubkey.clone(),
            )
            .unwrap_err();
        assert_eq!(
            // 不能投票环节结束之后不能进行sign up
            ContractError::PeriodError {},
            sign_up_after_voting_end_error.downcast().unwrap()
        );

        let stop_voting_error = contract.stop_voting(&mut app, owner()).unwrap_err();
        assert_eq!(
            ContractError::AlreadySetVotingTime {
                time_name: String::from("end_time")
            },
            stop_voting_error.downcast().unwrap()
        );
        app.update_block(next_block);

        _ = contract.start_process(&mut app, owner());
        assert_eq!(
            Period {
                status: PeriodStatus::Processing
            },
            contract.get_period(&app).unwrap()
        );

        println!(
            "after start process: {:?}",
            contract.get_period(&app).unwrap()
        );

        let new_state_commitment = uint256_from_decimal_string(&data.new_state_commitment);
        let proof = Groth16ProofType {
                a: "25b5c63b4d2f7d3ac4a01258040ea6ab731797144ec246c3af3c6578986b10720522540f38cab117c83e58f6540a43c7dd77c807ed436b344f9a137d8a4c8b32".to_string(),
                b: "01aba8a6b76bb1c7b301c2f0c15005a0550a94b68c0f19b01ff385e4c441f5a610ad81a1689db632c16c2054fd862cd1ad132a3b46926dd21769ff9e691c2a670ef6e81de05b039fd805422437e890581edd4db80469deefb2edcddcf2872dec15a7b27a5ea2c2886d04e5454b9d24918a90bf0865326217d0e8f78abdef18fb".to_string(),
                c: "02a00a70680f2e20f28521bdf8bd139cd2227051bcdf2d5744e85c2b3c5f2f642aceac09e1cc3fe487f587f4a6fa362d71ac6669f6870a0ed33a89a4c8c297e0".to_string()
            };
        println!("process_message proof {:?}", proof);
        println!(
            "process_message new state commitment {:?}",
            new_state_commitment
        );
        _ = contract
            .process_message(&mut app, owner(), new_state_commitment, proof)
            .unwrap();

        _ = contract.stop_processing(&mut app, owner());
        println!(
            "after stop process: {:?}",
            contract.get_period(&app).unwrap()
        );

        let error_start_process_in_talling = contract.start_process(&mut app, owner()).unwrap_err();
        assert_eq!(
            ContractError::PeriodError {},
            error_start_process_in_talling.downcast().unwrap()
        );
        assert_eq!(
            Period {
                status: PeriodStatus::Tallying
            },
            contract.get_period(&app).unwrap()
        );
        let tally_path = "./src/test/qv_test/tally.json";
        let mut tally_file = fs::File::open(tally_path).expect("Failed to open file");
        let mut tally_content = String::new();
        tally_file
            .read_to_string(&mut tally_content)
            .expect("Failed to read file");

        let tally_data: TallyData =
            serde_json::from_str(&tally_content).expect("Failed to parse JSON");

        let new_tally_commitment = uint256_from_decimal_string(&tally_data.new_tally_commitment);

        let tally_proof = Groth16ProofType {
            a: "2887519d960001d9a47a6338fadaa9ae57a52ed7ebd8a56c80616e4245762caf221b1a4188c4a6e8db5f968a6c04c56a4ca1b2f46a254f7b2737e444394e6f96".to_string(),
            b: "2dacd0fc846bf705ae591121f8fcd6f240dbd8eac23902c0da6fa791cf4a553c1f320f588c5ace3c42edcaeeb6242491accc6dde284d18d107952600b2dc91160687d1a8ff86fc397f0c19f3fd2f68d1a629a8a30f9d696561c70b342df1b97e20f79261ae47d812805ecaac01b6408cd5049383953439b97b58f1348831ac4e".to_string(),
            c: "09e8a2dcf849d84d05d567c482ab144e252755e820cb331eafab44ed96e13b28158341fa2103ac8efdebe336beed5ddec420ca0e3f6736aa7f7937418c0c4f29".to_string()
        };

        _ = contract
            .process_tally(&mut app, owner(), new_tally_commitment, tally_proof)
            .unwrap();

        let results: Vec<Uint256> = result_data
            .results
            .iter()
            .map(|input| uint256_from_decimal_string(input))
            .collect();

        let salt = uint256_from_decimal_string(&tally_data.new_results_root_salt);
        _ = contract.stop_tallying(&mut app, owner(), results, salt);

        let all_result = contract.get_all_result(&app);
        println!("all_result: {:?}", all_result);
        let error_start_process = contract.start_process(&mut app, owner()).unwrap_err();
        assert_eq!(
            ContractError::PeriodError {},
            error_start_process.downcast().unwrap()
        );

        assert_eq!(
            Period {
                status: PeriodStatus::Ended
            },
            contract.get_period(&app).unwrap()
        );
    }

    // #[test]
    fn instantiate_with_voting_time_and_test_grant_should_works() {
        let admin_coin_amount = 50u128;
        let bond_coin_amount = 10u128;
        const DORA_DEMON: &str = "peaka";

        let msg_file_path = "./src/test/msg_test.json";

        let mut msg_file = fs::File::open(msg_file_path).expect("Failed to open file");
        let mut msg_content = String::new();

        msg_file
            .read_to_string(&mut msg_content)
            .expect("Failed to read file");

        let data: MsgData = serde_json::from_str(&msg_content).expect("Failed to parse JSON");

        let mut app = AppBuilder::default()
            .with_stargate(StargateAccepting)
            .build(|router, _api, storage| {
                router
                    .bank
                    .init_balance(storage, &owner(), coins(admin_coin_amount, DORA_DEMON))
                    .unwrap();
            });

        let code_id = MaciCodeId::store_code(&mut app);
        let label = "Group";
        let contract = code_id
            .instantiate_with_voting_time_and_no_whitelist(&mut app, owner(), label)
            .unwrap();

        _ = contract.set_vote_option_map(&mut app, owner());
        let new_vote_option_map = contract.vote_option_map(&app).unwrap();
        assert_eq!(
            new_vote_option_map,
            vec![
                String::from("did_not_vote"),
                String::from("yes"),
                String::from("no"),
                String::from("no_with_veto"),
                String::from("abstain"),
            ]
        );
        _ = contract.set_whitelist(&mut app, owner());

        let error_grant_in_pending = contract
            .grant(&mut app, owner(), &coins(bond_coin_amount, DORA_DEMON))
            .unwrap_err();
        assert_eq!(
            ContractError::PeriodError {},
            error_grant_in_pending.downcast().unwrap()
        );

        _ = contract.set_vote_option_map(&mut app, owner());

        app.update_block(next_block); // Start Voting

        let a = contract.grant(&mut app, owner(), &coins(bond_coin_amount, DORA_DEMON));
        println!("grant res: {:?}", a);
        let feegrant_amount = contract.query_total_feegrant(&app).unwrap();
        assert_eq!(Uint128::from(10000000000000u128), feegrant_amount);

        for i in 0..data.msgs.len() {
            if i < Uint256::from_u128(2u128).to_string().parse().unwrap() {
                let pubkey = PubKey {
                    x: uint256_from_decimal_string(&data.current_state_leaves[i][0]),
                    y: uint256_from_decimal_string(&data.current_state_leaves[i][1]),
                };

                println!("---------- signup ---------- {:?}", i);
                let _ = contract.sign_up(&mut app, Addr::unchecked(i.to_string()), pubkey);
            }
            let message = MessageData {
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
            _ = contract.publish_message(&mut app, user2(), message, enc_pub);
        }

        assert_eq!(
            contract.num_sign_up(&app).unwrap(),
            Uint256::from_u128(2u128)
        );

        assert_eq!(
            contract.msg_length(&app).unwrap(),
            Uint256::from_u128(3u128)
        );

        // Stop Voting Period
        app.update_block(next_block);
    }
}
