#[cfg(test)]
mod test {
    use cosmwasm_std::{coins, Addr, Uint128, Uint256};

    use cw_multi_test::{next_block, App};

    use crate::error::ContractError;
    use crate::msg::ProofType;
    use crate::multitest::{owner, uint256_from_decimal_string, user1, user2, MaciCodeId};
    use crate::state::{MessageData, Period, PeriodStatus, PubKey, RoundInfo};
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

    // #[test]
    fn instantiate_with_no_voting_time_should_works() {
        let msg_file_path = "./src/test/msg_test.json";

        let mut msg_file = fs::File::open(msg_file_path).expect("Failed to open file");
        let mut msg_content = String::new();

        msg_file
            .read_to_string(&mut msg_content)
            .expect("Failed to read file");

        let data: MsgData = serde_json::from_str(&msg_content).expect("Failed to parse JSON");

        let mut app = App::default();

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

        for i in 0..data.msgs.len() {
            if i < Uint256::from_u128(2u128).to_string().parse().unwrap() {
                let pubkey = PubKey {
                    x: uint256_from_decimal_string(&data.current_state_leaves[i][0]),
                    y: uint256_from_decimal_string(&data.current_state_leaves[i][1]),
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

        let sign_up_after_voting_end_error = contract
            .sign_up(
                &mut app,
                Addr::unchecked(0.to_string()),
                test_pubkey.clone(),
            )
            .unwrap_err();
        assert_eq!(
            // 注册之后不能再进行注册
            ContractError::Unauthorized {},
            sign_up_after_voting_end_error.downcast().unwrap()
        );

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
        let proof = ProofType {
                a: "29c214f2e1b0b10ebdb52c629714526764355daa96aa077cb249db04586e705b0c4dcf9b653d561cec0988842f8604c7fc3b9742bf27864637ac6b14b675644c".to_string(),
                b: "21c903a347fa0c9640d749c974f63317d4597f194d0df896c4150a2e970484790792a071af0a7e50ada1c2dc0e5eb443e3c4661c036a9705cdccfcc5d3f0d3e617fc7d5525fe41a47171448b17bb31f90cceca92de9416268c2e55f37f76e2b8248c8231d33675174cdafe8ad04b8b17a42894f5e047d2984519be75312ae4ac".to_string(),
                c: "0367155150920842a79a007ce6a311e3f970a45548354fec69216eea28661a0c10e1fa54022a7f4b078e7972f76ac91fa446447f0b2b4c4dc539f7c3f9c546da".to_string()
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

        let tally_proof = ProofType {
            a: "136119496feea080d3b191f8f872ee471642f5e9c3c55f3dfd38b5510d8c3ea3188944f0866a4ddb3ee0543a0b57b80ce5cfadbdbbaae1e3b8c70f7ac05718de".to_string(),
            b: "171e57bd50b3cc28db893095de6ee56336847890bb46563bceac48fc5d8d1b66079bd76a71d5b90a97cbe34c6fdf7277c2aee5292e82d7f62407d019cc74be3b1865535414327686604c0bda663a375411ed8e89619e61c2d603ee3ef678eb602d4e3d5106dba466709c76a7e204c5557fbba126b7b56925c4927e01cbbe10d1".to_string(),
            c: "111e06873463cd8749a1bd8adc83d252fe79097089777668e40007accdb7cdb406de890a7d29c08a90ed207a140b0ad142f558754708b86c3ca61444143eb40d".to_string()
        };

        _ = contract.process_tally(&mut app, owner(), new_tally_commitment, tally_proof);
        println!("------ tally");
        let results: Vec<Uint256> = tally_data
            .current_results
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

        let mut app = App::default();
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

        let sign_up_after_voting_end_error = contract
            .sign_up(
                &mut app,
                Addr::unchecked(0.to_string()),
                test_pubkey.clone(),
            )
            .unwrap_err();
        assert_eq!(
            // 注册之后不能再进行注册
            ContractError::Unauthorized {},
            sign_up_after_voting_end_error.downcast().unwrap()
        );

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
        let proof = ProofType {
                a: "29c214f2e1b0b10ebdb52c629714526764355daa96aa077cb249db04586e705b0c4dcf9b653d561cec0988842f8604c7fc3b9742bf27864637ac6b14b675644c".to_string(),
                b: "21c903a347fa0c9640d749c974f63317d4597f194d0df896c4150a2e970484790792a071af0a7e50ada1c2dc0e5eb443e3c4661c036a9705cdccfcc5d3f0d3e617fc7d5525fe41a47171448b17bb31f90cceca92de9416268c2e55f37f76e2b8248c8231d33675174cdafe8ad04b8b17a42894f5e047d2984519be75312ae4ac".to_string(),
                c: "0367155150920842a79a007ce6a311e3f970a45548354fec69216eea28661a0c10e1fa54022a7f4b078e7972f76ac91fa446447f0b2b4c4dc539f7c3f9c546da".to_string()
            };
        println!("process_message proof {:?}", proof);
        println!(
            "process_message new state commitment {:?}",
            new_state_commitment
        );
        _ = contract.process_message(&mut app, owner(), new_state_commitment, proof);

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

        let tally_proof = ProofType {
            a: "136119496feea080d3b191f8f872ee471642f5e9c3c55f3dfd38b5510d8c3ea3188944f0866a4ddb3ee0543a0b57b80ce5cfadbdbbaae1e3b8c70f7ac05718de".to_string(),
            b: "171e57bd50b3cc28db893095de6ee56336847890bb46563bceac48fc5d8d1b66079bd76a71d5b90a97cbe34c6fdf7277c2aee5292e82d7f62407d019cc74be3b1865535414327686604c0bda663a375411ed8e89619e61c2d603ee3ef678eb602d4e3d5106dba466709c76a7e204c5557fbba126b7b56925c4927e01cbbe10d1".to_string(),
            c: "111e06873463cd8749a1bd8adc83d252fe79097089777668e40007accdb7cdb406de890a7d29c08a90ed207a140b0ad142f558754708b86c3ca61444143eb40d".to_string()
        };

        _ = contract.process_tally(&mut app, owner(), new_tally_commitment, tally_proof);

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
    fn instantiate_with_start_time_should_works() {
        let msg_file_path = "./src/test/msg_test.json";

        let mut msg_file = fs::File::open(msg_file_path).expect("Failed to open file");
        let mut msg_content = String::new();

        msg_file
            .read_to_string(&mut msg_content)
            .expect("Failed to read file");

        let data: MsgData = serde_json::from_str(&msg_content).expect("Failed to parse JSON");

        let mut app = App::default();
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

        let sign_up_after_voting_end_error = contract
            .sign_up(
                &mut app,
                Addr::unchecked(0.to_string()),
                test_pubkey.clone(),
            )
            .unwrap_err();
        assert_eq!(
            // 注册之后不能再进行注册
            ContractError::Unauthorized {},
            sign_up_after_voting_end_error.downcast().unwrap()
        );

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
        let proof = ProofType {
                a: "29c214f2e1b0b10ebdb52c629714526764355daa96aa077cb249db04586e705b0c4dcf9b653d561cec0988842f8604c7fc3b9742bf27864637ac6b14b675644c".to_string(),
                b: "21c903a347fa0c9640d749c974f63317d4597f194d0df896c4150a2e970484790792a071af0a7e50ada1c2dc0e5eb443e3c4661c036a9705cdccfcc5d3f0d3e617fc7d5525fe41a47171448b17bb31f90cceca92de9416268c2e55f37f76e2b8248c8231d33675174cdafe8ad04b8b17a42894f5e047d2984519be75312ae4ac".to_string(),
                c: "0367155150920842a79a007ce6a311e3f970a45548354fec69216eea28661a0c10e1fa54022a7f4b078e7972f76ac91fa446447f0b2b4c4dc539f7c3f9c546da".to_string()
            };
        println!("process_message proof {:?}", proof);
        println!(
            "process_message new state commitment {:?}",
            new_state_commitment
        );
        _ = contract.process_message(&mut app, owner(), new_state_commitment, proof);

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

        let tally_proof = ProofType {
            a: "136119496feea080d3b191f8f872ee471642f5e9c3c55f3dfd38b5510d8c3ea3188944f0866a4ddb3ee0543a0b57b80ce5cfadbdbbaae1e3b8c70f7ac05718de".to_string(),
            b: "171e57bd50b3cc28db893095de6ee56336847890bb46563bceac48fc5d8d1b66079bd76a71d5b90a97cbe34c6fdf7277c2aee5292e82d7f62407d019cc74be3b1865535414327686604c0bda663a375411ed8e89619e61c2d603ee3ef678eb602d4e3d5106dba466709c76a7e204c5557fbba126b7b56925c4927e01cbbe10d1".to_string(),
            c: "111e06873463cd8749a1bd8adc83d252fe79097089777668e40007accdb7cdb406de890a7d29c08a90ed207a140b0ad142f558754708b86c3ca61444143eb40d".to_string()
        };

        _ = contract.process_tally(&mut app, owner(), new_tally_commitment, tally_proof);

        let results: Vec<Uint256> = tally_data
            .current_results
            .iter()
            .map(|input| uint256_from_decimal_string(input))
            .collect();

        let salt = uint256_from_decimal_string(&tally_data.new_results_root_salt);
        _ = contract.stop_tallying(&mut app, owner(), results, salt);

        let all_result = contract.get_all_result(&app);
        println!("all_result: {:?}", all_result);
    }

    // #[test]
    fn instantiate_with_end_time_should_works() {
        let msg_file_path = "./src/test/msg_test.json";

        let mut msg_file = fs::File::open(msg_file_path).expect("Failed to open file");
        let mut msg_content = String::new();

        msg_file
            .read_to_string(&mut msg_content)
            .expect("Failed to read file");

        let data: MsgData = serde_json::from_str(&msg_content).expect("Failed to parse JSON");

        let mut app = App::default();
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

        let sign_up_after_voting_end_error = contract
            .sign_up(
                &mut app,
                Addr::unchecked(0.to_string()),
                test_pubkey.clone(),
            )
            .unwrap_err();
        assert_eq!(
            // 注册之后不能再进行注册
            ContractError::Unauthorized {},
            sign_up_after_voting_end_error.downcast().unwrap()
        );

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
        let proof = ProofType {
                a: "29c214f2e1b0b10ebdb52c629714526764355daa96aa077cb249db04586e705b0c4dcf9b653d561cec0988842f8604c7fc3b9742bf27864637ac6b14b675644c".to_string(),
                b: "21c903a347fa0c9640d749c974f63317d4597f194d0df896c4150a2e970484790792a071af0a7e50ada1c2dc0e5eb443e3c4661c036a9705cdccfcc5d3f0d3e617fc7d5525fe41a47171448b17bb31f90cceca92de9416268c2e55f37f76e2b8248c8231d33675174cdafe8ad04b8b17a42894f5e047d2984519be75312ae4ac".to_string(),
                c: "0367155150920842a79a007ce6a311e3f970a45548354fec69216eea28661a0c10e1fa54022a7f4b078e7972f76ac91fa446447f0b2b4c4dc539f7c3f9c546da".to_string()
            };
        println!("process_message proof {:?}", proof);
        println!(
            "process_message new state commitment {:?}",
            new_state_commitment
        );
        _ = contract.process_message(&mut app, owner(), new_state_commitment, proof);

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

        let tally_proof = ProofType {
            a: "136119496feea080d3b191f8f872ee471642f5e9c3c55f3dfd38b5510d8c3ea3188944f0866a4ddb3ee0543a0b57b80ce5cfadbdbbaae1e3b8c70f7ac05718de".to_string(),
            b: "171e57bd50b3cc28db893095de6ee56336847890bb46563bceac48fc5d8d1b66079bd76a71d5b90a97cbe34c6fdf7277c2aee5292e82d7f62407d019cc74be3b1865535414327686604c0bda663a375411ed8e89619e61c2d603ee3ef678eb602d4e3d5106dba466709c76a7e204c5557fbba126b7b56925c4927e01cbbe10d1".to_string(),
            c: "111e06873463cd8749a1bd8adc83d252fe79097089777668e40007accdb7cdb406de890a7d29c08a90ed207a140b0ad142f558754708b86c3ca61444143eb40d".to_string()
        };

        _ = contract.process_tally(&mut app, owner(), new_tally_commitment, tally_proof);

        let results: Vec<Uint256> = tally_data
            .current_results
            .iter()
            .map(|input| uint256_from_decimal_string(input))
            .collect();

        let salt = uint256_from_decimal_string(&tally_data.new_results_root_salt);
        _ = contract.stop_tallying(&mut app, owner(), results, salt);

        let all_result = contract.get_all_result(&app);
        println!("all_result: {:?}", all_result);
    }

    // #[test]
    fn instantiate_with_wrong_voting_time_error() {
        let mut app = App::default();
        let code_id = MaciCodeId::store_code(&mut app);
        let label = "Group";
        let contract = code_id
            .instantiate_with_wrong_voting_time(&mut app, owner(), user1(), user2(), label)
            .unwrap_err();

        // let start_voting_error = contract.start_voting(&mut app, owner()).unwrap_err();

        assert_eq!(ContractError::WrongTimeSet {}, contract.downcast().unwrap());
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

        let mut app = App::new(|router, _api, storage| {
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

    // #[test]
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

        let mut app = App::default();
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

        let sign_up_after_voting_end_error = contract
            .sign_up(
                &mut app,
                Addr::unchecked(0.to_string()),
                test_pubkey.clone(),
            )
            .unwrap_err();
        assert_eq!(
            // 注册之后不能再进行注册
            ContractError::Unauthorized {},
            sign_up_after_voting_end_error.downcast().unwrap()
        );

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
        let proof = ProofType {
                a: "1d357813049bc4b83ded0d9dab748251c70633d6283df4aef6c3c8f53da22942297e1f9820cdd8acd3719be1dc18c0d6d7d978b8022b10b2412c0be757d898cb".to_string(),
                b: "205d75e9165f8e472d935314381246d192e174262a19779afbb3fac8f9471b211b93759ce5a42fcb5c92a37b7013b9f9f72f13bd6d4190a7327d661b2a1530c205cc957a89cf5a4be26d822ea194bee53b59c8780f49e13968436a734c2e5de10f5fcf817e99122edce715d30bb63babbbdb7c541154c166ee2d9f42349957c8".to_string(),
                c: "15f91dba796a622d18dc73af0e50a5a7b2d9668f3cbd4015b4137b54c6743f5524080bdc6be18a94e8a3e638c684e4810465e065bb3c68d3c752e5fb8ea9ea65".to_string()
            };
        println!("process_message proof {:?}", proof);
        println!(
            "process_message new state commitment {:?}",
            new_state_commitment
        );
        _ = contract.process_message(&mut app, owner(), new_state_commitment, proof);

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

        let tally_proof = ProofType {
            a: "23e4c58a265d9c5c0c0b96f8882fa26b924c85719bc260873fb4d96a722254802f682da81d21a5ca6316fb7451fad4ed5282fcd01994e18b525dbbcd32fc3bec".to_string(),
            b: "253a0a3c1fe6ad269a80049ba63dca0fbb8d3ec64bccddc0246dc0541808432d1b7f72c0beb4cd64db1f718ab74cff52b5e3776f1f94f88136c96792ad452e7c02a2007a46b9b231a4abc46bb1682e8993c1655c14e8d05c8e5adbc1f88a3e73292067d24e6802a365750347b4506490979a83ae9cade7e00eae06df09488ab9".to_string(),
            c: "12a4d65323b9db119499574faeadfcfaac33890249a9919b859993fb96cba6382ecaeba6e50795170bbe5e545084b800faa20dc6fdcb8054b1b79886e683266f".to_string()
        };

        _ = contract.process_tally(&mut app, owner(), new_tally_commitment, tally_proof);

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
}
