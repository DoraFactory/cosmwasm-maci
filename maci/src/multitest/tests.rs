#[cfg(test)]
mod test {
    use crate::error::ContractError;
    use crate::msg::{Groth16ProofType, PlonkProofType};
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

        let tally_proof = Groth16ProofType {
            a: "136119496feea080d3b191f8f872ee471642f5e9c3c55f3dfd38b5510d8c3ea3188944f0866a4ddb3ee0543a0b57b80ce5cfadbdbbaae1e3b8c70f7ac05718de".to_string(),
            b: "171e57bd50b3cc28db893095de6ee56336847890bb46563bceac48fc5d8d1b66079bd76a71d5b90a97cbe34c6fdf7277c2aee5292e82d7f62407d019cc74be3b1865535414327686604c0bda663a375411ed8e89619e61c2d603ee3ef678eb602d4e3d5106dba466709c76a7e204c5557fbba126b7b56925c4927e01cbbe10d1".to_string(),
            c: "111e06873463cd8749a1bd8adc83d252fe79097089777668e40007accdb7cdb406de890a7d29c08a90ed207a140b0ad142f558754708b86c3ca61444143eb40d".to_string()
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
            a: "136119496feea080d3b191f8f872ee471642f5e9c3c55f3dfd38b5510d8c3ea3188944f0866a4ddb3ee0543a0b57b80ce5cfadbdbbaae1e3b8c70f7ac05718de".to_string(),
            b: "171e57bd50b3cc28db893095de6ee56336847890bb46563bceac48fc5d8d1b66079bd76a71d5b90a97cbe34c6fdf7277c2aee5292e82d7f62407d019cc74be3b1865535414327686604c0bda663a375411ed8e89619e61c2d603ee3ef678eb602d4e3d5106dba466709c76a7e204c5557fbba126b7b56925c4927e01cbbe10d1".to_string(),
            c: "111e06873463cd8749a1bd8adc83d252fe79097089777668e40007accdb7cdb406de890a7d29c08a90ed207a140b0ad142f558754708b86c3ca61444143eb40d".to_string()
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
            a: "136119496feea080d3b191f8f872ee471642f5e9c3c55f3dfd38b5510d8c3ea3188944f0866a4ddb3ee0543a0b57b80ce5cfadbdbbaae1e3b8c70f7ac05718de".to_string(),
            b: "171e57bd50b3cc28db893095de6ee56336847890bb46563bceac48fc5d8d1b66079bd76a71d5b90a97cbe34c6fdf7277c2aee5292e82d7f62407d019cc74be3b1865535414327686604c0bda663a375411ed8e89619e61c2d603ee3ef678eb602d4e3d5106dba466709c76a7e204c5557fbba126b7b56925c4927e01cbbe10d1".to_string(),
            c: "111e06873463cd8749a1bd8adc83d252fe79097089777668e40007accdb7cdb406de890a7d29c08a90ed207a140b0ad142f558754708b86c3ca61444143eb40d".to_string()
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
            a: "136119496feea080d3b191f8f872ee471642f5e9c3c55f3dfd38b5510d8c3ea3188944f0866a4ddb3ee0543a0b57b80ce5cfadbdbbaae1e3b8c70f7ac05718de".to_string(),
            b: "171e57bd50b3cc28db893095de6ee56336847890bb46563bceac48fc5d8d1b66079bd76a71d5b90a97cbe34c6fdf7277c2aee5292e82d7f62407d019cc74be3b1865535414327686604c0bda663a375411ed8e89619e61c2d603ee3ef678eb602d4e3d5106dba466709c76a7e204c5557fbba126b7b56925c4927e01cbbe10d1".to_string(),
            c: "111e06873463cd8749a1bd8adc83d252fe79097089777668e40007accdb7cdb406de890a7d29c08a90ed207a140b0ad142f558754708b86c3ca61444143eb40d".to_string()
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
                a: "1d357813049bc4b83ded0d9dab748251c70633d6283df4aef6c3c8f53da22942297e1f9820cdd8acd3719be1dc18c0d6d7d978b8022b10b2412c0be757d898cb".to_string(),
                b: "205d75e9165f8e472d935314381246d192e174262a19779afbb3fac8f9471b211b93759ce5a42fcb5c92a37b7013b9f9f72f13bd6d4190a7327d661b2a1530c205cc957a89cf5a4be26d822ea194bee53b59c8780f49e13968436a734c2e5de10f5fcf817e99122edce715d30bb63babbbdb7c541154c166ee2d9f42349957c8".to_string(),
                c: "15f91dba796a622d18dc73af0e50a5a7b2d9668f3cbd4015b4137b54c6743f5524080bdc6be18a94e8a3e638c684e4810465e065bb3c68d3c752e5fb8ea9ea65".to_string()
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
            a: "2274e1f6b71fc2887c4f746ff384f00fd9d2b4f8ed1d59853af2cb891058624a2e73d79f02de60ee49604e972e9dae72e5a3f3b63b7b0bb6167d1d7365f3af0b".to_string(),
            b: "147e97b696f2483f9be88419802de05a37c272328413907b1cadf61768e4abf604435ebd5462d1af60bee71de26d9a7259982f809f5edf3da7ecbb8c2b55dec40b403b2e4becd1587519488c8fcbf7e6b504dd68016e1ed48443ccced09d08c10a69014af748d7b2921449762eb7e870f0185dab186df6a5aeda4401e9a343cc".to_string(),
            c: "100005547853768af099c27f658c8b44d52bb94117a235243dfb243f3687395e2d3634cdce0cbe115d8d497e2330a907f965e4d9080183b381fb4ff30f98f02a".to_string()
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
    fn instantiate_with_voting_time_plonk_should_works() {
        let msg_file_path = "./src/test/plonk_test/msg.json";

        let mut msg_file = fs::File::open(msg_file_path).expect("Failed to open file");
        let mut msg_content = String::new();

        msg_file
            .read_to_string(&mut msg_content)
            .expect("Failed to read file");

        let data: MsgData = serde_json::from_str(&msg_content).expect("Failed to parse JSON");

        let result_file_path = "./src/test/plonk_test/result.json";
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
            .instantiate_with_voting_time_plonk(&mut app, owner(), user1(), user2(), label)
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
        let proof = PlonkProofType {
          num_inputs: 1,
          n: 1048575,
          input_values: [
            "20646b5086e2b137a8fdfdb065a74fa8a9dd345c5b722c27de787a608baacddb".to_string()
            ].to_vec(),
          wire_commitments: [
            "04310e42369497124e4adbcd8621fd5882d8ed1a5aa10600ee6b7b24692ef18d143a3519ac13f1b0b6a1e685198ed7a93e8c3b3ab710f1fca0615cfb7ff0b7f3".to_string(),
            "0a07e47878d7288e7cb38e9a43999f05d9c6425f7654db4a409a9d48f06c827518557af3bbcfc3e99a4331f16d5a70d48744006d8798f17ae37a39540ad262d9".to_string(),
            "1fa866a74fae21787cfaba4ca23324de623babcc3a4d7b9cb13d87123df58a35010abc7b4a0567a8a4c8fe8bc8b4a5e73ff5be08440f4cf963c7030672198271".to_string(),
            "07f58098c66ec72b54817f9c8c05b45b598b1ca2897038eea0ecec207145498f0bcb6d2479c9daf544b71332c96d2b9aadc8297f31db77d5c473a862842d423c".to_string()
            ].to_vec(),
          grand_product_commitment: "096052f40c68ab6d3fcf67df849b5d106f30c86cc63137285d4fe83fe48b174b1e92ace0364b95c72a42a02d94512e7d75797fc5ba03aaee179cd07f10555c4e".to_string(),
          quotient_poly_commitments: [
            "286ed7d6db7b2efd978cb4db3cd264386f2476fa3f9b074e08a5a4804adc44d50439333ab068eb6195d54b8d17803b5443d6ae872b3a747bea54be7c9c2766e2".to_string(),
            "045354bb00099110c12563190d0e470bcbf2f86466053878b2039d0a5e165c9819210278fe2a590d034188310ecdc5185c46d5f29233d7a46a0b97d75b19e0a4".to_string(),
            "0c738046211faf2ea3f8089dbe48cb0134fa7dd88e8a156965ce553bc4ccee1e15aeb972f3566a14598fd6053323d31904cc2078b3d856754b5a02b14d63cf53".to_string(),
            "0463d3b0993c4885b143e818d8a300aebbf28d7bcec58c3788883a98d75a801d2f06c31336c0b8d76183340712e99b7d5fd768b4f694636162e5e988689451c6".to_string()
            ].to_vec(),
          wire_values_at_z: [
            "09f58a6d7744ec3fa823f03e557102d88a70b6b5b2fc4025b40c9ef2ab547a05".to_string(),
            "0d616b48d85db1014e064e5a25f5b3dbaeabbe20752a06135dc3a5b61518bb16".to_string(),
            "1405672507d47f4a8909ad20c54bf645b9cb452d74fdd3207845712a9b63892d".to_string(),
            "1bebfcffb35ade66030ce9c57b09365ffe4a4c7165d8337f212eeee4a7940025".to_string()
            ].to_vec(),
          wire_values_at_z_omega: [
            "2a8570d5337de231432df065fdf4f068c32b63a4a8b56b0896571b6a818d1411".to_string()
            ].to_vec(),
          grand_product_at_z_omega: "076228edb4909945ace4447f3053053c4c082d9babaa556c58ddcb3d18f13b48".to_string(),
          quotient_polynomial_at_z: "22a01cdbdba002c175a6bbe3b4009758a7276586df7508e904df5126caba7de5".to_string(),
          linearization_polynomial_at_z: "0a26ef82d63272742283487c1acf119db88c3a8bda480a42b85c90489497a1e4".to_string(),
          permutation_polynomials_at_z: [
            "0845beb37695ac74c1d08abbe50d239209d1a7fffd86c57dae279e22d103ea8b".to_string(),
            "21f74916f6af9df945842e606e53f1419b2b349d8c782ddd1bd174469f2f122d".to_string(),
            "1b34eb3c18d0812703c43f02dc98c853309f237159db6704e184abb6cde0781b".to_string()
            ].to_vec(),
          opening_at_z_proof: "07466cda6ee15e852e5bc5a63bcc6769e06d778b8de03a7742e42a5014b005a111dd7749021981352768d7fdfd51e60acb8ca588972d516460c556c04dfe1a32".to_string(),
          opening_at_z_omega_proof: "13edbdb1243281190765a121538c6566796b34da989d4230ea3d92423409067b09cbe32b7c58c96ed4afa5ea37355008f8513e8ed81100d94a4a97040a0944f5".to_string()
        };
        println!("process_message proof {:?}", proof);
        println!(
            "process_message new state commitment {:?}",
            new_state_commitment
        );
        let _ = contract
            .process_message_plonk(&mut app, owner(), new_state_commitment, proof)
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
        let tally_path = "./src/test/plonk_test/tally.json";
        let mut tally_file = fs::File::open(tally_path).expect("Failed to open file");
        let mut tally_content = String::new();
        tally_file
            .read_to_string(&mut tally_content)
            .expect("Failed to read file");

        let tally_data: TallyData =
            serde_json::from_str(&tally_content).expect("Failed to parse JSON");

        let new_tally_commitment = uint256_from_decimal_string(&tally_data.new_tally_commitment);

        let tally_proof = PlonkProofType {
          num_inputs: 1,
          n: 524287,
          input_values: [
            "124e6b43c44d47da13bc08efa1e5bf9be596c027dd5372c6245eb1a553c06b71".to_string()
            ].to_vec(),
          wire_commitments: [
            "0052b5cf94ee167de28f06b1f049dd72cc35fea3bbe55bdcb2a2ec33ac959d472bb51db7af1713353e3af2feeb58ed62b8f1eb2af2d9da49a13a9e7f96d85581".to_string(),
            "257c5114adda24074052bcec979a8461c6bec4084a8b1b8380362a0ab2e982872ba88aaf7c25d5425dcf9bac945a809021e7b648bf44eef97f18e8056220f1e8".to_string(),
            "0b5b82ae9ac71b01cd6f4905180f09e8e01757422d9ebee04d738e980876f51b2b2cf656904e0f82d1f68c027a4213baa766fdab692c06379cda69b7d5eb9b2f".to_string(),
            "1be762c866c2e88a37ea3617ff9515e011fb0d3bdc3f682554c0ad454211fb0e05848e67e07f7d94c83b44e22be380c2f4b11f687af9f497d2ea4930977637bd".to_string()
            ].to_vec(),
          grand_product_commitment: "12a87d074aa1fe8d5acb42cfa787a0665d27c71fd794ebd2788f3af845fc88bc229a873e99e91ade37d90e7dc14134f011d17223897b19456ccaedeb3a6cbe8f".to_string(),
          quotient_poly_commitments: [
            "238cdecb0aacad7450fbe847c58a06012f795e6c9532198c0366270b9e3846aa2674adb67918b88330c5fb39294ca98b5bac501ba4d840b3d1db2e6b3f0f7d72".to_string(),
            "06239d69bd9d546a95df85191a507d4de0bd5a5573734690869185650f1a788303a6a715aa29f8fdccc310f0da510edfe0e0951e3fbcdc38f311b11ffff041dc".to_string(),
            "0fd4f07f25d4cfd48bb2a7db1c3cf76829036d4d41d519d66e07277872cd00df27eed27fbf9ed75317ba1faa67b97d2d861be6ee9eac25f7ab3779d1c076ac30".to_string(),
            "0eaaec5fc83d2df65b1472a5597e46d0a4b6b5a4e63d50ce43708a5e912c4cb814506706b4241f34f11c80daf56fb9b91da9a3ffd32470df2fe0b950371af14d".to_string()
            ].to_vec(),
          wire_values_at_z: [
            "15aaaaf6e3912f25f4439c4435508aef7ced5b01a234b4b3ec915ce39fd75adb".to_string(),
            "0195827e3e4529a7947fe3db6a556c5dd0b83273d7910784948d8d32bf5ed777".to_string(),
            "13ce28e4440e428d1a8e4926fec817f34c7ad0dd54ae7bd8f8f1fdcdcf211fd9".to_string(),
            "270025af4aed28c8229e7bfbc335a210d151fa0dbaeb4a9f3bf75a751ac2fa13".to_string()
            ].to_vec(),
          wire_values_at_z_omega: [
            "27153fc6e78fdbb1290dfc9f75dc3dc2d6d04bbe9a18e2d52736207b3175f121".to_string()
            ].to_vec(),
          grand_product_at_z_omega: "1b993d9a0dd7086e1379194bf3a41a7d6172d112f607ed41a8a78f959b362487".to_string(),
          quotient_polynomial_at_z: "2946fc838c33afc1ff4e640102147e9f6576d11a4a700687632a223de4ba336e".to_string(),
          linearization_polynomial_at_z: "0e25b0ec183581f3f4a1602f81e9f50e9b39e180150e0a43340873b4d38638de".to_string(),
          permutation_polynomials_at_z: [
            "046931d0c549d9055bd675eaf7fbf5395a020fa8c7a4aa0a7d9dfc936eb9f63a".to_string(),
            "16e51ec87c6b0c65cd4f39ca679ecb86a2b35d883cbb551bee98b3b17a438324".to_string(),
            "18a7b4995f1b0639a9993d3fc1fe146db3fa317b0b82320f1d9099e44b9e6df2".to_string()
            ].to_vec(),
          opening_at_z_proof: "19e4ddc7a45e67547ee8e23a0813786589c1386fdc3cec3a06e24c7bdacb83c700590162aa030b3043b2a1dfd8ff40bb1be74c528df0bba4cfc700ddd55b7fc6".to_string(),
          opening_at_z_omega_proof: "0b7b5f1f7a1bad8e2de0798b783be1ca0bda364b11ad05691fdaf77f884e4e4c223e9ad1c59eccddd3281e0eaada926ecefff3754920dc8bdff8dab6fe4d993d".to_string()
        };

        _ = contract
            .process_tally_plonk(&mut app, owner(), new_tally_commitment, tally_proof)
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
