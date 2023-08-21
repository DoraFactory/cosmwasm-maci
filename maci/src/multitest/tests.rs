#[cfg(test)]
mod test {
    use cosmwasm_std::{Addr, Uint256};
    use cw_multi_test::App;

    use crate::msg::ProofType;
    use crate::multitest::{owner, uint256_from_decimal_string, user1, user2, MaciCodeId};
    use crate::state::{Message, PubKey};
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

    #[test]
    fn instantiate_should_works() {
        let mut app = App::default();
        let code_id = MaciCodeId::store_code(&mut app);
        let label = "Group";
        let contract = code_id
            .instantiate(&mut app, owner(), user1(), user2(), label)
            .unwrap();

        // check winner
        let num_sign_up = contract.num_sign_up(&app).unwrap();
        assert_eq!(num_sign_up, Uint256::from_u128(0u128));

        let msg_file_path = "./src/test/msg_test.json";

        let mut msg_file = fs::File::open(msg_file_path).expect("Failed to open file");
        let mut msg_content = String::new();

        msg_file
            .read_to_string(&mut msg_content)
            .expect("Failed to read file");

        let data: MsgData = serde_json::from_str(&msg_content).expect("Failed to parse JSON");

        let mut msgs = vec![];
        let mut encpubs = vec![];
        for i in 0..data.msgs.len() {
            if i < Uint256::from_u128(2u128).to_string().parse().unwrap() {
                let pubkey = PubKey {
                    x: uint256_from_decimal_string(&data.current_state_leaves[i][0]),
                    y: uint256_from_decimal_string(&data.current_state_leaves[i][1]),
                };

                println!("---------- signup ---------- {:?}", i);
                let _ = contract.sign_up(&mut app, Addr::unchecked(i.to_string()), pubkey);
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
            msgs.push(message);
            encpubs.push(enc_pub);
        }
        println!("------ batch publish message ------");
        println!("messages: {:?}", msgs.clone());
        println!("encpubs: {:?}", encpubs.clone());
        _ = contract.batch_publish_message(&mut app, user2(), msgs, encpubs);
        println!("-------------batch publish end-----------------------");

        assert_eq!(
            contract.num_sign_up(&app).unwrap(),
            Uint256::from_u128(2u128)
        );

        assert_eq!(
            contract.msg_length(&app).unwrap(),
            Uint256::from_u128(3u128)
        );

        _ = contract.stop_voting(&mut app, owner());
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
                a: "0bae3bc2485c2cd6a3bfdf16e7d8a5b93710c3bdcf9410d725aae938ccbebca12b1021be36b6c1d96db410d52369a0e51249da0a1b41497af53bb227ae1e674e".to_string(),
                b: "1ff4ed89d5aefdca176419a76a82d2359f334d9bc479daa6ca11201076745749220fc921f3e77889779969467456beec42cdb5c874e3961a7a0f29b75899417929d1f4d3bb2ca8cfa15b1a1c893f0daa9304131f7512841174b2d2deeb30462e2f8eed8ab95da0c502c740216f89553f1b37ee2d34110c04363a34093337044b".to_string(),
                c: "0c054469563868b8878f72628cb3db437137e3d39fa8b74e344e573fedef8fcb1794cd30a661746438034f71e49349ac16357ebd8c1afc8be7585f4aa5366534".to_string()
            };

        _ = contract.process_tally(&mut app, owner(), new_tally_commitment, tally_proof);

        let results: Vec<Uint256> = tally_data
            .current_results
            .iter()
            .map(|input| uint256_from_decimal_string(input))
            .collect();

        let salt = uint256_from_decimal_string(&tally_data.new_results_root_salt);
        _ = contract.stop_tallying(&mut app, owner(), results, salt);
    }
}