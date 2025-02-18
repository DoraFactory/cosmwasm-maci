use crate::groth16_parser::parse_groth16_vkey;

use crate::ContractError;
use crate::{msg::Groth16VKeyType, state::Groth16VkeyStr};
use pairing_ce::bn256::Bn256;

pub struct VkeyParams {
    pub process_vkey: Groth16VkeyStr,
    pub tally_vkey: Groth16VkeyStr,
}

pub fn format_vkey(groth16_vkey: &Groth16VKeyType) -> Result<Groth16VkeyStr, ContractError> {
    // Create a process_vkeys struct from the process_vkey in the message
    let groth16_vkey_formatted = Groth16VkeyStr {
        alpha_1: hex::decode(&groth16_vkey.vk_alpha1)
            .map_err(|_| ContractError::HexDecodingError {})?,
        beta_2: hex::decode(&groth16_vkey.vk_beta_2)
            .map_err(|_| ContractError::HexDecodingError {})?,
        gamma_2: hex::decode(&groth16_vkey.vk_gamma_2)
            .map_err(|_| ContractError::HexDecodingError {})?,
        delta_2: hex::decode(&groth16_vkey.vk_delta_2)
            .map_err(|_| ContractError::HexDecodingError {})?,
        ic0: hex::decode(&groth16_vkey.vk_ic0).map_err(|_| ContractError::HexDecodingError {})?,
        ic1: hex::decode(&groth16_vkey.vk_ic1).map_err(|_| ContractError::HexDecodingError {})?,
    };
    parse_groth16_vkey::<Bn256>(groth16_vkey_formatted.clone())
        .map_err(|_| ContractError::InvalidVKeyError {})?;

    Ok(groth16_vkey_formatted)
}

pub fn match_vkeys() -> Result<VkeyParams, ContractError> {
    // 1p1v_qv key
    let groth16_process_vkey = Groth16VKeyType {
        vk_alpha1: "2d4d9aa7e302d9df41749d5507949d05dbea33fbb16c643b22f599a2be6df2e214bedd503c37ceb061d8ec60209fe345ce89830a19230301f076caff004d1926".to_string(),
        vk_beta_2: "0967032fcbf776d1afc985f88877f182d38480a653f2decaa9794cbc3bf3060c0e187847ad4c798374d0d6732bf501847dd68bc0e071241e0213bc7fc13db7ab304cfbd1e08a704a99f5e847d93f8c3caafddec46b7a0d379da69a4d112346a71739c1b1a457a8c7313123d24d2f9192f896b7c63eea05a9d57f06547ad0cec8".to_string(),
        vk_gamma_2: "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa".to_string(),
        vk_delta_2: "057f25675851ef5a79a6d8706a43a6cd8e494cfb12c241ede46991d9174cf30605b081ff44f3ede774dab68ea9324c12308c13cb09cbb129adf94401b9134f5b16137d952fd32ab2d4243ebff4cb15d17206948ef17909ea8606886a8109bdad082f7d27e1cbf98925f055b39d1c89f9bcc4f6d92fdb920934ff5e37ba4d9b49".to_string(),
        vk_ic0: "27c937c032a18a320566e934448a0ffceea7050492a509c45a3bcb7e8ff8905d20789ada31729a833a4f595ff9f49f88adb66f2ab987de15a15deccb0e785bf4".to_string(),
        vk_ic1: "0ed2cefc103a2234dbc6bbd8634812d65332218b7589f4079b2c08eb5a4f5f63113a7f3cb53797a7f5819d7de7e3f0b2197d1c34790685a4a59af4314810420b".to_string(),
    };

    let groth16_process_vkeys = format_vkey(&groth16_process_vkey)?;
    // Create a tally_vkeys struct from the tally_vkey in the message
    let groth16_tally_vkey = Groth16VKeyType {
        vk_alpha1:
			"2d4d9aa7e302d9df41749d5507949d05dbea33fbb16c643b22f599a2be6df2e214bedd503c37ceb061d8ec60209fe345ce89830a19230301f076caff004d1926".to_string(),
		vk_beta_2:
			"0967032fcbf776d1afc985f88877f182d38480a653f2decaa9794cbc3bf3060c0e187847ad4c798374d0d6732bf501847dd68bc0e071241e0213bc7fc13db7ab304cfbd1e08a704a99f5e847d93f8c3caafddec46b7a0d379da69a4d112346a71739c1b1a457a8c7313123d24d2f9192f896b7c63eea05a9d57f06547ad0cec8".to_string(),
		vk_gamma_2:
			"198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa".to_string(),
		vk_delta_2:
			"2065e91c00fcc5cbc3d974cf52e24de972bdb1b4d8ded629dec20b5c904c3fa327ffe02402094795ff4d02588c8268fcad738f69eb4c732a0c98b485035e1f4913ede11b074ff143a929673e581a547717c58ce01af87d9d8b28f65f506093a61013e367b93e6782129362065840a0af9b77d7d9659a84577176e64a918d8d4c".to_string(),
		vk_ic0: "11db4a022aab89a265f06ff62aa18c74b21e913a8b23e7fce9cb46f76d1c4d9f2a7475b1eeb7be0a0dc457e6d52536ba351b621b63a7d77da75d4e773048537e".to_string(),
		vk_ic1: "0f298d235d0822ad281386abdf511853529af4c864b0cd54140facebfc1356a3059cd6d0d4b27b39e5683548fe12025e2a6b2e2724c2ca87d2008ef932ed3801".to_string(),
    };
    let groth16_tally_vkeys = format_vkey(&groth16_tally_vkey)?;

    let vkeys = VkeyParams {
        process_vkey: groth16_process_vkeys,
        tally_vkey: groth16_tally_vkeys,
    };
    return Ok(vkeys);
}
