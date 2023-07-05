use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, ProofType, QueryMsg};
use crate::parser::{parse_proof, parse_vkey};
use crate::state::{
    Admin, Config, Message, Period, PeriodStatus, ProofStr, PubKey, StateLeaf, VkeyStr, ADMIN,
    CONFIG, COORDINATORHASH, CURRENT_STATE_COMMITMENT, CURRENT_TALLY_COMMITMENT, LEAF_IDX_0,
    MACIPARAMETERS, MAX_LEAVES_COUNT, MAX_VOTE_OPTIONS, MSG_CHAIN_LENGTH, MSG_HASHES, NODES,
    NUMSIGNUPS, PERIOD, PROCESSED_MSG_COUNT, PROCESSED_USER_COUNT, PROCESS_VKEYS, QTR_LIB, RESULT,
    STATEIDXINC, TALLY_VKEYS, TOTAL_RESULT, VOICECREDITBALANCE, ZEROS,
};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, Uint128, Uint256,
};

use crate::utils::{hash2, hash5, hash_256_uint256_list, uint256_from_hex_string};

use bellman_ce_verifier::{prepare_verifying_key, verify_proof};
use ff_ce::PrimeField as Fr;
use pairing_ce::bn256::Bn256;

use hex;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    // Create an admin with the sender address
    let admin = Admin { admin: info.sender };
    ADMIN.save(deps.storage, &admin)?;

    // Save the MACI parameters to storage
    MACIPARAMETERS.save(deps.storage, &msg.parameters)?;

    // Create a config struct with the maci_denom value from the message
    let config = Config {
        maci_denom: msg.maci_denom,
    };

    CONFIG.save(deps.storage, &config)?;

    // Save the qtr_lib value to storage
    QTR_LIB.save(deps.storage, &msg.qtr_lib)?;

    // Create a process_vkeys struct from the process_vkey in the message
    let process_vkeys = VkeyStr {
        alpha_1: hex::decode(msg.process_vkey.vk_alpha1)
            .map_err(|_| ContractError::HexDecodingError {})?,
        beta_2: hex::decode(msg.process_vkey.vk_beta_2)
            .map_err(|_| ContractError::HexDecodingError {})?,
        gamma_2: hex::decode(msg.process_vkey.vk_gamma_2)
            .map_err(|_| ContractError::HexDecodingError {})?,
        delta_2: hex::decode(msg.process_vkey.vk_delta_2)
            .map_err(|_| ContractError::HexDecodingError {})?,
        ic0: hex::decode(msg.process_vkey.vk_ic0)
            .map_err(|_| ContractError::HexDecodingError {})?,
        ic1: hex::decode(msg.process_vkey.vk_ic1)
            .map_err(|_| ContractError::HexDecodingError {})?,
    };
    let _ = parse_vkey::<Bn256>(process_vkeys.clone())?;
    PROCESS_VKEYS.save(deps.storage, &process_vkeys)?;

    // Create a tally_vkeys struct from the tally_vkey in the message
    let tally_vkeys = VkeyStr {
        alpha_1: hex::decode(msg.tally_vkey.vk_alpha1)
            .map_err(|_| ContractError::HexDecodingError {})?,
        beta_2: hex::decode(msg.tally_vkey.vk_beta_2)
            .map_err(|_| ContractError::HexDecodingError {})?,
        gamma_2: hex::decode(msg.tally_vkey.vk_gamma_2)
            .map_err(|_| ContractError::HexDecodingError {})?,
        delta_2: hex::decode(msg.tally_vkey.vk_delta_2)
            .map_err(|_| ContractError::HexDecodingError {})?,
        ic0: hex::decode(msg.tally_vkey.vk_ic0).map_err(|_| ContractError::HexDecodingError {})?,
        ic1: hex::decode(msg.tally_vkey.vk_ic1).map_err(|_| ContractError::HexDecodingError {})?,
    };
    let _ = parse_vkey::<Bn256>(tally_vkeys.clone())?;
    TALLY_VKEYS.save(deps.storage, &tally_vkeys)?;

    // Compute the coordinator hash from the coordinator values in the message
    let coordinator_hash = hash2([msg.coordinator.x, msg.coordinator.y]);
    COORDINATORHASH.save(deps.storage, &coordinator_hash)?;

    // Compute the maximum number of leaves based on the state tree depth
    let max_leaves_count =
        Uint256::from_u128(5u128.pow(msg.parameters.state_tree_depth.to_string().parse().unwrap()));
    MAX_LEAVES_COUNT.save(deps.storage, &max_leaves_count)?;

    // Calculate the index of the first leaf in the tree
    let leaf_idx0 = (max_leaves_count - Uint256::from_u128(1u128)) / Uint256::from_u128(4u128);
    LEAF_IDX_0.save(deps.storage, &leaf_idx0)?;

    // Define an array of zero values
    let zeros: [Uint256; 8] = [
        uint256_from_hex_string("2066be41bebe6caf7e079360abe14fbf9118c62eabc42e2fe75e342b160a95bc"),
        uint256_from_hex_string("2a956d37d8e73692877b104630a08cc6840036f235f2134b0606769a369d85c1"),
        uint256_from_hex_string("2f9791ba036a4148ff026c074e713a4824415530dec0f0b16c5115aa00e4b825"),
        uint256_from_hex_string("2c41a7294c7ef5c9c5950dc627c55a00adb6712548bcbd6cd8569b1f2e5acc2a"),
        uint256_from_hex_string("2594ba68eb0f314eabbeea1d847374cc2be7965944dec513746606a1f2fadf2e"),
        uint256_from_hex_string("5c697158c9032bfd7041223a7dba696396388129118ae8f867266eb64fe7636"),
        uint256_from_hex_string("272b3425fcc3b2c45015559b9941fde27527aab5226045bf9b0a6c1fe902d601"),
        uint256_from_hex_string("268d82cc07023a1d5e7c987cbd0328b34762c9ea21369bea418f08b71b16846a"),
        // uint256_from_decimal_string(
        //     "14655542659562014735865511769057053982292279840403315552050801315682099828156",
        // ),
        // uint256_from_decimal_string(
        //     "19261153649140605024552417994922546473530072875902678653210025980873274131905",
        // ),
        // uint256_from_decimal_string(
        //     "21526503558325068664033192388586640128492121680588893182274749683522508994597",
        // ),
        // uint256_from_decimal_string(
        //     "20017764101928005973906869479218555869286328459998999367935018992260318153770",
        // ),
        // uint256_from_decimal_string(
        //     "16998355316577652097112514691750893516081130026395813155204269482715045879598",
        // ),
        // uint256_from_decimal_string(
        //     "2612442706402737973181840577010736087708621987282725873936541279764292204086",
        // ),
        // uint256_from_decimal_string(
        //     "17716535433480122581515618850811568065658392066947958324371350481921422579201",
        // ),
        // uint256_from_decimal_string(
        //     "17437916409890180001398333108882255895598851862997171508841759030332444017770",
        // ),
    ];
    ZEROS.save(deps.storage, &zeros)?;

    // Save initial values for message hash, message chain length, processed message count, current tally commitment,
    // processed user count, and number of signups to storage
    MSG_HASHES.save(
        deps.storage,
        Uint256::from_u128(0u128).to_be_bytes().to_vec(),
        &Uint256::from_u128(0u128),
    )?;
    MSG_CHAIN_LENGTH.save(deps.storage, &Uint256::from_u128(0u128))?;
    PROCESSED_MSG_COUNT.save(deps.storage, &Uint256::from_u128(0u128))?;
    CURRENT_TALLY_COMMITMENT.save(deps.storage, &Uint256::from_u128(0u128))?;
    PROCESSED_USER_COUNT.save(deps.storage, &Uint256::from_u128(0u128))?;
    NUMSIGNUPS.save(deps.storage, &Uint256::from_u128(0u128))?;

    // Create a period struct with the initial status set to Voting
    let period = Period {
        status: PeriodStatus::Voting,
    };

    // Save the initial period to storage
    PERIOD.save(deps.storage, &period)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::SetParams {
            state_tree_depth,
            int_state_tree_depth,
            message_batch_size,
            vote_option_tree_depth,
        } => execute_set_parameters(
            deps,
            env,
            info,
            state_tree_depth,
            int_state_tree_depth,
            message_batch_size,
            vote_option_tree_depth,
        ),
        ExecuteMsg::SignUp { pubkey } => execute_sign_up(deps, env, info, pubkey),
        ExecuteMsg::StopVotingPeriod { max_vote_options } => {
            execute_stop_voting_period(deps, env, info, max_vote_options)
        }
        ExecuteMsg::PublishMessage {
            message,
            enc_pub_key,
        } => execute_publish_message(deps, env, info, message, enc_pub_key),
        ExecuteMsg::ProcessMessage {
            new_state_commitment,
            proof,
        } => execute_process_message(deps, env, info, new_state_commitment, proof),
        ExecuteMsg::StopProcessingPeriod {} => execute_stop_processing_period(deps, env, info),
        ExecuteMsg::ProcessTally {
            new_tally_commitment,
            proof,
        } => execute_process_tally(deps, env, info, new_tally_commitment, proof),
        ExecuteMsg::StopTallyingPeriod { results, salt } => {
            execute_stop_tallying_period(deps, env, info, results, salt)
        }
    }
}

pub fn execute_set_parameters(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    state_tree_depth: Uint256,
    int_state_tree_depth: Uint256,
    message_batch_size: Uint256,
    vote_option_tree_depth: Uint256,
) -> Result<Response, ContractError> {
    if !can_execute(deps.as_ref(), info.sender.as_ref())? {
        Err(ContractError::Unauthorized {})
    } else {
        let mut cfg = MACIPARAMETERS.load(deps.storage)?;
        cfg.state_tree_depth = state_tree_depth;
        cfg.int_state_tree_depth = int_state_tree_depth;
        cfg.message_batch_size = message_batch_size;
        cfg.vote_option_tree_depth = vote_option_tree_depth;

        MACIPARAMETERS.save(deps.storage, &cfg)?;
        let res = Response::new().add_attribute("action", "set_parameters");
        Ok(res)
    }
}

pub fn execute_sign_up(
    mut deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    pubkey: PubKey,
) -> Result<Response, ContractError> {
    let period = PERIOD.load(deps.storage)?;
    // Check if the period status is Voting
    if period.status != PeriodStatus::Voting {
        return Err(ContractError::PeriodError {});
    }

    let mut num_sign_ups = NUMSIGNUPS.load(deps.storage)?;

    let max_leaves_count = MAX_LEAVES_COUNT.load(deps.storage)?;

    // // Load the scalar field value
    let snark_scalar_field =
        uint256_from_hex_string("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
    // let snark_scalar_field = uint256_from_decimal_string(
    // "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    // );

    // Check if the number of sign-ups is less than the maximum number of leaves
    assert!(num_sign_ups < max_leaves_count, "full");
    // Check if the pubkey values are within the allowed range
    assert!(
        pubkey.x < snark_scalar_field && pubkey.y < snark_scalar_field,
        "MACI: pubkey values should be less than the snark scalar field"
    );

    let config = CONFIG.load(deps.storage)?;

    let mut amount: Uint128 = Uint128::new(0);

    // Iterate through the funds and find the amount with the MACI denomination
    info.funds.iter().for_each(|fund| {
        if fund.denom == config.maci_denom {
            amount = fund.amount;
        }
    });

    // Create a state leaf with the provided pubkey and amount
    let state_leaf = StateLeaf {
        pub_key: pubkey,
        // voice_credit_balance: uint256_from_decimal_string(&amount.to_string()),
        voice_credit_balance: Uint256::from_uint128(amount),
        vote_option_tree_root: Uint256::from_u128(0),
        nonce: Uint256::from_u128(0),
    }
    .hash_state_leaf();

    let state_index = num_sign_ups;

    // Enqueue the state leaf
    state_enqueue(&mut deps, state_leaf)?;

    num_sign_ups += Uint256::from_u128(1u128);

    // Save the updated state index, voice credit balance, and number of sign-ups
    STATEIDXINC.save(deps.storage, &info.sender, &num_sign_ups)?;
    VOICECREDITBALANCE.save(
        deps.storage,
        state_index.to_be_bytes().to_vec(),
        &Uint256::from_u128(0u128),
    )?;
    NUMSIGNUPS.save(deps.storage, &num_sign_ups)?;

    Ok(Response::new()
        .add_attribute("action", "sign_up")
        .add_attribute("state_idx", state_index.to_string()))
}

pub fn execute_publish_message(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    message: Message,
    enc_pub_key: PubKey,
) -> Result<Response, ContractError> {
    let period = PERIOD.load(deps.storage)?;
    // Check if the period status is Voting
    if period.status != PeriodStatus::Voting {
        return Err(ContractError::PeriodError {});
    }

    // Load the scalar field value
    let snark_scalar_field =
        uint256_from_hex_string("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");

    // let snark_scalar_field = uint256_from_decimal_string(
    //     "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    // );

    // Check if the encrypted public key is valid
    if enc_pub_key.x != Uint256::from_u128(0u128)
        && enc_pub_key.y != Uint256::from_u128(1u128)
        && enc_pub_key.x < snark_scalar_field
        && enc_pub_key.y < snark_scalar_field
    {
        let mut msg_chain_length = MSG_CHAIN_LENGTH.load(deps.storage)?;
        let old_msg_hashes =
            MSG_HASHES.load(deps.storage, msg_chain_length.to_be_bytes().to_vec())?;

        // Compute the new message hash using the provided message, encrypted public key, and previous hash
        MSG_HASHES.save(
            deps.storage,
            (msg_chain_length + Uint256::from_u128(1u128))
                .to_be_bytes()
                .to_vec(),
            &hash_message_and_enc_pub_key(message, enc_pub_key, old_msg_hashes),
        )?;

        // Update the message chain length
        msg_chain_length += Uint256::from_u128(1u128);
        MSG_CHAIN_LENGTH.save(deps.storage, &msg_chain_length)?;

        // Return a success response
        Ok(Response::new()
            .add_attribute("action", "publish_message")
            .add_attribute("event", "success publish message"))
    } else {
        // Return an error response for invalid user or encrypted public key
        Ok(Response::new()
            .add_attribute("action", "publish_message")
            .add_attribute("event", "error user."))
    }
}

pub fn execute_stop_voting_period(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    max_vote_options: Uint256,
) -> Result<Response, ContractError> {
    let period = PERIOD.load(deps.storage)?;
    // Check if the period status is Voting
    if period.status != PeriodStatus::Voting {
        return Err(ContractError::PeriodError {});
    }

    // Check if the sender is authorized to execute the function
    if !can_execute(deps.as_ref(), info.sender.as_ref())? {
        Err(ContractError::Unauthorized {})
    } else {
        // Save the maximum vote options
        MAX_VOTE_OPTIONS.save(deps.storage, &max_vote_options)?;

        // Update the period status to Processing
        let period = Period {
            status: PeriodStatus::Processing,
        };
        PERIOD.save(deps.storage, &period)?;

        // Compute the state root
        let state_root = state_root(deps.as_ref());

        // Compute the current state commitment as the hash of the state root and 0
        CURRENT_STATE_COMMITMENT.save(
            deps.storage,
            &hash2([state_root, Uint256::from_u128(0u128)]),
        )?;

        // Return a success response
        Ok(Response::new().add_attribute("action", "stop_voting_period"))
    }
}

pub fn execute_process_message(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    new_state_commitment: Uint256,
    proof: ProofType,
) -> Result<Response, ContractError> {
    let period = PERIOD.load(deps.storage)?;
    // Check if the period status is Processing
    if period.status != PeriodStatus::Processing {
        return Err(ContractError::PeriodError {});
    }

    let mut processed_msg_count = PROCESSED_MSG_COUNT.load(deps.storage)?;
    let msg_chain_length = MSG_CHAIN_LENGTH.load(deps.storage)?;
    // Check that all messages have not been processed yet
    assert!(
        processed_msg_count < msg_chain_length,
        "all messages have been processed"
    );

    // Create an array to store the input values for the SNARK proof
    let mut input: [Uint256; 6] = [Uint256::zero(); 6];

    let num_sign_ups = NUMSIGNUPS.load(deps.storage)?;
    let max_vote_options = MAX_VOTE_OPTIONS.load(deps.storage)?;
    input[0] = (num_sign_ups << 32) + max_vote_options; // packedVals

    // Load the coordinator's public key hash
    let coordinator_hash = COORDINATORHASH.load(deps.storage)?;
    input[1] = coordinator_hash; // coordPubKeyHash

    // Load the MACI parameters
    let parameters = MACIPARAMETERS.load(deps.storage)?;
    let batch_size = parameters.message_batch_size;

    // Compute the start and end indices of the current batch
    let batch_start_index = (msg_chain_length - processed_msg_count - Uint256::from_u128(1u128))
        / batch_size
        * batch_size;
    let mut batch_end_index = batch_start_index.clone() + batch_size;
    if batch_end_index > msg_chain_length {
        batch_end_index = msg_chain_length;
    }

    // Load the hash of the message at the batch start index
    input[2] = MSG_HASHES.load(
        deps.storage,
        batch_start_index.clone().to_be_bytes().to_vec(),
    )?; // batchStartHash

    // Load the hash of the message at the batch end index
    input[3] = MSG_HASHES.load(deps.storage, batch_end_index.to_be_bytes().to_vec())?; // batchEndHash

    // Load the current state commitment
    let current_state_commitment = CURRENT_STATE_COMMITMENT.load(deps.storage)?;
    input[4] = current_state_commitment;

    // Set the new state commitment
    input[5] = new_state_commitment;

    // Load the scalar field value
    let snark_scalar_field =
        uint256_from_hex_string("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
    // let snark_scalar_field = uint256_from_decimal_string(
    //     "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    // );

    // Compute the hash of the input values
    let input_hash = uint256_from_hex_string(&hash_256_uint256_list(&input)) % snark_scalar_field; // input hash
    println!("input: {:?}", input);
    println!("input_hash: {:?}", input_hash);
    // Load the process verification keys
    let process_vkeys_str = PROCESS_VKEYS.load(deps.storage)?;

    // Parse the SNARK proof
    let proof_str = ProofStr {
        pi_a: hex::decode(proof.a).map_err(|_| ContractError::HexDecodingError {})?,
        pi_b: hex::decode(proof.b).map_err(|_| ContractError::HexDecodingError {})?,
        pi_c: hex::decode(proof.c).map_err(|_| ContractError::HexDecodingError {})?,
    };

    // Parse the verification key and prepare for verification
    let vkey = parse_vkey::<Bn256>(process_vkeys_str)?;
    let pvk = prepare_verifying_key(&vkey);

    // Parse the proof and prepare for verification
    let pof = parse_proof::<Bn256>(proof_str.clone())?;

    // Verify the SNARK proof using the input hash
    let is_passed = verify_proof(
        &pvk,
        &pof,
        &[Fr::from_str(&input_hash.to_string()).unwrap()],
    )
    .unwrap();

    // If the proof verification fails, return an error
    if !is_passed {
        return Err(ContractError::InvalidProof {
            step: String::from("Process"),
        });
    }

    // Proof verify success
    // Update the current state commitment
    CURRENT_STATE_COMMITMENT.save(deps.storage, &new_state_commitment)?;

    // Update the count of processed messages
    processed_msg_count += batch_end_index - batch_start_index;
    PROCESSED_MSG_COUNT.save(deps.storage, &processed_msg_count)?;

    Ok(Response::new().add_attribute("action", "process_message"))
}

pub fn execute_stop_processing_period(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
) -> Result<Response, ContractError> {
    let period = PERIOD.load(deps.storage)?;
    // Check if the period status is Processing
    if period.status != PeriodStatus::Processing {
        return Err(ContractError::PeriodError {});
    }

    // Check if the sender is authorized to execute the function
    if !can_execute(deps.as_ref(), info.sender.as_ref())? {
        Err(ContractError::Unauthorized {})
    } else {
        // Update the period status to Tallying
        let period = Period {
            status: PeriodStatus::Tallying,
        };
        PERIOD.save(deps.storage, &period)?;

        Ok(Response::new().add_attribute("action", "stop_processing_period"))
    }
}

pub fn execute_process_tally(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    new_tally_commitment: Uint256,
    proof: ProofType,
) -> Result<Response, ContractError> {
    let period = PERIOD.load(deps.storage)?;
    // Check if the period status is Tallying
    if period.status != PeriodStatus::Tallying {
        return Err(ContractError::PeriodError {});
    }

    let mut processed_user_count = PROCESSED_USER_COUNT.load(deps.storage)?;
    let num_sign_ups = NUMSIGNUPS.load(deps.storage)?;
    // Check that all users have not been processed yet
    assert!(
        processed_user_count.clone() < num_sign_ups.clone(),
        "all users have been processed"
    );

    let parameters = MACIPARAMETERS.load(deps.storage)?;
    // Calculate the batch size
    let batch_size =
        Uint256::from_u128(5u128).pow(parameters.int_state_tree_depth.to_string().parse().unwrap());
    // Calculate the batch number
    let batch_num = processed_user_count / batch_size;

    // Create an array to store the input values for the SNARK proof
    let mut input: [Uint256; 4] = [Uint256::zero(); 4];

    input[0] = (num_sign_ups << 32) + batch_num; // packedVals

    // Load the current state commitment and current tally commitment
    let current_state_commitment = CURRENT_STATE_COMMITMENT.load(deps.storage)?;
    let current_tally_commitment = CURRENT_TALLY_COMMITMENT.load(deps.storage)?;

    input[1] = current_state_commitment; // stateCommitment
    input[2] = current_tally_commitment; // tallyCommitment
    input[3] = new_tally_commitment; // newTallyCommitment

    // Load the scalar field value
    let snark_scalar_field =
        uint256_from_hex_string("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
    // let snark_scalar_field = uint256_from_decimal_string(
    //     "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    // );

    // Compute the hash of the input values
    let input_hash = uint256_from_hex_string(&hash_256_uint256_list(&input)) % snark_scalar_field;

    // Load the tally verification keys
    let tally_vkeys_str = TALLY_VKEYS.load(deps.storage)?;

    // Parse the SNARK proof
    let proof_str = ProofStr {
        pi_a: hex::decode(proof.a).map_err(|_| ContractError::HexDecodingError {})?,
        pi_b: hex::decode(proof.b).map_err(|_| ContractError::HexDecodingError {})?,
        pi_c: hex::decode(proof.c).map_err(|_| ContractError::HexDecodingError {})?,
    };

    // Parse the verification key and prepare for verification
    let vkey = parse_vkey::<Bn256>(tally_vkeys_str)?;
    let pvk = prepare_verifying_key(&vkey);

    // Parse the proof and prepare for verification
    let pof = parse_proof::<Bn256>(proof_str.clone())?;

    // Verify the SNARK proof using the input hash
    let is_passed = verify_proof(
        &pvk,
        &pof,
        &[Fr::from_str(&input_hash.to_string()).unwrap()],
    )
    .unwrap();

    // If the proof verification fails, return an error
    if !is_passed {
        return Err(ContractError::InvalidProof {
            step: String::from("Tally"),
        });
    }

    // Proof verify success
    // Update the current tally commitment
    CURRENT_TALLY_COMMITMENT
        .save(deps.storage, &new_tally_commitment)
        .unwrap();

    // Update the count of processed users
    processed_user_count += batch_size;
    PROCESSED_USER_COUNT
        .save(deps.storage, &processed_user_count)
        .unwrap();

    Ok(Response::new().add_attribute("action", "process_tally"))
}

fn execute_stop_tallying_period(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    results: Vec<Uint256>,
    salt: Uint256,
) -> Result<Response, ContractError> {
    let period = PERIOD.load(deps.storage)?;
    // Check if the period status is Tallying
    if period.status != PeriodStatus::Tallying {
        return Err(ContractError::PeriodError {});
    }

    let processed_user_count = PROCESSED_USER_COUNT.load(deps.storage)?;
    let num_sign_ups = NUMSIGNUPS.load(deps.storage)?;
    let max_vote_options = MAX_VOTE_OPTIONS.load(deps.storage)?;

    // Check that all users have been processed
    assert!(processed_user_count >= num_sign_ups);

    // Check that the number of results is not greater than the maximum vote options
    assert!(Uint256::from_u128(results.len() as u128) <= max_vote_options);

    // Load the QTR library and MACI parameters
    let qtr_lib = QTR_LIB.load(deps.storage)?;
    let parameters = MACIPARAMETERS.load(deps.storage)?;

    // Calculate the results root
    let results_root = qtr_lib.root_of(parameters.vote_option_tree_depth, results.clone());

    // Calculate the tally commitment
    let tally_commitment = hash2([results_root, salt]);

    // Load the current tally commitment
    let current_tally_commitment = CURRENT_TALLY_COMMITMENT.load(deps.storage)?;

    // Check that the tally commitment matches the current tally commitment
    assert_eq!(tally_commitment, current_tally_commitment);

    let mut sum = Uint256::zero();

    // Save the results and calculate the sum
    for i in 0..results.len() {
        RESULT.save(
            deps.storage,
            Uint256::from_u128(i as u128).to_be_bytes().to_vec(),
            &results[i],
        )?;
        sum += results[i];
    }

    // Save the total result
    TOTAL_RESULT.save(deps.storage, &sum)?;

    // Update the period status to Ended
    let period = Period {
        status: PeriodStatus::Ended,
    };
    PERIOD.save(deps.storage, &period)?;

    Ok(Response::new().add_attribute("action", "stop_tallying_period"))
}

// Load the root node of the state tree
fn state_root(deps: Deps) -> Uint256 {
    let root = NODES
        .load(
            deps.storage,
            Uint256::from_u128(0u128).to_be_bytes().to_vec(),
        )
        .unwrap();
    root
}

// Enqueues the state leaf into the tree
fn state_enqueue(deps: &mut DepsMut, leaf: Uint256) -> Result<bool, ContractError> {
    let leaf_idx0 = LEAF_IDX_0.load(deps.storage).unwrap();
    let num_sign_ups = NUMSIGNUPS.load(deps.storage).unwrap();

    let leaf_idx = leaf_idx0 + num_sign_ups;
    NODES.save(deps.storage, leaf_idx.to_be_bytes().to_vec(), &leaf)?;
    state_update_at(deps, leaf_idx)
}

// Updates the state at the given index in the tree
fn state_update_at(deps: &mut DepsMut, index: Uint256) -> Result<bool, ContractError> {
    let leaf_idx0 = LEAF_IDX_0.load(deps.storage).unwrap();
    if index < leaf_idx0 {
        return Err(ContractError::MustUpdate {});
    }

    let mut idx = index.clone();

    let mut height = 0;

    let zeros = ZEROS.load(deps.storage).unwrap();

    while idx > Uint256::from_u128(0u128) {
        let parent_idx = (idx - Uint256::one()) / Uint256::from(5u8);
        let children_idx0 = parent_idx * Uint256::from(5u8) + Uint256::one();

        let zero = zeros[height];

        let mut inputs: [Uint256; 5] = [Uint256::zero(); 5];

        for i in 0..5 {
            let node_value = NODES
                .may_load(
                    deps.storage,
                    (children_idx0 + Uint256::from_u128(i as u128))
                        .to_be_bytes()
                        .to_vec(),
                )
                .unwrap();

            let child = match node_value {
                Some(value) => value,
                None => zero,
            };

            inputs[i] = child;
        }

        if NODES.has(deps.storage, parent_idx.to_be_bytes().to_vec()) {
            NODES
                .update(
                    deps.storage,
                    parent_idx.to_be_bytes().to_vec(),
                    |_c: Option<Uint256>| -> StdResult<_> { Ok(hash5(inputs)) },
                )
                .unwrap();
        } else {
            NODES
                .save(
                    deps.storage,
                    parent_idx.to_be_bytes().to_vec(),
                    &hash5(inputs),
                )
                .unwrap();
        }

        height += 1;
        idx = parent_idx;
    }

    Ok(true)
}

pub fn hash_message_and_enc_pub_key(
    message: Message,
    enc_pub_key: PubKey,
    prev_hash: Uint256,
) -> Uint256 {
    let mut m: [Uint256; 5] = [Uint256::zero(); 5];
    m[0] = message.data[0];
    m[1] = message.data[1];
    m[2] = message.data[2];
    m[3] = message.data[3];
    m[4] = message.data[4];

    let mut n: [Uint256; 5] = [Uint256::zero(); 5];
    n[0] = message.data[5];
    n[1] = message.data[6];
    n[2] = enc_pub_key.x;
    n[3] = enc_pub_key.y;
    n[4] = prev_hash;

    let m_hash = hash5(m);

    let n_hash = hash5(n);
    let m_n_hash = hash2([m_hash, n_hash]);
    return m_n_hash;
}

// Only admin can execute
fn can_execute(deps: Deps, sender: &str) -> StdResult<bool> {
    let cfg = ADMIN.load(deps.storage)?;
    let can = cfg.is_admin(&sender);
    Ok(can)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetPeriod {} => to_binary::<Period>(&PERIOD.load(deps.storage).unwrap()),
        QueryMsg::GetMsgChainLength {} => {
            to_binary::<Uint256>(&MSG_CHAIN_LENGTH.load(deps.storage).unwrap())
        }
        QueryMsg::GetResult { index } => to_binary::<Uint256>(
            &RESULT
                .load(deps.storage, index.to_be_bytes().to_vec())
                .unwrap(),
        ),
        QueryMsg::GetAllResult {} => {
            to_binary::<Uint256>(&MSG_CHAIN_LENGTH.load(deps.storage).unwrap())
        }
        QueryMsg::GetStateIdxInc { address } => {
            to_binary::<Uint256>(&STATEIDXINC.load(deps.storage, &address).unwrap())
        }
        QueryMsg::GetVoiceCreditBalance { index } => to_binary::<Uint256>(
            &VOICECREDITBALANCE
                .load(deps.storage, index.to_be_bytes().to_vec())
                .unwrap(),
        ),
    }
}

#[cfg(test)]
mod tests {}
