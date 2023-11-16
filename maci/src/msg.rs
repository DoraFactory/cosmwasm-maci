use crate::state::{
    MaciParameters, MessageData, PeriodStatus, PubKey, QuinaryTreeRoot, RoundInfo, VotingTime,
    Whitelist,
};
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128, Uint256};

#[cw_serde]
pub struct InstantiateMsg {
    pub parameters: MaciParameters,
    pub coordinator: PubKey,
    pub qtr_lib: QuinaryTreeRoot,
    pub groth16_process_vkey: Option<Groth16VKeyType>,
    pub groth16_tally_vkey: Option<Groth16VKeyType>,
    pub plonk_process_vkey: Option<PlonkVKeyType>,
    pub plonk_tally_vkey: Option<PlonkVKeyType>,
    pub max_vote_options: Uint256,

    pub round_info: RoundInfo,
    pub voting_time: Option<VotingTime>,
    pub whitelist: Option<Whitelist>,
    pub circuit_type: Uint256,         // <0: 1p1v | 1: pv>
    pub certification_system: Uint256, // <0: groth16 | 1: plonk>
}

#[cw_serde]
pub struct Groth16VKeyType {
    pub vk_alpha1: String,
    pub vk_beta_2: String,
    pub vk_gamma_2: String,
    pub vk_delta_2: String,
    pub vk_ic0: String,
    pub vk_ic1: String,
}

#[cw_serde]
pub struct Groth16ProofType {
    pub a: String,
    pub b: String,
    pub c: String,
}

#[cw_serde]
pub struct PlonkVKeyType {
    pub n: usize,
    pub num_inputs: usize,
    pub selector_commitments: Vec<String>,
    pub next_step_selector_commitments: Vec<String>,
    pub permutation_commitments: Vec<String>,
    pub non_residues: Vec<String>,
    pub g2_elements: Vec<String>,
}

#[cw_serde]
pub struct PlonkProofType {
    pub num_inputs: usize,
    pub n: usize,
    pub input_values: Vec<String>,
    pub wire_commitments: Vec<String>,
    pub grand_product_commitment: String,
    pub quotient_poly_commitments: Vec<String>,
    pub wire_values_at_z: Vec<String>,
    pub wire_values_at_z_omega: Vec<String>,
    pub grand_product_at_z_omega: String,
    pub quotient_polynomial_at_z: String,
    pub linearization_polynomial_at_z: String,
    pub permutation_polynomials_at_z: Vec<String>,
    pub opening_at_z_proof: String,
    pub opening_at_z_omega_proof: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    SetParams {
        state_tree_depth: Uint256,
        int_state_tree_depth: Uint256,
        message_batch_size: Uint256,
        vote_option_tree_depth: Uint256,
    },
    SetRoundInfo {
        round_info: RoundInfo,
    },
    SetWhitelists {
        whitelists: Whitelist,
    },
    SetVoteOptionsMap {
        vote_option_map: Vec<String>,
    },
    StartVotingPeriod {},
    SignUp {
        pubkey: PubKey, // user's pubkey
    },
    StartProcessPeriod {},
    StopVotingPeriod {},
    PublishMessage {
        message: MessageData,
        enc_pub_key: PubKey,
    },
    ProcessMessage {
        new_state_commitment: Uint256,
        groth16_proof: Option<Groth16ProofType>,
        plonk_proof: Option<PlonkProofType>,
    },
    StopProcessingPeriod {},
    ProcessTally {
        new_tally_commitment: Uint256,
        groth16_proof: Option<Groth16ProofType>,
        plonk_proof: Option<PlonkProofType>,
    },
    StopTallyingPeriod {
        results: Vec<Uint256>,
        salt: Uint256,
    },
    Grant {
        max_amount: Uint128,
    },
    Revoke {},
    Bond {},
    Withdraw {
        amount: Option<Uint128>,
    },
}

#[cw_serde]
pub struct Period {
    pub status: PeriodStatus,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(RoundInfo)]
    GetRoundInfo {},

    #[returns(VotingTime)]
    GetVotingTime {},

    #[returns(Period)]
    GetPeriod {},

    #[returns(Uint256)]
    GetNumSignUp {},

    #[returns(Uint256)]
    GetMsgChainLength {},

    #[returns(Uint256)]
    GetResult { index: Uint256 },

    #[returns(Uint256)]
    GetAllResult {},

    #[returns(Uint256)]
    GetStateIdxInc { address: Addr },

    #[returns(Uint256)]
    GetVoiceCreditBalance { index: Uint256 },

    #[returns(Whitelist)]
    WhiteList {},
    /// Checks permissions of the caller on this proxy.
    /// If CanExecute returns true then a call to `Execute` with the same message,
    /// before any further state changes, should also succeed.
    #[returns(bool)]
    IsWhiteList { sender: String },

    #[returns(Uint256)]
    WhiteBalanceOf { sender: String },

    #[returns(Vec<String>)]
    VoteOptionMap {},

    #[returns(Uint256)]
    MaxVoteOptions {},

    #[returns(Uint128)]
    QueryTotalFeeGrant {},

    #[returns(Uint256)]
    QueryCircuitType {},
}
