use crate::utils::hash5;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Binary, Timestamp, Uint128, Uint256};
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub struct RoundInfo {
    pub title: String,
    pub description: String,
    pub link: String,
}

pub const ROUNDINFO: Item<RoundInfo> = Item::new("round_info");

#[cw_serde]
pub struct VotingTime {
    pub start_time: Option<Timestamp>,
    pub end_time: Option<Timestamp>,
}

pub const VOTINGTIME: Item<VotingTime> = Item::new("voting_time");

pub const VOTEOPTIONMAP: Item<Vec<String>> = Item::new("vote_option_map");

#[cw_serde]
pub struct Admin {
    pub admin: Addr,
}

impl Admin {
    pub fn is_admin(&self, addr: impl AsRef<str>) -> bool {
        let addr = addr.as_ref();
        self.admin.as_ref() == addr
    }
}

#[cw_serde]
pub enum PeriodStatus {
    Pending,
    Voting,
    Processing,
    Tallying,
    Ended,
}

#[cw_serde]
pub struct Period {
    pub status: PeriodStatus,
}

#[cw_serde]
pub struct MaciParameters {
    pub state_tree_depth: Uint256,
    pub int_state_tree_depth: Uint256,
    pub message_batch_size: Uint256,
    pub vote_option_tree_depth: Uint256,
}

pub const STATEIDXINC: Map<&Addr, Uint256> = Map::new("state_idx_inc");

pub const ADMIN: Item<Admin> = Item::new("admin");
pub const PERIOD: Item<Period> = Item::new("period");
pub const MACIPARAMETERS: Item<MaciParameters> = Item::new("maci_param");

// the num of signup, the state_key is signupnums.
pub const NUMSIGNUPS: Item<Uint256> = Item::new("num_sign_ups");

// key is state_key, value is sender balance
pub const VOICECREDITBALANCE: Map<Vec<u8>, Uint256> = Map::new("voice_credit_balance");

pub const NODES: Map<Vec<u8>, Uint256> = Map::new("nodes");

pub const MAX_VOTE_OPTIONS: Item<Uint256> = Item::new("max_vote_options");
pub const CURRENT_STATE_COMMITMENT: Item<Uint256> = Item::new("current_state_commitment");
pub const CURRENT_TALLY_COMMITMENT: Item<Uint256> = Item::new("current_tally_commitment");

pub const RESULT: Map<Vec<u8>, Uint256> = Map::new("voice_credit_balance");
pub const TOTAL_RESULT: Item<Uint256> = Item::new("total_result");

#[cw_serde]
pub struct PubKey {
    pub x: Uint256,
    pub y: Uint256,
}

#[cw_serde]
pub struct StateLeaf {
    pub pub_key: PubKey,
    pub voice_credit_balance: Uint256,
    pub vote_option_tree_root: Uint256,
    pub nonce: Uint256,
}

impl StateLeaf {
    pub fn hash_state_leaf(&self) -> Uint256 {
        let mut plaintext: [Uint256; 5] = [Uint256::from_u128(0); 5];

        plaintext[0] = self.pub_key.x;
        plaintext[1] = self.pub_key.y;
        plaintext[2] = self.voice_credit_balance;
        plaintext[3] = self.vote_option_tree_root;
        plaintext[4] = self.nonce;
        return hash5(plaintext);
    }
}

// Init Data
pub const MAX_LEAVES_COUNT: Item<Uint256> = Item::new("max_leaves_count");
pub const LEAF_IDX_0: Item<Uint256> = Item::new("leaf_idx_0");
pub const COORDINATORHASH: Item<Uint256> = Item::new("coordinator_hash");
pub const ZEROS: Item<[Uint256; 10]> = Item::new("zeros");

#[cw_serde]
pub struct MessageData {
    pub data: [Uint256; 7],
}

pub const MSG_HASHES: Map<Vec<u8>, Uint256> = Map::new("msg_hashes");
// pub const MSG_HASHES: Item<Vec<Uint256>> = Item::new("msg_hashes");
pub const MSG_CHAIN_LENGTH: Item<Uint256> = Item::new("msg_chain_length");
pub const PROCESSED_MSG_COUNT: Item<Uint256> = Item::new("processed_msg_count");
pub const PROCESSED_USER_COUNT: Item<Uint256> = Item::new("processed_user_count");

#[cw_serde]
pub struct Groth16ProofStr {
    pub pi_a: Vec<u8>,
    pub pi_b: Vec<u8>,
    pub pi_c: Vec<u8>,
}

#[cw_serde]
pub struct QuinaryTreeRoot {
    pub zeros: [Uint256; 9],
}

impl QuinaryTreeRoot {
    const DEGREE: u32 = 5;

    pub fn root_of(&self, depth: Uint256, nodes: Vec<Uint256>) -> Uint256 {
        let _depth = depth.to_string().parse().unwrap();
        let capacity = Self::DEGREE.pow(_depth);
        let length = nodes.len() as u32;

        assert!(capacity >= length, "overflow");

        let mut c = capacity / Self::DEGREE;
        let mut pl = (length - 1) / Self::DEGREE + 1;
        let mut _nodes = nodes;

        for i in 0.._depth {
            let zero = self.get_zero(i);
            // number of non-zero parent nodes
            for j in 0..c {
                if j >= length {
                    continue;
                }
                let mut h = Uint256::zero();
                if j < pl {
                    let mut inputs = [Uint256::zero(); 5];
                    let mut s = Uint256::zero();
                    for k in 0..5 {
                        let node = if j * 5 + k < length {
                            _nodes[(j * 5 + k) as usize]
                        } else {
                            Uint256::zero()
                        };
                        s += node;
                        let mut input = node;
                        if node == Uint256::zero() {
                            input = zero;
                        }
                        inputs[k as usize] = input;
                    }
                    if s > Uint256::zero() {
                        h = hash5(inputs);
                    }
                }
                _nodes[j as usize] = h;
            }

            pl = (pl - 1) / Self::DEGREE + 1;
            c = c / Self::DEGREE;
        }

        let mut result = _nodes[0];
        if result == Uint256::zero() {
            result = self.get_zero(_depth);
        }
        result
    }

    fn get_zero(&self, height: u32) -> Uint256 {
        self.zeros[height as usize]
    }
}

pub const QTR_LIB: Item<QuinaryTreeRoot> = Item::new("qtr_lib");

#[cw_serde]
pub struct WhitelistConfig {
    pub balance: Uint256,
    pub is_register: bool,
    pub fee_amount: Uint128,
    pub fee_grant: bool,
}

impl WhitelistConfig {
    pub fn register(&mut self) {
        self.is_register = true;
        self.balance = Uint256::from_u128(0u128);
    }

    pub fn grant(&mut self, amount: Uint128) {
        self.fee_grant = true;
        self.fee_amount = amount;
    }

    pub fn revoke(&mut self) {
        self.fee_grant = false;
        self.fee_amount = Uint128::from(0u128);
    }

    pub fn balance_of(&self) -> Uint256 {
        return self.balance;
    }
}

pub const WHITELIST: Map<&Addr, WhitelistConfig> = Map::new("whitelist");

pub const MAX_WHITELIST_NUM: Item<u128> = Item::new("max_whitelist_num");

pub const FEEGRANTS: Item<Uint128> = Item::new("fee_grants");

pub const CIRCUITTYPE: Item<Uint256> = Item::new("circuit_type"); // <0: 1p1v | 1: pv>

pub const CERTSYSTEM: Item<Uint256> = Item::new("certification_system"); // <0: groth16 | 1: plonk>

#[cw_serde]
pub struct PlonkProofStr {
    pub num_inputs: usize,
    pub n: usize,
    pub input_values: Vec<String>,
    pub wire_commitments: Vec<Vec<u8>>,
    pub grand_product_commitment: Vec<u8>,
    pub quotient_poly_commitments: Vec<Vec<u8>>,
    pub wire_values_at_z: Vec<String>,
    pub wire_values_at_z_omega: Vec<String>,
    pub grand_product_at_z_omega: String,
    pub quotient_polynomial_at_z: String,
    pub linearization_polynomial_at_z: String,
    pub permutation_polynomials_at_z: Vec<String>,
    pub opening_at_z_proof: Vec<u8>,
    pub opening_at_z_omega_proof: Vec<u8>,
}

#[cw_serde]
pub struct Groth16VkeyStr {
    pub alpha_1: Vec<u8>,
    pub beta_2: Vec<u8>,
    pub gamma_2: Vec<u8>,
    pub delta_2: Vec<u8>,
    pub ic0: Vec<u8>,
    pub ic1: Vec<u8>,
}

pub const GROTH16_PROCESS_VKEYS: Item<Groth16VkeyStr> = Item::new("groth16_process_vkeys");
pub const GROTH16_TALLY_VKEYS: Item<Groth16VkeyStr> = Item::new("groth16_tally_vkeys");

#[cw_serde]
pub struct PlonkVkeyStr {
    pub n: usize,
    pub num_inputs: usize,
    pub selector_commitments: Vec<Vec<u8>>,
    pub next_step_selector_commitments: Vec<Vec<u8>>,
    pub permutation_commitments: Vec<Vec<u8>>,
    pub non_residues: Vec<String>,
    pub g2_elements: Vec<Vec<u8>>,
}

pub const PLONK_PROCESS_VKEYS: Item<PlonkVkeyStr> = Item::new("plonk_process_vkeys");
pub const PLONK_TALLY_VKEYS: Item<PlonkVkeyStr> = Item::new("plonk_tally_vkeys");

// pub const WHITELIST_BACKEND_PUBKEY: Item<Binary> = Item::new("whitelist_backend_pubkey");
// pub const WHITELIST_ECOSYSTEM: Item<String> = Item::new("whitelist_ecosystem");
// pub const WHITELIST_SNAPSHOT_HEIGHT: Item<Uint256> = Item::new("whitelist_snapshot_height");

#[cw_serde]
pub struct OracleWhitelistConfig {
    pub backend_pubkey: Binary,
    pub ecosystem: String,
    pub snapshot_height: Uint256,
    pub slope: Uint256,
}

pub const ORACLE_WHITELIST_CONFIG: Item<OracleWhitelistConfig> =
    Item::new("oracle_whitelist_config");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_admin() {
        let alice: Addr = Addr::unchecked("alice");

        let config: Admin = Admin {
            admin: alice.clone(),
        };

        assert!(config.is_admin(alice.as_ref()));
        assert!(!config.is_admin("other"));
    }
}
