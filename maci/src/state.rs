use crate::utils::hash5;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cosmwasm_std::Uint256;
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub struct Config {
    pub round_description: String,
}

pub const CONFIG: Item<Config> = Item::new("config");

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
pub const ZEROS: Item<[Uint256; 8]> = Item::new("zeros");

#[cw_serde]
pub struct Message {
    pub data: [Uint256; 7],
}

pub const MSG_HASHES: Map<Vec<u8>, Uint256> = Map::new("msg_hashes");
// pub const MSG_HASHES: Item<Vec<Uint256>> = Item::new("msg_hashes");
pub const MSG_CHAIN_LENGTH: Item<Uint256> = Item::new("msg_chain_length");
pub const PROCESSED_MSG_COUNT: Item<Uint256> = Item::new("processed_msg_count");
pub const PROCESSED_USER_COUNT: Item<Uint256> = Item::new("processed_user_count");

#[cw_serde]
pub struct ProofStr {
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
pub struct VkeyStr {
    pub alpha_1: Vec<u8>,
    pub beta_2: Vec<u8>,
    pub gamma_2: Vec<u8>,
    pub delta_2: Vec<u8>,
    pub ic0: Vec<u8>,
    pub ic1: Vec<u8>,
}

#[cw_serde]
pub struct ProofInfo {
    pub proof: ProofStr,
    pub is_valid: bool,
}

pub const PROVERINFO: Map<&Addr, ProofInfo> = Map::new("prover_info");
pub const PROVERLIST: Map<(&Addr, &Addr), ProofInfo> = Map::new("prover_list");
pub const PROCESS_VKEYS: Item<VkeyStr> = Item::new("process_vkeys");
pub const TALLY_VKEYS: Item<VkeyStr> = Item::new("tally_vkeys");

#[cw_serde]
pub struct WhitelistConfig {
    pub addr: String,
    pub balance: Uint256,
}

#[cw_serde]
pub struct Whitelist {
    pub users: Vec<WhitelistConfig>,
}

impl Whitelist {
    pub fn is_whitelist(&self, addr: impl AsRef<str>) -> bool {
        let addr = addr.as_ref();
        self.users.iter().any(|a| a.addr == addr)
    }

    pub fn register(&mut self, addr: impl AsRef<str>) {
        let addr = addr.as_ref();
        self.users = self
            .users
            .clone()
            .into_iter()
            .map(|mut user| {
                if user.addr == addr {
                    user.balance = Uint256::from_u128(0u128);
                }
                user
            })
            .collect();
    }

    pub fn balance_of(&self, addr: impl AsRef<str>) -> Uint256 {
        let addr = addr.as_ref();

        let user = self.users.iter().find(|a| a.addr == addr);
        match user {
            Some(user) => user.balance,
            None => Uint256::from_u128(0u128),
        }
    }
}

pub const WHITELIST: Item<Whitelist> = Item::new("whitelist");

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
