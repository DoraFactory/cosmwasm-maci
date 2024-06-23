/**
* This file was automatically generated by @cosmwasm/ts-codegen@0.30.1.
* DO NOT MODIFY IT BY HAND. Instead, modify the source JSONSchema file,
* and run the @cosmwasm/ts-codegen generate command to regenerate this file.
*/

export type Uint256 = string;
export type Timestamp = Uint64;
export type Uint64 = string;
export interface InstantiateMsg {
  circuit_type: Uint256;
  coordinator: PubKey;
  groth16_add_key_vkey: Groth16VKeyType;
  groth16_deactivate_vkey: Groth16VKeyType;
  groth16_process_vkey: Groth16VKeyType;
  groth16_tally_vkey: Groth16VKeyType;
  max_vote_options: Uint256;
  parameters: MaciParameters;
  qtr_lib: QuinaryTreeRoot;
  round_info: RoundInfo;
  voice_credit_amount: Uint256;
  voting_time?: VotingTime | null;
  whitelist?: Whitelist | null;
}
export interface PubKey {
  x: Uint256;
  y: Uint256;
}
export interface Groth16VKeyType {
  vk_alpha1: string;
  vk_beta_2: string;
  vk_delta_2: string;
  vk_gamma_2: string;
  vk_ic0: string;
  vk_ic1: string;
}
export interface MaciParameters {
  int_state_tree_depth: Uint256;
  message_batch_size: Uint256;
  state_tree_depth: Uint256;
  vote_option_tree_depth: Uint256;
}
export interface QuinaryTreeRoot {
  zeros: [Uint256, Uint256, Uint256, Uint256, Uint256, Uint256, Uint256, Uint256, Uint256];
}
export interface RoundInfo {
  description: string;
  link: string;
  title: string;
}
export interface VotingTime {
  end_time?: Timestamp | null;
  start_time?: Timestamp | null;
}
export interface Whitelist {
  users: WhitelistConfig[];
}
export interface WhitelistConfig {
  addr: string;
}
export type ExecuteMsg = {
  set_params: {
    int_state_tree_depth: Uint256;
    message_batch_size: Uint256;
    state_tree_depth: Uint256;
    vote_option_tree_depth: Uint256;
  };
} | {
  set_round_info: {
    round_info: RoundInfo;
  };
} | {
  set_whitelists: {
    whitelists: Whitelist;
  };
} | {
  set_vote_options_map: {
    vote_option_map: string[];
  };
} | {
  start_voting_period: {};
} | {
  sign_up: {
    pubkey: PubKey;
  };
} | {
  start_process_period: {};
} | {
  stop_voting_period: {};
} | {
  publish_deactivate_message: {
    enc_pub_key: PubKey;
    message: MessageData;
  };
} | {
  process_deactivate_message: {
    groth16_proof: Groth16ProofType;
    new_deactivate_commitment: Uint256;
    new_deactivate_root: Uint256;
    size: Uint256;
  };
} | {
  add_new_key: {
    d: [Uint256, Uint256, Uint256, Uint256];
    groth16_proof: Groth16ProofType;
    nullifier: Uint256;
    pubkey: PubKey;
  };
} | {
  publish_message: {
    enc_pub_key: PubKey;
    message: MessageData;
  };
} | {
  process_message: {
    groth16_proof: Groth16ProofType;
    new_state_commitment: Uint256;
  };
} | {
  stop_processing_period: {};
} | {
  process_tally: {
    groth16_proof: Groth16ProofType;
    new_tally_commitment: Uint256;
  };
} | {
  stop_tallying_period: {
    results: Uint256[];
    salt: Uint256;
  };
} | {
  grant: {
    max_amount: Uint128;
  };
} | {
  revoke: {};
} | {
  bond: {};
} | {
  withdraw: {
    amount?: Uint128 | null;
  };
};
export type Uint128 = string;
export interface MessageData {
  data: [Uint256, Uint256, Uint256, Uint256, Uint256, Uint256, Uint256];
}
export interface Groth16ProofType {
  a: string;
  b: string;
  c: string;
}
export type QueryMsg = {
  get_round_info: {};
} | {
  get_voting_time: {};
} | {
  get_period: {};
} | {
  get_num_sign_up: {};
} | {
  get_msg_chain_length: {};
} | {
  get_d_msg_chain_length: {};
} | {
  get_processed_d_msg_count: {};
} | {
  get_processed_msg_count: {};
} | {
  get_processed_user_count: {};
} | {
  get_result: {
    index: Uint256;
  };
} | {
  get_all_result: {};
} | {
  get_state_idx_inc: {
    address: Addr;
  };
} | {
  get_voice_credit_balance: {
    index: Uint256;
  };
} | {
  white_list: {};
} | {
  is_white_list: {
    sender: string;
  };
} | {
  vote_option_map: {};
} | {
  max_vote_options: {};
} | {
  query_total_fee_grant: {};
} | {
  query_circuit_type: {};
} | {
  query_cert_system: {};
};
export type Addr = string;
export type PeriodStatus = "pending" | "voting" | "processing" | "tallying" | "ended";
export interface Period {
  status: PeriodStatus;
}
export type Boolean = boolean;
export type ArrayOfString = string[];