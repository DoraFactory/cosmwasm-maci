use cosmwasm_std::Uint256;
// use num_bigint::BigUint;
use sha256::digest;

use ff::*;
use poseidon_rs::Poseidon;
pub type Fr = poseidon_rs::Fr; // alias

// pub fn uint256_from_decimal_string(decimal_string: &str) -> Uint256 {
//     assert!(
//         decimal_string.len() <= 77,
//         "the decimal length can't abrove 77"
//     );

//     let decimal_number = BigUint::parse_bytes(decimal_string.as_bytes(), 10)
//         .expect("Failed to parse decimal string");

//     let byte_array = decimal_number.to_bytes_be();

//     let hex_string = hex::encode(byte_array);
//     uint256_from_hex_string(&hex_string)
// }

pub fn uint256_from_hex_string(hex_string: &str) -> Uint256 {
    let padded_hex_string = if hex_string.len() < 64 {
        let padding_length = 64 - hex_string.len();
        format!("{:0>width$}{}", "", hex_string, width = padding_length)
    } else {
        hex_string.to_string()
    };

    let res = hex_to_decimal(&padded_hex_string);
    Uint256::from_be_bytes(res)
}

pub fn uint256_to_hex(data: Uint256) -> String {
    hex::encode(data.to_be_bytes())
}

pub fn hex_to_decimal(hex_bytes: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_bytes).unwrap_or_else(|_| vec![]);
    let decimal_values: Vec<u8> = bytes.iter().cloned().collect();

    let mut array: [u8; 32] = [0; 32];

    if decimal_values.len() >= 32 {
        array.copy_from_slice(&decimal_values[..32]);
    } else {
        array[..decimal_values.len()].copy_from_slice(&decimal_values);
    }

    array
}

pub fn hex_to_uint256(hex_bytes: &str) -> Uint256 {
    let bytes = hex::decode(hex_bytes).unwrap_or_else(|_| vec![]);
    let decimal_values: Vec<u8> = bytes.iter().cloned().collect();

    let mut array: [u8; 32] = [0; 32];

    if decimal_values.len() >= 32 {
        array.copy_from_slice(&decimal_values[..32]);
    } else {
        array[..decimal_values.len()].copy_from_slice(&decimal_values);
    }

    Uint256::from_be_bytes(array)
}

pub fn hash_uint256(data: Uint256) -> Uint256 {
    let uint256_inputs = vec![Fr::from_str(&data.to_string()).unwrap()];

    hash(uint256_inputs)
}

pub fn hash(message: Vec<Fr>) -> Uint256 {
    let poseidon = Poseidon::new();

    let hash_item = poseidon.hash(message).unwrap().to_string();
    let hash_res = &hash_item[5..hash_item.len() - 1];

    uint256_from_hex_string(hash_res)
}

pub fn hash2(data: [Uint256; 2]) -> Uint256 {
    let uint256_inputs: Vec<Fr> = data
        .iter()
        .map(|input| Fr::from_str(&input.to_string()).unwrap())
        .collect();

    hash(uint256_inputs)
}

pub fn hash5(data: [Uint256; 5]) -> Uint256 {
    let uint256_inputs: Vec<Fr> = data
        .iter()
        .map(|input| -> Fr { Fr::from_str(&input.to_string()).unwrap() })
        .collect();
    hash(uint256_inputs)
}

pub fn hash_256_uint256_list(arrays: &[Uint256]) -> String {
    let total_length = arrays.len() * 32;
    let mut result: Vec<u8> = Vec::with_capacity(total_length);

    for array in arrays {
        result.extend_from_slice(&array.to_be_bytes());
    }

    digest(result.as_slice())
}

pub fn encode_packed(arrays: &[&[u8; 32]]) -> Vec<u8> {
    let total_length = arrays.len() * 32;
    let mut result: Vec<u8> = Vec::with_capacity(total_length);

    for array in arrays {
        result.extend_from_slice(*array);
    }

    result
}
