use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use clap::{Arg, Command};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::process::exit;

const INVERSE_SBOX: [[u8; 16]; 16] = [
    [
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7,
        0xFB,
    ],
    [
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9,
        0xCB,
    ],
    [
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3,
        0x4E,
    ],
    [
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1,
        0x25,
    ],
    [
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6,
        0x92,
    ],
    [
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D,
        0x84,
    ],
    [
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45,
        0x06,
    ],
    [
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A,
        0x6B,
    ],
    [
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6,
        0x73,
    ],
    [
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF,
        0x6E,
    ],
    [
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE,
        0x1B,
    ],
    [
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A,
        0xF4,
    ],
    [
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC,
        0x5F,
    ],
    [
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C,
        0xEF,
    ],
    [
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99,
        0x61,
    ],
    [
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C,
        0x7D,
    ],
];

const SBOX: [[u8; 16]; 16] = [
    [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB,
        0x76,
    ],
    [
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72,
        0xC0,
    ],
    [
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31,
        0x15,
    ],
    [
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2,
        0x75,
    ],
    [
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F,
        0x84,
    ],
    [
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58,
        0xCF,
    ],
    [
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F,
        0xA8,
    ],
    [
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3,
        0xD2,
    ],
    [
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19,
        0x73,
    ],
    [
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B,
        0xDB,
    ],
    [
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4,
        0x79,
    ],
    [
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE,
        0x08,
    ],
    [
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B,
        0x8A,
    ],
    [
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D,
        0x9E,
    ],
    [
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28,
        0xDF,
    ],
    [
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB,
        0x16,
    ],
];

// AES Rcon values
const ROUND_CONSTANTS: [[u8; 4]; 10] = [
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1b, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00],
];

fn rot_word(word: &mut [u8; 4]) {
    let temp = word[0];
    for i in 0..3 {
        word[i] = word[i + 1];
    }
    word[3] = temp;
}

fn sub_word(word: &mut [u8; 4]) {
    for i in 0..4 {
        word[i] = SBOX[(word[i] >> 4) as usize][(word[i] & 0x0F) as usize];
    }
}

fn sha192(input: &[u8]) -> [u8; 24] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();

    let mut sha192_hash = [0u8; 24];
    sha192_hash.copy_from_slice(&result[0..24]);

    sha192_hash
}

fn key_derive(key: &str) -> Result<Vec<u8>, String> {
    let key_bytes = key.as_bytes();
    match key_bytes.len() {
        16 | 24 | 32 => Ok(key_bytes.to_vec()),
        _ => {
            let hashed_key = sha192(key_bytes);
            Ok(hashed_key.to_vec())
        }
    }
}

fn rounds(key: &[u8]) -> Result<u8, String> {
    match key.len() {
        16 => Ok(10),                             // AES-128
        24 => Ok(12),                             // AES-192
        32 => Ok(14),                             // AES-256
        _ => Err("Invalid key size".to_string()), // Invalid key size
    }
}

fn add_round_key(state: &mut [u8; 16], round_key: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= round_key[i];
    }
}

fn sub_bytes(state: &mut [u8; 16]) {
    for i in 0..16 {
        let row = (state[i] >> 4) as usize;
        let col = (state[i] & 0x0F) as usize;
        state[i] = SBOX[row][col];
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    state.swap(1, 5);
    state.swap(2, 10);
    state.swap(3, 15);
}

fn mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let col_idx = col * 4;
        let s0 = state[col_idx + 0];
        let s1 = state[col_idx + 1];
        let s2 = state[col_idx + 2];
        let s3 = state[col_idx + 3];

        state[col_idx + 0] = galois_multiply(s0, 2)
            ^ galois_multiply(s1, 3)
            ^ galois_multiply(s2, 1)
            ^ galois_multiply(s3, 1);
        state[col_idx + 1] = galois_multiply(s0, 1)
            ^ galois_multiply(s1, 2)
            ^ galois_multiply(s2, 3)
            ^ galois_multiply(s3, 1);
        state[col_idx + 2] = galois_multiply(s0, 1)
            ^ galois_multiply(s1, 1)
            ^ galois_multiply(s2, 2)
            ^ galois_multiply(s3, 3);
        state[col_idx + 3] = galois_multiply(s0, 3)
            ^ galois_multiply(s1, 1)
            ^ galois_multiply(s2, 1)
            ^ galois_multiply(s3, 2);
    }
}

fn galois_multiply(x: u8, y: u8) -> u8 {
    let mut result = 0;
    let mut a = x;
    let mut b = y;

    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let hi_bit_set = a & 0x80;
        a <<= 1;
        if hi_bit_set != 0 {
            a ^= 0x1b; // AES's irreducible polynomial: x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }

    result
}

fn key_expansion(key: &[u8], rounds: u8) -> Result<Vec<[u8; 16]>, String> {
    let mut key_schedule: Vec<[u8; 4]> = Vec::new();
    let key_len = key.len();

    // Step 1: Initialize key_schedule with the key divided into 4-byte words.
    for chunk in key.chunks(4) {
        let mut word = [0u8; 4];
        word.copy_from_slice(chunk);
        key_schedule.push(word);
    }

    // Step 2: Expand the key to generate round keys.
    let mut i = key_schedule.len();
    while i < (4 * (rounds + 1)) as usize {
        let mut temp = key_schedule[i - 1];

        // Every 4th word: apply Key Schedule Core
        if i % 4 == 0 {
            rot_word(&mut temp);
            sub_word(&mut temp);
            let rcon_index = (i / 4 - 1) as usize;
            temp[0] ^= ROUND_CONSTANTS[rcon_index][0];
        }

        // XOR the new word with the word 4 words back.
        for j in 0..4 {
            temp[j] ^= key_schedule[i - 4][j];
        }

        key_schedule.push(temp);
        i += 1;
    }

    // Convert to 16-byte round keys.
    let mut round_keys = Vec::new();
    for chunk in key_schedule.chunks(4) {
        let mut round_key = [0u8; 16];
        let mut idx = 0;
        for word in chunk {
            round_key[idx..(idx + 4)].copy_from_slice(word);
            idx += 4;
        }
        round_keys.push(round_key);
    }

    Ok(round_keys)
}

fn pkcs7_pad(data: &mut Vec<u8>, block_size: usize) {
    let padding_len = block_size - (data.len() % block_size);
    let padding = vec![padding_len as u8; padding_len];
    data.extend(padding);
}

fn encrypt_block(state: &mut [u8; 16], key_schedule: &Vec<[u8; 16]>, rounds: u8) {
    let mut state_copy = *state;
    add_round_key(&mut state_copy, &key_schedule[0]);

    for round in 1..rounds {
        sub_bytes(&mut state_copy);
        shift_rows(&mut state_copy);
        if round < rounds - 1 {
            mix_columns(&mut state_copy);
        }
        add_round_key(&mut state_copy, &key_schedule[round as usize]);
    }

    sub_bytes(&mut state_copy);
    shift_rows(&mut state_copy);
    add_round_key(&mut state_copy, &key_schedule[rounds as usize]);

    *state = state_copy;
}

fn encrypt(plaintext: &str, key: &str) -> Result<Vec<u8>, String> {
    let derived_key = key_derive(key)?;
    let rounds = match rounds(&derived_key) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}", e);
            exit(1);
        }
    };

    let key_schedule = key_expansion(&derived_key, rounds)?;

    let mut padded_plaintext = plaintext.as_bytes().to_vec();

    // Apply PKCS7 padding to the plaintext
    pkcs7_pad(&mut padded_plaintext, 16);

    // Encrypt the padded plaintext
    let ciphertext: Vec<u8> = padded_plaintext
        .par_chunks_mut(16)
        .map(|chunk| {
            let mut state = [0u8; 16];
            state.copy_from_slice(chunk);
            encrypt_block(&mut state, &key_schedule, rounds);
            state.to_vec()
        })
        .flatten()
        .collect();

    Ok(ciphertext)
}

fn pkcs7_unpad(data: &mut Vec<u8>) {
    if data.is_empty() {
        return;
    }

    // The last byte represents the padding length
    let padding_len = data[data.len() - 1] as usize;

    // Ensure that the padding length is valid (should not be greater than the length of the data)
    if padding_len == 0 || padding_len > data.len() {
        return; // Invalid padding
    }

    // Remove the padding from the vector
    data.truncate(data.len() - padding_len);
}

fn read_file_to_bytes(file_path: &str) -> Result<Vec<u8>, io::Error> {
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn inv_sub_bytes(state: &mut [u8; 16]) {
    // Inverse of SubBytes: Use the inverse S-box (can be precomputed similarly as SBOX)
    for i in 0..16 {
        let row = (state[i] >> 4) as usize;
        let col = (state[i] & 0x0F) as usize;
        state[i] = INVERSE_SBOX[row][col]; // INVERSE_SBOX should be defined like SBOX
    }
}

fn inv_shift_rows(state: &mut [u8; 16]) {
    // Inverse of ShiftRows: Reverse the row swaps
    state.swap(1, 13);
    state.swap(2, 10);
    state.swap(3, 7);
}

fn inv_mix_columns(state: &mut [u8; 16]) {
    // Inverse MixColumns: This involves multiplication in GF(2^8) by the inverse matrix.
    for col in 0..4 {
        let col_idx = col * 4;
        let s0 = state[col_idx + 0];
        let s1 = state[col_idx + 1];
        let s2 = state[col_idx + 2];
        let s3 = state[col_idx + 3];

        state[col_idx + 0] = galois_multiply(s0, 0x0E)
            ^ galois_multiply(s1, 0x0B)
            ^ galois_multiply(s2, 0x0D)
            ^ galois_multiply(s3, 0x09);
        state[col_idx + 1] = galois_multiply(s0, 0x09)
            ^ galois_multiply(s1, 0x0E)
            ^ galois_multiply(s2, 0x0B)
            ^ galois_multiply(s3, 0x0D);
        state[col_idx + 2] = galois_multiply(s0, 0x0D)
            ^ galois_multiply(s1, 0x09)
            ^ galois_multiply(s2, 0x0E)
            ^ galois_multiply(s3, 0x0B);
        state[col_idx + 3] = galois_multiply(s0, 0x0B)
            ^ galois_multiply(s1, 0x0D)
            ^ galois_multiply(s2, 0x09)
            ^ galois_multiply(s3, 0x0E);
    }
}

fn decrypt_block(state: &mut [u8; 16], key_schedule: &Vec<[u8; 16]>, rounds: u8) {
    let mut state_copy = *state;

    // Initial round key addition
    add_round_key(&mut state_copy, &key_schedule[rounds as usize]);

    // Apply rounds in reverse order
    for round in (1..rounds).rev() {
        inv_shift_rows(&mut state_copy);
        inv_sub_bytes(&mut state_copy);
        add_round_key(&mut state_copy, &key_schedule[round as usize]);
        inv_mix_columns(&mut state_copy); // Only do this on rounds before the last one
    }

    // Final round (no InvMixColumns)
    inv_shift_rows(&mut state_copy);
    inv_sub_bytes(&mut state_copy);
    add_round_key(&mut state_copy, &key_schedule[0]);

    *state = state_copy;
}

fn decrypt(ciphertext: &[u8], key: &str) -> Result<String, String> {
    let derived_key = key_derive(key)?;
    let rounds = match rounds(&derived_key) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}", e);
            exit(1);
        }
    };

    let key_schedule = key_expansion(&derived_key, rounds)?;

    let mut plaintext = ciphertext.to_vec();

    // Decrypt the ciphertext in blocks
    let decrypted: Vec<u8> = plaintext
        .par_chunks_mut(16)
        .map(|chunk| {
            let mut state = [0u8; 16];
            state.copy_from_slice(chunk);
            decrypt_block(&mut state, &key_schedule, rounds);
            state.to_vec()
        })
        .flatten()
        .collect();

    // Remove PKCS7 padding
    pkcs7_unpad(&mut decrypted);

    // Convert decrypted bytes to string
    match String::from_utf8(decrypted) {
        Ok(result) => Ok(result),
        Err(_) => Err("Decryption resulted in invalid UTF-8".to_string()),
    }
}

fn main() {
    let matches = Command::new("AES Encryption CLI")
        .version("1.0")
        .author("Your Name <your.email@example.com>")
        .about("Encrypts and decrypts messages using AES")
        .arg(
            Arg::new("encrypt")
                .short('e')
                .long("encrypt")
                .value_name("TEXT")
                .help("Encrypt the input text")
                .takes_value(true),
        )
        .arg(
            Arg::new("decrypt")
                .short('d')
                .long("decrypt")
                .value_name("TEXT")
                .help("Decrypt the input text")
                .takes_value(true),
        )
        .arg(
            Arg::new("key")
                .short('k')
                .long("key")
                .value_name("KEY")
                .help("AES key for encryption/decryption")
                .required(true)
                .takes_value(true),
        )
        .get_matches();

    if let Some(plaintext) = matches.value_of("encrypt") {
        let key = matches.value_of("key").unwrap();
        match encrypt(plaintext, key) {
            Ok(ciphertext) => {
                let encoded = STANDARD_NO_PAD.encode(&ciphertext);
                println!("Encrypted text: {}", encoded);
            }
            Err(e) => eprintln!("Error during encryption: {}", e),
        }
    }

    if let Some(ciphertext_base64) = matches.value_of("decrypt") {
        let key = matches.value_of("key").unwrap();
        match STANDARD_NO_PAD.decode(ciphertext_base64) {
            Ok(ciphertext) => match decrypt(&ciphertext, key) {
                Ok(plaintext) => println!("Decrypted text: {}", plaintext),
                Err(e) => eprintln!("Error during decryption: {}", e),
            },
            Err(_) => eprintln!("Invalid base64 encoded ciphertext"),
        }
    }
}
