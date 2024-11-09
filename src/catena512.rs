use crate::tf512;
use crate::ubi512;

use ubi512::Ubi512;

pub const WITHOUT_PHI_VERSION_ID: [u64; 8] = [
    0x79b5791e9aac0264u64.to_be(),
    0x2aaa991bd547ed14u64.to_be(),
    0x744d72bf132254c9u64.to_be(),
    0xadd6b9bee87018e2u64.to_be(),
    0xaa5150e21fcd9019u64.to_be(),
    0xb61f0ec60500d6edu64.to_be(),
    0x7cf20353fd42a5a3u64.to_be(),
    0x7a0ebbb4a7ebdbabu64.to_be(),
];

pub const WITH_PHI_VERSION_ID: [u64; 8] = [
    0x1f2389584a4abba5u64.to_be(),
    0x9f09cad4efac431du64.to_be(),
    0xde9ab0f869aa50f3u64.to_be(),
    0xedccb47d6d4f10b9u64.to_be(),
    0x8e6a68ab6e53bcd6u64.to_be(),
    0xcffca7639444bdc7u64.to_be(),
    0xb96d09f56631a3c5u64.to_be(),
    0xf326eb6fa6acb0a6u64.to_be(),
];

pub const NUM_SALT_BYTES:     usize = 32;
pub const NUM_SALT_WORDS:     usize = NUM_SALT_BYTES / 8;
pub const MAX_PASSWORD_BYTES: usize = 125;
pub const NUM_TWEAK_BYTES:    usize = {
    tf512::NUM_BLOCK_BYTES + 1 + 1 + 2 + 2
};
pub const NUM_RNG_BYTES: usize = tf512::NUM_BLOCK_BYTES;
pub const NUM_RNG_WORDS: usize = NUM_RNG_BYTES / 8;

pub const DOMAIN_PW_SCRAMBLER: u8 = 0u8;
pub const DOMAIN_KDF:          u8 = 1u8;
pub const DOMAIN_POW:          u8 = 2u8;

pub const MHF_TEMP_BYTES: usize = 0usize; //FIXME

pub const NUM_TWEAK_PW_SALT_BYTES: usize = {
    NUM_TWEAK_BYTES + MAX_PASSWORD_BYTES + NUM_SALT_BYTES
};

pub const NUM_FLAP_BYTES:   usize = tf512::NUM_BLOCK_BYTES * 3;
pub const NUM_FLAP_WORDS:   usize = NUM_FLAP_BYTES / 8;
pub const NUM_PHI_BYTES:    usize = tf512::NUM_BLOCK_BYTES * 2;
pub const NUM_PHI_WORDS:    usize = NUM_PHI_BYTES / 8;

pub const NUM_CATENA_BYTES: usize = tf512::NUM_BLOCK_BYTES + 1;

pub const NUM_GAMMA_BUFFER_BYTES: usize = tf512::NUM_BLOCK_BYTES * 2;
pub const NUM_GAMMA_BUFFER_WORDS: usize = NUM_GAMMA_BUFFER_BYTES / 8;

#[derive(Clone, Copy)]
struct Gamma {
    buffer: [u64; NUM_GAMMA_BUFFER_WORDS],
    rng:    [u64; NUM_RNG_WORDS],
}

union Temp {
    gamma:         Gamma,
    flap:          [u64; NUM_FLAP_WORDS],
    phi:           [u64; NUM_PHI_WORDS],
    tweak_pw_salt: [u8;  NUM_TWEAK_PW_SALT_BYTES],
    catena:        [u8;  NUM_CATENA_BYTES],
    mhf:           [u8;  MHF_TEMP_BYTES],
}

struct Catena {
    ubi512:       Ubi512,
    x:            [u64; tf512::NUM_BLOCK_WORDS],
    salt:         [u64; NUM_SALT_WORDS],
    graph_memory: Box::<u64>,
}





