use crate::tf512;
use crate::ubi512;

use tf512::{
    NUM_BLOCK_BYTES,
    NUM_BLOCK_WORDS,
    NUM_KEY_BYTES,
    NUM_KEY_WORDS
};
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

pub const NUM_MHF_BYTES: usize = tf512::NUM_BLOCK_BYTES * 2;
pub const NUM_MHF_WORDS: usize = NUM_MHF_BYTES / 8;

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

pub const NUM_X_WORDS: usize = tf512::NUM_BLOCK_WORDS;

#[derive(Clone, Copy)]
pub struct Gamma {
    buffer: [u64; NUM_GAMMA_BUFFER_WORDS],
    rng:    [u64; NUM_RNG_WORDS],
}

pub union Temp {
    gamma:         Gamma,
    flap:          [u64; NUM_FLAP_WORDS],
    phi:           [u64; NUM_PHI_WORDS],
    mhf:           [u64; NUM_MHF_WORDS],
    tweak_pw_salt: [u8;  NUM_TWEAK_PW_SALT_BYTES],
    catena:        [u8;  NUM_CATENA_BYTES],
}

pub struct Catena {
    pub ubi512:       Ubi512,
    pub temp:         Temp,
    pub x:            [u64; NUM_X_WORDS],
    pub salt:         [u64; NUM_SALT_WORDS],
    pub graph_memory: Box::<[u64]>,
}

macro_rules! as_bytes{
    ($u64_slice:expr, $u64_size:expr) => {unsafe {
        std::slice::from_raw_parts(
            $u64_slice as *const _ as *const u8,
            std::mem::size_of::<u64>() * $u64_size
        )
    }}
}

macro_rules! as_bytes_mut {
    ($u64_slice:expr, $u64_size:expr) => {unsafe {
        std::slice::from_raw_parts_mut(
            $u64_slice as *mut _ as *mut u8,
            std::mem::size_of::<u64>() * $u64_size
        )
    }}
}

impl Catena {
    pub fn new(g_high: u8) -> Catena {
        let num_allocated_words = {1usize << {g_high + 3}};
        let v = vec![0u64; num_allocated_words];
        Catena {
            ubi512: Ubi512::new(),
            temp:   unsafe { std::mem::zeroed() },
            x:      [0u64; NUM_X_WORDS],
            salt:   [0u64; NUM_SALT_WORDS],
            graph_memory: v.into_boxed_slice()
        }
    }
    pub fn make_tweak(&mut self, lambda: u8, use_phi: bool) {
        {
            let bytes = if use_phi {
                as_bytes!(&WITH_PHI_VERSION_ID, tf512::NUM_BLOCK_WORDS)
            } else {
                as_bytes!(&WITHOUT_PHI_VERSION_ID, tf512::NUM_BLOCK_WORDS)
            };
            unsafe {self.temp.tweak_pw_salt[..tf512::NUM_BLOCK_WORDS].copy_from_slice(
                &bytes
            )};
        }
        let mut i = tf512::NUM_BLOCK_WORDS;
        unsafe {*self.temp.tweak_pw_salt.get_unchecked_mut(i) = DOMAIN_KDF};
        i += 1;
        unsafe {*self.temp.tweak_pw_salt.get_unchecked_mut(i) = lambda};
        i += 1;
        unsafe {*self.temp.tweak_pw_salt.get_unchecked_mut(i) = {
            tf512::NUM_BLOCK_BYTES as u8
        }};
        i += 1;
        unsafe {*self.temp.tweak_pw_salt.get_unchecked_mut(i) = {
            (tf512::NUM_BLOCK_BYTES >> 8) as u8
        }};
        i += 1;
        unsafe {*self.temp.tweak_pw_salt.get_unchecked_mut(i) = {
            NUM_SALT_BYTES as u8
        }};
        i += 1;
        unsafe {*self.temp.tweak_pw_salt.get_unchecked_mut(i) = {
            (NUM_SALT_BYTES >> 8) as u8
        }};
    }
    pub fn flap(&mut self, garlic: u8, lambda: u8, use_phi: bool) {
        const CONFIG: [u64; NUM_BLOCK_WORDS] = [
            0x545e7a4c7832afdbu64.to_be(),
            0xc7ab18d287d9e62du64.to_be(),
            0x4108903acba9a3aeu64.to_be(),
            0x3108c7e40e0e55a0u64.to_be(),
            0xc39ca85d6cd24671u64.to_be(),
            0xba1b586631a3fd33u64.to_be(),
            0x876983543c179302u64.to_be(),
            0xd759946100b8b807u64.to_be(),
        ];
        self.ubi512.threefish512.key[..NUM_KEY_WORDS].copy_from_slice(
            &CONFIG
        );
    }
}

