use crate::tf512;
use crate::ubi512;
use crate::skein512;

use tf512::{
    NUM_BLOCK_BYTES,
    NUM_BLOCK_WORDS,
    NUM_KEY_BYTES,
    NUM_KEY_WORDS
};
use ubi512::Ubi512;
use skein512::{
    Skein512,
    NUM_HASH_WORDS,
};

pub const WITHOUT_PHI_VERSION_ID: [u8; NUM_KEY_BYTES] = [
    0x79u8, 0xb5u8, 0x79u8, 0x1eu8, 0x9au8, 0xacu8, 0x02u8, 0x64u8,
    0x2au8, 0xaau8, 0x99u8, 0x1bu8, 0xd5u8, 0x47u8, 0xedu8, 0x14u8,
    0x74u8, 0x4du8, 0x72u8, 0xbfu8, 0x13u8, 0x22u8, 0x54u8, 0xc9u8,
    0xadu8, 0xd6u8, 0xb9u8, 0xbeu8, 0xe8u8, 0x70u8, 0x18u8, 0xe2u8,
    0xaau8, 0x51u8, 0x50u8, 0xe2u8, 0x1fu8, 0xcdu8, 0x90u8, 0x19u8,
    0xb6u8, 0x1fu8, 0x0eu8, 0xc6u8, 0x05u8, 0x00u8, 0xd6u8, 0xedu8,
    0x7cu8, 0xf2u8, 0x03u8, 0x53u8, 0xfdu8, 0x42u8, 0xa5u8, 0xa3u8,
    0x7au8, 0x0eu8, 0xbbu8, 0xb4u8, 0xa7u8, 0xebu8, 0xdbu8, 0xabu8,
];

pub const WITH_PHI_VERSION_ID: [u8; NUM_KEY_BYTES] = [
    0x1fu8, 0x23u8, 0x89u8, 0x58u8, 0x4au8, 0x4au8, 0xbbu8, 0xa5u8,
    0x9fu8, 0x09u8, 0xcau8, 0xd4u8, 0xefu8, 0xacu8, 0x43u8, 0x1du8,
    0xdeu8, 0x9au8, 0xb0u8, 0xf8u8, 0x69u8, 0xaau8, 0x50u8, 0xf3u8,
    0xedu8, 0xccu8, 0xb4u8, 0x7du8, 0x6du8, 0x4fu8, 0x10u8, 0xb9u8,
    0x8eu8, 0x6au8, 0x68u8, 0xabu8, 0x6eu8, 0x53u8, 0xbcu8, 0xd6u8,
    0xcfu8, 0xfcu8, 0xa7u8, 0x63u8, 0x94u8, 0x44u8, 0xbdu8, 0xc7u8,
    0xb9u8, 0x6du8, 0x09u8, 0xf5u8, 0x66u8, 0x31u8, 0xa3u8, 0xc5u8,
    0xf3u8, 0x26u8, 0xebu8, 0x6fu8, 0xa6u8, 0xacu8, 0xb0u8, 0xa6u8,
];

pub const NUM_HASH_BYTES: usize = NUM_HASH_WORDS * 8;

pub const NUM_SALT_BYTES:     usize = 32;
pub const NUM_SALT_WORDS:     usize = NUM_SALT_BYTES / 8;
pub const MAX_PASSWORD_BYTES: usize = 125;
pub const NUM_TWEAK_BYTES:    usize = {
    NUM_BLOCK_BYTES + 1 + 1 + 2 + 2
};
pub const NUM_RNG_BYTES: usize = NUM_BLOCK_BYTES;
pub const NUM_RNG_WORDS: usize = NUM_RNG_BYTES / 8;

pub const DOMAIN_PW_SCRAMBLER: u8 = 0u8;
pub const DOMAIN_KDF:          u8 = 1u8;
pub const DOMAIN_POW:          u8 = 2u8;

pub const NUM_MHF_BYTES: usize = NUM_BLOCK_BYTES * 2;
pub const NUM_MHF_WORDS: usize = NUM_MHF_BYTES / 8;

pub const NUM_TWEAK_PW_SALT_BYTES: usize = {
    NUM_TWEAK_BYTES + MAX_PASSWORD_BYTES + NUM_SALT_BYTES
};

pub const NUM_FLAP_BYTES:   usize = NUM_BLOCK_BYTES * 3;
pub const NUM_FLAP_WORDS:   usize = NUM_FLAP_BYTES / 8;
pub const NUM_PHI_BYTES:    usize = NUM_BLOCK_BYTES * 2;
pub const NUM_PHI_WORDS:    usize = NUM_PHI_BYTES / 8;

pub const NUM_CATENA_BYTES: usize = NUM_BLOCK_BYTES + 1;

pub const NUM_GAMMA_BUFFER_BYTES: usize = NUM_BLOCK_BYTES * 2;
pub const NUM_GAMMA_BUFFER_WORDS: usize = NUM_GAMMA_BUFFER_BYTES / 8;

pub const NUM_X_WORDS: usize = NUM_BLOCK_WORDS;
pub const NUM_X_BYTES: usize = NUM_X_WORDS * 8;

pub const NUM_HASH_INPUT_WORDS: usize = NUM_HASH_WORDS * 2;
pub const NUM_HASH_INPUT_BYTES: usize = NUM_HASH_INPUT_WORDS * 8;

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

macro_rules! idx {
    ($i:expr) => {
        ($i * 8)
    }
}

macro_rules! hash_native {
    ($ubi:expr, $dest:expr, $src:expr) => {
        $ubi.threefish512.key[..NUM_KEY_WORDS].copy_from_slice(&skein512::NATIVE_INIT);
        $ubi.chain_message($src);
        $ubi.chain_native_output($dest);
    }
}

#[derive(Clone, Copy)]
pub struct Gamma {
    buffer: [u64; NUM_GAMMA_BUFFER_WORDS],
    rng:    [u64; NUM_RNG_WORDS],
}

pub union Temp {
    gamma:         Gamma,
    flap:          [u8; NUM_FLAP_BYTES],
    phi:           [u8; NUM_PHI_BYTES],
    mhf:           [u8; NUM_MHF_BYTES],
    tweak_pw_salt: [u8; NUM_TWEAK_PW_SALT_BYTES],
    catena:        [u8; NUM_CATENA_BYTES],
}

pub struct Catena {
    pub skein512:     Skein512,
    pub temp:         Temp,
    pub x:            [u8; NUM_X_BYTES],
    pub salt:         [u8; NUM_SALT_BYTES],
    pub graph_memory: Box::<[u8]>,
}

macro_rules! x_bytes_mut {
    ($catena:expr) => { as_bytes_mut!(&mut $catena.x, NUM_X_WORDS) }
}
macro_rules! flap_bytes_mut {
    ($catena:expr) => { unsafe {as_bytes_mut!(&mut $catena.temp.flap, NUM_FLAP_WORDS)} }
}

impl Catena {
    pub fn new(g_high: u8) -> Catena {
        let num_allocated_bytes = {1usize << {g_high + 6}};
        let v = vec![0u8;  num_allocated_bytes];
        Catena {
            skein512:     Skein512::new(),
            temp:         unsafe { std::mem::zeroed() },
            x:            [0u8; NUM_X_BYTES],
            salt:         [0u8; NUM_SALT_BYTES],
            graph_memory: v.into_boxed_slice()
        }
    }
    pub fn make_tweak(&mut self, lambda: u8, use_phi: bool) {
        let version_id = if use_phi {
            &WITH_PHI_VERSION_ID
        } else {
            &WITHOUT_PHI_VERSION_ID
        };
        unsafe { self.temp.tweak_pw_salt[..NUM_KEY_BYTES].copy_from_slice(version_id) };
        let mut i = NUM_KEY_BYTES;
        unsafe {*self.temp.tweak_pw_salt.get_unchecked_mut(i) = DOMAIN_KDF};
        i += 1;
        unsafe {*self.temp.tweak_pw_salt.get_unchecked_mut(i) = lambda};
        i += 1;
        unsafe {*self.temp.tweak_pw_salt.get_unchecked_mut(i) = {
            NUM_BLOCK_BYTES as u8
        }};
        i += 1;
        unsafe {*self.temp.tweak_pw_salt.get_unchecked_mut(i) = {
            (NUM_BLOCK_BYTES >> 8) as u8
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
        {
            const CONFIG: &[u64; NUM_KEY_WORDS] = &skein512::OUTPUT_16_WORDS_INIT;
            let ubi = &mut self.skein512.ubi512;
            ubi.threefish512.key[..NUM_KEY_WORDS].copy_from_slice(
                CONFIG
            );
            ubi.chain_message(&self.x);
            ubi.chain_output(unsafe {&mut self.temp.flap[..NUM_HASH_BYTES * 2]});
        }
        //TODO: HASH(TEMP{1}, TEMP{0..1})
        //TODO: COPY(TEMP{2}, TEMP{0})
        //TODO: HASH(TEMP{0}, TEMP{1..2})
        //TODO: COPY(GRAPH{0}, TEMP{1})
        //TODO: COPY(GRAPH{1}, TEMP{0})
    }
}

