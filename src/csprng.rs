use crate::tf512;
use crate::ubi512;
use crate::skein512;

use ssc::op::{SSC_secureZero, secure_zero, c_void};
use ssc::rand::get_entropy;
use skein512::Skein512;
use skein512::{NUM_HASH_BYTES, NUM_HASH_WORDS};

pub const NUM_SEED_BYTES:   usize = ubi512::NUM_HASH_BYTES;
pub const NUM_BUFFER_BYTES: usize = NUM_SEED_BYTES * 2;

pub struct Csprng {
    skein512: Skein512,
    buffer:   [u8; NUM_BUFFER_BYTES],
    seed:     [u8; NUM_SEED_BYTES],
}

impl Drop for Csprng {
    fn drop(&mut self) {
        unsafe {
            SSC_secureZero(
                self as *mut _ as *mut c_void,
                std::mem::size_of::<Self>()
            )
        }
    }
}

const SKEIN_CFG_INIT: [u64; NUM_HASH_WORDS] = [
    0x545e7a4c7832afdbu64.to_be(),
    0xc7ab18d287d9e62du64.to_be(),
    0x4108903acba9a3aeu64.to_be(),
    0x3108c7e40e0e55a0u64.to_be(),
    0xc39ca85d6cd24671u64.to_be(),
    0xba1b586631a3fd33u64.to_be(),
    0x876983543c179302u64.to_be(),
    0xd759946100b8b807u64.to_be(),
];

macro_rules! skein_hash_pre_configed {
    ($skein:expr, $out:expr, $in:expr) => {{
        $skein.ubi512.threefish512.key[..NUM_HASH_WORDS].copy_from_slice(&SKEIN_CFG_INIT);
        $skein.ubi512.chain_message($in);
        $skein.ubi512.chain_output($out);
    }}
}

impl Csprng {
    pub fn new() -> Csprng {
        let mut csprng = Csprng {
            skein512: Skein512::new(),
            buffer:   [0u8; NUM_BUFFER_BYTES],
            seed:     [0u8; NUM_SEED_BYTES]
        };
        get_entropy(&mut csprng.seed);
        csprng
    }
    pub fn reseed_from_bytes(
        &mut self,
        material: &[u8])
    {
        self.buffer[..NUM_SEED_BYTES].copy_from_slice(&self.seed);
        self.buffer[NUM_SEED_BYTES..].copy_from_slice(material);
        self.skein512.hash_native(&mut self.seed, &self.buffer);
        secure_zero(&mut self.buffer);
    }
    pub fn reseed_from_os(&mut self)
    {
        self.buffer[..NUM_SEED_BYTES].copy_from_slice(&self.seed);
        get_entropy(&mut self.buffer[NUM_SEED_BYTES..]);
        self.skein512.hash_native(&mut self.seed, &self.buffer);
        secure_zero(&mut self.buffer);
    }
    pub fn get(
        &mut self,
        output: &mut [u8])
    {
        if output.len() == 0 {
            return;
        }
        let mut idx  = 0usize;
        let mut next_idx = if output.len() >= NUM_SEED_BYTES {
            NUM_SEED_BYTES as usize
        } else {
            output.len() as usize
        };
        while next_idx - idx == NUM_SEED_BYTES {
            skein_hash_pre_configed!(
                self.skein512,
                &mut self.buffer,
                &self.seed
            );
            self.seed.copy_from_slice(&self.buffer[..NUM_SEED_BYTES]);
            output[idx..next_idx].copy_from_slice(&self.buffer[NUM_SEED_BYTES..]);
            idx = next_idx;
            next_idx = if output.len() - idx >= NUM_SEED_BYTES {
                idx + NUM_SEED_BYTES
            } else {
                idx + (output.len() - idx)
            };
        }
        if idx != next_idx {
            skein_hash_pre_configed!(
                self.skein512,
                &mut self.buffer,
                &self.seed
            );
            self.seed.copy_from_slice(&self.buffer[..NUM_SEED_BYTES]);
            let buffer_stop = NUM_SEED_BYTES + (next_idx - idx);
            output[idx..next_idx].copy_from_slice(&self.buffer[NUM_SEED_BYTES..buffer_stop]);
        }
        secure_zero(&mut self.buffer);
    }
}
