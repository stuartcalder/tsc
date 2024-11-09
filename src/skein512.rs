use crate::tf512;
use crate::ubi512;
use ubi512::Ubi512;

pub use ubi512::{NUM_HASH_BYTES, NUM_HASH_WORDS};

pub struct Skein512 {
    pub ubi512: Ubi512
}

pub const NATIVE_INIT: [u64; 8] = [
    0xce519c74ffad0349u64.to_be(),
    0x03df469739de950du64.to_be(),
    0xce9bc7274193d18fu64.to_be(),
    0xb12c35ff2956259au64.to_be(),
    0xb0a76cdf9925b65du64.to_be(),
    0xf4c3d5a94c39beeau64.to_be(),
    0x23b5751ac7121199u64.to_be(),
    0x33cc0f660ba418aeu64.to_be(),
];

impl Skein512 {

    pub fn new() -> Skein512 {
        Skein512 {
            ubi512: Ubi512::new()
        }
    }

    pub fn hash(
        &mut self,
        output: &mut [u8],
        input:  &[u8]
    )
    {
        self.ubi512.threefish512.key.fill(0u64);
        self.ubi512.chain_config({output.len() as u64} * 8u64);
        self.ubi512.chain_message(input);
        self.ubi512.chain_output(output);
    }
    
    pub fn hash_native(
        &mut self,
        output: &mut [u8],
        input:  &[u8]
    )
    {
        debug_assert!(output.len() == ubi512::NUM_HASH_BYTES);
        self.ubi512.threefish512.key[..NATIVE_INIT.len()].copy_from_slice(&NATIVE_INIT);
        self.ubi512.chain_message(input);
        self.ubi512.chain_native_output(output);
    }
    
    pub fn mac(
        &mut self,
        output: &mut [u8],
        input:  &[u8],
        key:    &[u64]
    )
    {
        debug_assert!(key.len() == tf512::NUM_KEY_WORDS);
        self.ubi512.threefish512.key.fill(0u64);
        self.ubi512.chain_key(key);
        self.ubi512.chain_config({output.len() as u64} * 8);
        self.ubi512.chain_message(input);
        self.ubi512.chain_output(output);
    }
}
