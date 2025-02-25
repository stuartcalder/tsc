use crate::tf512;
use crate::ubi512;
use ubi512::Ubi512;

pub use ubi512::{NUM_HASH_BYTES, NUM_HASH_WORDS};

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Skein512 {
    pub ubi512: Ubi512
}

pub const NATIVE_INIT: [u64; 8] = [
    0xCE519C74FFAD0349u64.to_be(),
    0x03DF469739DE950Du64.to_be(),
    0xCE9BC7274193D18Fu64.to_be(),
    0xB12C35FF2956259Au64.to_be(),
    0xB0A76CDF9925B65Du64.to_be(),
    0xF4C3D5A94C39BEEAu64.to_be(),
    0x23B5751AC7121199u64.to_be(),
    0x33CC0F660BA418AEu64.to_be(),
];

pub const OUTPUT_16_WORDS_INIT: [u64; 8] = [
    0x545E7A4C7832AFDBu64.to_be(),
    0xC7AB18D287D9E62Du64.to_be(),
    0x4108903ACBA9A3AEu64.to_be(),
    0x3108C7E40E0E55A0u64.to_be(),
    0xC39CA85D6CD24671u64.to_be(),
    0xBA1B586631A3FD33u64.to_be(),
    0x876983543C179302u64.to_be(),
    0xD759946100B8B807u64.to_be(),
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
        input:  &[u8])
    {
        self.ubi512.threefish512.key.fill(0u64);
        self.ubi512.chain_config({output.len() as u64} * 8u64);
        self.ubi512.chain_message(input);
        self.ubi512.chain_output(output);
    }
    
    pub fn hash_native(
        &mut self,
        output: &mut [u8],
        input:  &[u8])
    {
        debug_assert!(output.len() == ubi512::NUM_HASH_BYTES);
        self.ubi512.threefish512.key[..NATIVE_INIT.len()].copy_from_slice(&NATIVE_INIT);
        self.ubi512.chain_message(input);
        self.ubi512.chain_output_native(output);
    }
    
    pub fn mac(
        &mut self,
        output: &mut [u8],
        input:  &[u8],
        key:    &[u64])
    {
        debug_assert!(key.len()    == tf512::NUM_KEY_WORDS);
        debug_assert!(output.len() == tf512::NUM_KEY_BYTES);
        self.ubi512.threefish512.key.fill(0u64);
        self.ubi512.chain_key_u64(key);
        self.ubi512.chain_config({output.len() as u64} * 8);
        self.ubi512.chain_message(input);
        self.ubi512.chain_output(output);
    }
}
