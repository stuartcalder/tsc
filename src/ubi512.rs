use std::mem::transmute;

use crate::tf512;
use tf512::{Threefish512,Threefish512Dynamic};

// The first block is being processed.
pub const TWEAK_FIRST_BIT:  u8 = 0x40u8;
// The first block has already been processed.
pub const TWEAK_FIRST_MASK: u8 = 0xbfu8;
// The last block is being processed.
pub const TWEAK_LAST_BIT:   u8 = 0x80u8;

// A key is being processed.
pub const TYPEMASK_KEY: u8 = 0u8;
pub const TYPEMASK_CFG: u8 = 4u8;
pub const TYPEMASK_PRS: u8 = 8u8;
pub const TYPEMASK_PK : u8 = 12u8;
pub const TYPEMASK_KDF: u8 = 16u8;
pub const TYPEMASK_NON: u8 = 20u8;
pub const TYPEMASK_MSG: u8 = 48u8;
pub const TYPEMASK_OUT: u8 = 63u8;

macro_rules! xor_8_words {
    ($dest:expr, $src:expr) => {unsafe {
        *$dest.get_unchecked_mut(0) ^= *$src.get_unchecked_mut(0);
        *$dest.get_unchecked_mut(1) ^= *$src.get_unchecked_mut(1);
        *$dest.get_unchecked_mut(2) ^= *$src.get_unchecked_mut(2);
        *$dest.get_unchecked_mut(3) ^= *$src.get_unchecked_mut(3);
        *$dest.get_unchecked_mut(4) ^= *$src.get_unchecked_mut(4);
        *$dest.get_unchecked_mut(5) ^= *$src.get_unchecked_mut(5);
        *$dest.get_unchecked_mut(6) ^= *$src.get_unchecked_mut(6);
        *$dest.get_unchecked_mut(7) ^= *$src.get_unchecked_mut(7);
    }}
}

macro_rules! rekey_encipher_xor {
    ($ubi:expr) => {
        $ubi.threefish512.rekey();
        $ubi.threefish512.encipher_into_key(&$ubi.msg);
        xor_8_words!($ubi.threefish512.key, $ubi.msg);
    }
}

macro_rules! get_tweak_flags_mut {
    ($ubi:expr) => {unsafe {
        let flag = $ubi.threefish512.tweak.get_unchecked_mut(
            tf512::NUM_TWEAK_WORDS - 1
        ) as *mut _ as *mut u8;
        &mut *flag.offset((std::mem::size_of::<u64>() - 1) as isize)
    }}
}

macro_rules! get_tweak_position_mut {
    ($ubi:expr) => {unsafe {
        $ubi.threefish512.tweak.get_unchecked_mut(0)
    }}
}

macro_rules! initialize_tweak {
    ($ubi:expr, $init_bitwise_or:expr) => {
        $ubi.threefish512.tweak.fill(0u64);
        *get_tweak_flags_mut!($ubi) |= (TWEAK_FIRST_BIT | ($init_bitwise_or));
    }
}

pub struct Ubi512
{
    threefish512: Threefish512Dynamic,
    msg:          [u64; tf512::NUM_BLOCK_WORDS],
}

const CONFIG_INIT: [u64; tf512::NUM_BLOCK_WORDS] = [
    0x5348413301000000u64.to_be(), 0u64, 0u64, 0u64,
    0u64                         , 0u64, 0u64, 0u64
];

impl Ubi512
{
    pub fn new() -> Ubi512 {
        Ubi512 {
            threefish512: Threefish512Dynamic::new(
                [0u64; tf512::NUM_KEY_WORDS_WITH_PARITY],
                [0u64; tf512::NUM_TWEAK_WORDS_WITH_PARITY]
            ),
            msg:   [0u64; tf512::NUM_BLOCK_WORDS],
        }
    }
    pub fn chain_config(
        &mut self,
        num_output_bits: u64)
    {
        initialize_tweak!(self, TWEAK_LAST_BIT | TYPEMASK_CFG);
        *get_tweak_position_mut!(self) = 32u64.to_le();
        self.msg = CONFIG_INIT.clone();
        self.msg[1] = num_output_bits.to_le();
        rekey_encipher_xor!(self);
    }
    pub fn chain_native_output(
        &mut self,
        output: &mut [u8])
    {
        debug_assert!(output.len() == tf512::NUM_BLOCK_BYTES);

        initialize_tweak!(self, TWEAK_LAST_BIT | TYPEMASK_OUT);
        *get_tweak_position_mut!(self) = 8u64.to_le();
        self.msg.fill(0u64);
        rekey_encipher_xor!(self);
        let key_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                &self.threefish512.key as *const _ as *const u8,
                std::mem::size_of::<u64>() * tf512::NUM_KEY_WORDS
            )
        };
        output.copy_from_slice(key_bytes);
    }
}
