use std::mem::transmute;

use crate::tf512;
use tf512::Threefish512Dynamic;

// The first block is being processed.
pub const TWEAK_FIRST_BIT:  u8 = 0x40u8;
// The first block has already been Processed.
pub const TWEAK_FIRST_MASK: u8 = 0xBFu8;
// The last block is being processeD.
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

pub const NUM_HASH_BYTES: usize = tf512::NUM_BLOCK_BYTES;
pub const NUM_HASH_WORDS: usize = tf512::NUM_BLOCK_WORDS;

/// Exclusive-Or 8 unsigned 64-bit integers.
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

/**
 * Recompute the parity words for the Threefish512 key and tweak,
 * then encipher the input message into the Threefish512 key buffer and
 * XOR the plaintext message into the ciphertext in the Threefish512 key buffer.
 */
macro_rules! rekey_encipher_xor {
    ($ubi:expr) => {
        $ubi.threefish512.rekey();
        $ubi.threefish512.encipher_into_key(&$ubi.msg);
        xor_8_words!($ubi.threefish512.key, $ubi.msg);
    }
}
/// Get a mutable reference to the u8 with the Threefish512 tweak bit flags.
macro_rules! get_tweak_flags_mut {
    ($ubi:expr) => {unsafe {
        let flag = $ubi.threefish512.tweak.get_unchecked_mut(
            tf512::NUM_TWEAK_WORDS - 1
        ) as *mut _ as *mut u8;
        &mut *flag.offset((std::mem::size_of::<u64>() - 1) as isize)
    }}
}
/// Get a mutable reference to the u64 representing the Threefish512 tweak 'position' field.
macro_rules! get_tweak_position_mut {
    ($ubi:expr) => {unsafe {
        $ubi.threefish512.tweak.get_unchecked_mut(0)
    }}
}
/// Get a mutable reference to the u64 representing the 'counter' of the message field.
macro_rules! get_msg_counter_mut {
    ($ubi:expr) => {unsafe {
        $ubi.msg.get_unchecked_mut(0)
    }}
}

macro_rules! initialize_tweak {
    ($ubi:expr, $init_bitwise_or:expr) => {
        $ubi.threefish512.tweak.fill(0u64);
        *get_tweak_flags_mut!($ubi) |= (TWEAK_FIRST_BIT | ($init_bitwise_or));
    }
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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ubi512
{
    pub threefish512: Threefish512Dynamic,
    pub msg:          [u64; NUM_HASH_WORDS],
}

const CONFIG_INIT: [u64; NUM_HASH_WORDS] = [
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
            msg: [0u64; NUM_HASH_WORDS],
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
    pub fn chain_output_native(
        &mut self,
        output: &mut [u8])
    {
        debug_assert!(output.len() == NUM_HASH_BYTES);

        initialize_tweak!(self, TWEAK_LAST_BIT | TYPEMASK_OUT);
        *get_tweak_position_mut!(self) = 8u64.to_le();
        self.msg.fill(0u64);
        rekey_encipher_xor!(self);
        let key_bytes: &[u8] = as_bytes!(&self.threefish512.key, NUM_HASH_WORDS);
        output.copy_from_slice(key_bytes);
    }
    pub fn chain_message(
        &mut self,
        input: &[u8]
    )
    {
        initialize_tweak!(self, TYPEMASK_MSG);
        if input.len() <= NUM_HASH_BYTES {
            *get_tweak_flags_mut!(self)   |= TWEAK_LAST_BIT;
            *get_tweak_position_mut!(self) = {input.len() as u64}.to_le();
            {
                let msg_bytes: &mut [u8] = as_bytes_mut!(&mut self.msg, NUM_HASH_WORDS);
                msg_bytes[..input.len()].copy_from_slice(input);
                if input.len() != NUM_HASH_BYTES {
                    msg_bytes[input.len()..].fill(0u8);
                }
            }
            rekey_encipher_xor!(self);
            return;
        }
        *get_tweak_position_mut!(self) = {NUM_HASH_BYTES as u64}.to_le();
        {
            let msg_bytes: &mut [u8] = as_bytes_mut!(&mut self.msg, NUM_HASH_WORDS);
            msg_bytes.copy_from_slice(&input[..NUM_HASH_BYTES]);
        }
        rekey_encipher_xor!(self);
        *get_tweak_flags_mut!(self) &= TWEAK_FIRST_MASK;

        let mut input_idx = NUM_HASH_BYTES as usize;
        while (input.len() - input_idx) > NUM_HASH_BYTES {
            let next_idx = input_idx + NUM_HASH_BYTES;
            *get_tweak_position_mut!(self) += NUM_HASH_BYTES as u64;
            {
                let msg_bytes: &mut [u8] = as_bytes_mut!(&mut self.msg, NUM_HASH_WORDS);
                msg_bytes.copy_from_slice(&input[input_idx..next_idx]);
            }
            rekey_encipher_xor!(self);
            input_idx = next_idx;
        }
        let bytes_remaining = input.len().saturating_sub(input_idx as usize);
        *get_tweak_flags_mut!(self)    |= TWEAK_LAST_BIT;
        *get_tweak_position_mut!(self) = {
            u64::from_le(*get_tweak_position_mut!(self)) + {bytes_remaining as u64}
        }.to_le();
        {
            let msg_bytes: &mut [u8] = as_bytes_mut!(&mut self.msg, NUM_HASH_WORDS);
            msg_bytes[..bytes_remaining].copy_from_slice(&input[input_idx..]);
            if bytes_remaining != NUM_HASH_BYTES {
                msg_bytes[bytes_remaining..].fill(0u8);
            }
        }
        rekey_encipher_xor!(self);
    }// ~ chain_message()
    pub fn chain_output(
        &mut self,
        output: &mut [u8]
    )
    {
        initialize_tweak!(self, TYPEMASK_OUT);
        self.msg.fill(0u64);
        *get_tweak_position_mut!(self) = 8u64;
        if output.len() <= tf512::NUM_KEY_BYTES {
            *get_tweak_flags_mut!(self) |= TWEAK_LAST_BIT;
            rekey_encipher_xor!(self);
            let key_bytes: &[u8] = as_bytes!(&self.threefish512.key, tf512::NUM_KEY_WORDS);
            output.copy_from_slice(&key_bytes[..output.len()]);
            return;
        }
        rekey_encipher_xor!(self);
        *get_tweak_flags_mut!(self) &= TWEAK_FIRST_MASK;
        {
            let key_bytes: &[u8] = as_bytes!(&self.threefish512.key, tf512::NUM_KEY_WORDS);
            output[..tf512::NUM_KEY_BYTES].copy_from_slice(&key_bytes);
        }
        *get_msg_counter_mut!(self) = {
            u64::from_le(*get_msg_counter_mut!(self)) + 1u64
        }.to_le();
        let mut output_idx = tf512::NUM_KEY_BYTES;
        while (output.len() - output_idx) > tf512::NUM_KEY_BYTES {
            let next_idx = output_idx + tf512::NUM_KEY_BYTES;
            *get_tweak_position_mut!(self) = {
                u64::from_le(*get_tweak_position_mut!(self)) + {std::mem::size_of::<u64>() as u64}
            }.to_le();
            rekey_encipher_xor!(self);
            {
                let key_bytes: &[u8] = as_bytes!(&self.threefish512.key, tf512::NUM_KEY_WORDS);
                output[output_idx..next_idx].copy_from_slice(&key_bytes);
            }
            *get_msg_counter_mut!(self) = {
                u64::from_le(*get_msg_counter_mut!(self)) + 1u64
            }.to_le();
            output_idx = next_idx;
        }
        *get_tweak_flags_mut!(self) |= TWEAK_LAST_BIT;
        *get_tweak_position_mut!(self) = {
            u64::from_le(*get_tweak_position_mut!(self)) + {std::mem::size_of::<u64>() as u64}
        }.to_le();
        rekey_encipher_xor!(self);
        let key_bytes: &[u8] = as_bytes!(&self.threefish512.key, tf512::NUM_KEY_WORDS);
        let bytes_remaining = output.len().saturating_sub(output_idx as usize);
        output[output_idx..].copy_from_slice(&key_bytes[..bytes_remaining]);
    }// ~ chain_output()
    pub fn chain_key_u8(
        &mut self,
        key: &[u8])
    {
        initialize_tweak!(self, TYPEMASK_KEY | TWEAK_LAST_BIT);
        *get_tweak_position_mut!(self) = {tf512::NUM_BLOCK_BYTES as u64}.to_le();
        unsafe {
            std::slice::from_raw_parts_mut(&mut self.msg as *mut _ as *mut u8, NUM_HASH_BYTES)
        }.copy_from_slice(key);
        rekey_encipher_xor!(self);
    }// ~ chain_key()
    pub fn chain_key_u64(
        &mut self,
        key: &[u64])
    {
        initialize_tweak!(self, TYPEMASK_KEY | TWEAK_LAST_BIT);
        *get_tweak_position_mut!(self) = {tf512::NUM_BLOCK_BYTES as u64}.to_le();
        self.msg.copy_from_slice(key);
        rekey_encipher_xor!(self);
    }// ~ chain_key()
}
