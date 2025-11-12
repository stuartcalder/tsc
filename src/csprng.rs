/* *
 * tsc - Implement Threefish, Skein, and CATENA cryptographic algorithms.
 * Copyright (C) 2025 Stuart Calder
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

use crate::ubi512;
use crate::skein512;

use rssc::op::{SSC_secureZero, secure_zero, c_void};
use rssc::rand::get_entropy;
use skein512::Skein512;
use skein512::NUM_HASH_WORDS;

pub const NUM_SEED_BYTES:   usize = ubi512::NUM_HASH_BYTES;
pub const NUM_BUFFER_BYTES: usize = NUM_SEED_BYTES * 2;

#[repr(C)]
#[derive(Clone)]
pub struct Csprng {
    pub skein512: Skein512,
    pub buffer:   [u8; NUM_BUFFER_BYTES],
    pub seed:     [u8; NUM_SEED_BYTES],
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

const SKEIN_CFG_INIT: &[u64; NUM_HASH_WORDS] = &skein512::OUTPUT_16_WORDS_INIT;

macro_rules! skein_hash_pre_configured {
    ($skein:expr, $out:expr, $in:expr) => {{
        $skein.ubi512.threefish512.key[..NUM_HASH_WORDS].copy_from_slice(SKEIN_CFG_INIT);
        $skein.ubi512.chain_message($in);
        $skein.ubi512.chain_output($out);
    }}
}

impl Csprng {
    /// Create and return a new Csprng object. Initialize its @seed field with entropy from the OS.
    pub fn new() -> Csprng
    {
        let mut csprng = Csprng {
            skein512: Skein512::new(),
            buffer:   [0u8; NUM_BUFFER_BYTES],
            seed:     [0u8; NUM_SEED_BYTES]
        };
        get_entropy(&mut csprng.seed);
        csprng
    }
    /// Reseed the Csprng with the u8 bytes of @material.
    pub fn reseed_from_bytes(
        &mut self,
        material: &[u8])
    {
        debug_assert!(material.len() == NUM_SEED_BYTES, "material must be {} large but it was {}!", NUM_SEED_BYTES, material.len());
        self.buffer[..NUM_SEED_BYTES].copy_from_slice(&self.seed);
        self.buffer[NUM_SEED_BYTES..].copy_from_slice(material);
        self.skein512.hash_native(&mut self.seed, &self.buffer);
        secure_zero(&mut self.buffer);
    }
    /// Reseed the Csprng with bytes from the OS.
    pub fn reseed_from_os(&mut self)
    {
        self.buffer[..NUM_SEED_BYTES].copy_from_slice(&self.seed);
        get_entropy(&mut self.buffer[NUM_SEED_BYTES..]);
        self.skein512.hash_native(&mut self.seed, &self.buffer);
        secure_zero(&mut self.buffer);
    }
    /// Overwrite all the bytes of the slice @output with pseudorandom
    /// output bytes from the Csprng.
    pub fn get_bytes(&mut self, output: &mut[u8])
    {
        if output.len() == 0 {
            return;
        }
        let mut out = &mut output[..];
        while out.len() > NUM_SEED_BYTES {
            skein_hash_pre_configured!(self.skein512, &mut self.buffer, &self.seed);
            self.seed.copy_from_slice(&self.buffer[..NUM_SEED_BYTES]);
            out[..NUM_SEED_BYTES].copy_from_slice(&self.buffer[NUM_SEED_BYTES..]);

            out = &mut out[NUM_SEED_BYTES..];
        }
        let end_idx = NUM_SEED_BYTES + out.len(); // Stop here on the last write to @out.
        skein_hash_pre_configured!(self.skein512, &mut self.buffer, &self.seed);
        self.seed.copy_from_slice(&self.buffer[..NUM_SEED_BYTES]);
        out.copy_from_slice(&self.buffer[NUM_SEED_BYTES..end_idx]);
        secure_zero(&mut self.buffer);
    }
    /// Generate a pseudorandom u64.
    pub fn get_random_u64(&mut self) -> u64
    {
        let mut bytes = [0u8; 8];
        self.get_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }
    /// Generate a pseudorandom natural number between 0u64 and @max.
    pub fn get_random_natural_num(&mut self, max: u64) -> u64
    {
        if max == 0u64 {
            return 0u64
        }
        // r = 2^64 % max, computed without 128-bit math.
        // In unsigned arithmetic, 0u64.wrapping_sub(max) == 2^64 - max.
        // Then (2^64 - max) % max == 2^64 % max.
        let r = (0u64.wrapping_sub(max)) % max;
        loop {
            // Accept if x < 2^64 - r. Using 64-bit values: x <= u64::MAX - r.
            let x = self.get_random_u64();
            if r == 0 || x <= u64::MAX - r {
                return x % max;
            }
            // Otherwise reject and retry.
        }
    }
    /// Generate a pseudorandom u64 within the range @range.0 and @range.1
    pub fn get_random_u64_in_range(&mut self, range: (u64, u64)) -> u64
    {
        debug_assert!(range.0 <= range.1);
        range.0 + self.get_random_natural_num(range.1 - range.0)
    }
}
