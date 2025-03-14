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

use crate::tf512;
use crate::ubi512;
use crate::skein512;

use rssc::op::{SSC_secureZero, secure_zero, c_void};
use rssc::rand::get_entropy;
use skein512::Skein512;
use skein512::{NUM_HASH_BYTES, NUM_HASH_WORDS};

pub const NUM_SEED_BYTES:   usize = ubi512::NUM_HASH_BYTES;
pub const NUM_BUFFER_BYTES: usize = NUM_SEED_BYTES * 2;

#[repr(C)]
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

macro_rules! skein_hash_pre_configed {
    ($skein:expr, $out:expr, $in:expr) => {{
        $skein.ubi512.threefish512.key[..NUM_HASH_WORDS].copy_from_slice(SKEIN_CFG_INIT);
        $skein.ubi512.chain_message($in);
        $skein.ubi512.chain_output($out);
    }}
}

impl Csprng {
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
    pub fn get_bytes(
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
    pub fn get_random_natural_num(&mut self, max: u64) -> u64
    {
        let num_sections = max + 1;
        let local_limit  = u64::MAX - (u64::MAX % num_sections);
        let quanta_per_section = local_limit / num_sections;
    
        let mut bytes = [0u8; 8];
        self.get_bytes(&mut bytes);
        let rand_u64 = u64::from_le_bytes(bytes);
        let offset = if rand_u64 < local_limit {
            let rounded_down = rand_u64 - (rand_u64 % quanta_per_section);
            rounded_down / quanta_per_section
        } else {
            num_sections - 1
        };
        offset
    }
    pub fn get_random_u64_in_range(&mut self, range: (u64, u64)) -> u64
    {
        debug_assert!(range.0 <= range.1);
        range.0 + self.get_random_natural_num(range.1 - range.0)
    }
}
