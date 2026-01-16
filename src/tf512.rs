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

pub const NUM_BLOCK_BITS: usize  = 512;
pub const NUM_BLOCK_BYTES: usize = 64;
pub const NUM_BLOCK_WORDS: usize = 8;

pub const NUM_KEY_BITS: usize  = NUM_BLOCK_BITS;
pub const NUM_KEY_BYTES: usize = NUM_BLOCK_BYTES;
pub const NUM_KEY_WORDS: usize = NUM_BLOCK_WORDS;

pub const NUM_TWEAK_BITS: usize  = 128;
pub const NUM_TWEAK_BYTES: usize = 16;
pub const NUM_TWEAK_WORDS: usize = 2;

pub const NUM_ROUNDS: usize  = 72;
pub const NUM_SUBKEYS: usize = 19;
pub const NUM_KEY_WORDS_WITH_PARITY: usize   = NUM_KEY_WORDS   + 1;
pub const NUM_TWEAK_WORDS_WITH_PARITY: usize = NUM_TWEAK_WORDS + 1;

/**
 * CONST_240 is the constant provided by the Threefish512 specification that is to be
 * bitwise XOR'd with the 8 u64 words of the input key.
 * Instead of swapping the endianness of all those u64's and XORing with CONST_240,
 * swap the bytes of CONST_240 itself when the target is big endian.
 */
pub const CONST_240: u64 = 0x1BD11BDAA9FC1A22u64.to_le();
pub const NUM_CTR_IV_BYTES: usize = 32;
pub const NUM_CTR_IV_WORDS: usize = 4;

pub const OCBT_DOMAIN_AD_CRYPT: u64      = 0b00u64; /// Ciphering the additional data.
pub const OCBT_DOMAIN_AD_FINALIZE: u64   = 0b01u64; /// Ciphering the final additional data block.
pub const OCBT_DOMAIN_DATA_CRYPT: u64    = 0b10u64; /// Ciphering the payload.
pub const OCBT_DOMAIN_DATA_FINALIZE: u64 = 0b11u64; /// Ciphering the final payload block.
pub const OCBT_DOMAIN_MASK: u64          = 0xfffffffffffffff3u64; /// All bits EXCEPT the domain bits.

macro_rules! store_word {
    ($key_schedule:expr,
     $key_words:expr,
     $subkey_num:literal,
     $subkey_idx:literal,
     $increment:expr) =>
     {{
        const KEY_SCHEDULE_IDX: usize = ($subkey_num * NUM_KEY_WORDS) + $subkey_idx;
        const KEY_WORD_IDX: usize     = ($subkey_num + $subkey_idx) % NUM_KEY_WORDS_WITH_PARITY;
        $key_schedule[KEY_SCHEDULE_IDX] = u64::from_le($key_words[KEY_WORD_IDX]).wrapping_add($increment).to_le();
     }}
}
macro_rules! make_subkey {
    ($key_schedule:expr,
     $key_words:expr,
     $tweak_words:expr,
     $subkey_num:literal) =>
     {{
        store_word!($key_schedule, $key_words, $subkey_num, 0usize, 0u64);
        store_word!($key_schedule, $key_words, $subkey_num, 1usize, 0u64);
        store_word!($key_schedule, $key_words, $subkey_num, 2usize, 0u64);
        store_word!($key_schedule, $key_words, $subkey_num, 3usize, 0u64);
        store_word!($key_schedule, $key_words, $subkey_num, 4usize, 0u64);
        let increment: u64 = $tweak_words[$subkey_num % 3];
        store_word!($key_schedule, $key_words, $subkey_num, 5usize, increment);
        let increment: u64 = $tweak_words[($subkey_num + 1) % 3];
        store_word!($key_schedule, $key_words, $subkey_num, 6usize, increment);
        store_word!($key_schedule, $key_words, $subkey_num, 7usize, $subkey_num as u64);
    }}
}
macro_rules! do_mix {
    ($state_words:expr,
     $state_idx:literal,
     $rot_const:literal) =>
     {{
        const W0: usize = $state_idx * 2;
        const W1: usize = W0 + 1;
        let mut w0: u64 = u64::from_le($state_words[W0]);
        let     w1: u64 = u64::from_le($state_words[W1]);
        w0 = w0.wrapping_add(w1);
        $state_words[W0] = w0.to_le();
        $state_words[W1] = (w1.rotate_left($rot_const) ^ w0).to_le();
     }}
}
macro_rules! subkey_idx    { ($round_num:literal) => ($round_num / 4usize) }
macro_rules! subkey_offset { ($round_num:literal) => (subkey_idx!($round_num) * NUM_BLOCK_WORDS) }
macro_rules! use_subkey_static {
    ($key_schedule_words:expr,
     $state_words:expr,
     $operation:tt,
     $round_num:literal) =>
    {{
        let state:  u64 = u64::from_le($state_words[0]);
        let keysch: u64 = u64::from_le($key_schedule_words[subkey_offset!($round_num)]);
        $state_words[0] = state.wrapping_add(keysch).to_le();

        let state:  u64 = u64::from_le($state_words[1]);
        let keysch: u64 = u64::from_le($key_schedule_words[subkey_offset!($round_num) + 1]);
        $state_words[1] = state.wrapping_add(keysch).to_le();

        let state:  u64 = u64::from_le($state_words[2]);
        let keysch: u64 = u64::from_le($key_schedule_words[subkey_offset!($round_num) + 2]);
        $state_words[2] = state.wrapping_add(keysch).to_le();

        let state:  u64 = u64::from_le($state_words[3]);
        let keysch: u64 = u64::from_le($key_schedule_words[subkey_offset!($round_num) + 3]);
        $state_words[3] = state.wrapping_add(keysch).to_le();

        let state:  u64 = u64::from_le($state_words[4]);
        let keysch: u64 = u64::from_le($key_schedule_words[subkey_offset!($round_num) + 4]);
        $state_words[4] = state.wrapping_add(keysch).to_le();

        let state:  u64 = u64::from_le($state_words[5]);
        let keysch: u64 = u64::from_le($key_schedule_words[subkey_offset!($round_num) + 5]);
        $state_words[5] = state.wrapping_add(keysch).to_le();

        let state:  u64 = u64::from_le($state_words[6]);
        let keysch: u64 = u64::from_le($key_schedule_words[subkey_offset!($round_num) + 6]);
        $state_words[6] = state.wrapping_add(keysch).to_le();

        let state:  u64 = u64::from_le($state_words[7]);
        let keysch: u64 = u64::from_le($key_schedule_words[subkey_offset!($round_num) + 7]);
        $state_words[7] = state.wrapping_add(keysch).to_le();
    }}
}
//FIXME: Changed use_subkey_static!() to use wrapping_add() for all arithmetic. Rethink how this
//works.
macro_rules! add_subkey_static {
    ($key_schedule_words:expr, $state_words:expr, $round_num:literal) =>
    {
        use_subkey_static!($key_schedule_words, $state_words, +, $round_num);
    }
}

#[allow(unused)]
macro_rules! subtract_subkey_static {
    ($key_schedule_words:expr, $state_words:expr, $round_num:literal) =>
    {
        use_subkey_static!($key_schedule_words, $state_words, -, $round_num);
    }
}
macro_rules! add_subkey_dynamic {
    ($key_words:expr,
     $state_words:expr,
     $tweak_words:expr,
     $round_num:literal) =>
    {{
        const SUBKEY_IDX: usize = subkey_idx!($round_num);

        let s = u64::from_le($state_words[0]);
        let k = u64::from_le(unsafe{ *$key_words.get_unchecked_mut(SUBKEY_IDX % NUM_KEY_WORDS_WITH_PARITY) });
        $state_words[0] = s.wrapping_add(k).to_le();

        let s = u64::from_le($state_words[1]);
        let k = u64::from_le(unsafe{ *$key_words.get_unchecked_mut((SUBKEY_IDX + 1) % NUM_KEY_WORDS_WITH_PARITY) });
        $state_words[1] = s.wrapping_add(k).to_le();

        let s = u64::from_le($state_words[2]);
        let k = u64::from_le(unsafe{ *$key_words.get_unchecked_mut((SUBKEY_IDX + 2) % NUM_KEY_WORDS_WITH_PARITY) });
        $state_words[2] = s.wrapping_add(k).to_le();

        let s = u64::from_le($state_words[3]);
        let k = u64::from_le(unsafe{ *$key_words.get_unchecked_mut((SUBKEY_IDX + 3) % NUM_KEY_WORDS_WITH_PARITY) });
        $state_words[3] = s.wrapping_add(k).to_le();

        let s = u64::from_le($state_words[4]);
        let k = u64::from_le(unsafe{ *$key_words.get_unchecked_mut((SUBKEY_IDX + 4) % NUM_KEY_WORDS_WITH_PARITY) });
        $state_words[4] = s.wrapping_add(k).to_le();

        let s = u64::from_le($state_words[5]);
        let k = u64::from_le(unsafe{ *$key_words.get_unchecked_mut((SUBKEY_IDX + 5) % NUM_KEY_WORDS_WITH_PARITY) });
        let t = u64::from_le(unsafe{ *$tweak_words.get_unchecked_mut(SUBKEY_IDX % 3) });
        $state_words[5] = s.wrapping_add(k.wrapping_add(t)).to_le();

        let s = u64::from_le($state_words[6]);
        let k = u64::from_le(unsafe{ *$key_words.get_unchecked_mut((SUBKEY_IDX + 6) % NUM_KEY_WORDS_WITH_PARITY) });
        let t = u64::from_le(unsafe{ *$tweak_words.get_unchecked_mut((SUBKEY_IDX + 1) % 3) });
        $state_words[6] = s.wrapping_add(k.wrapping_add(t)).to_le();

        let s = u64::from_le($state_words[7]);
        let k = u64::from_le(unsafe{ *$key_words.get_unchecked_mut((SUBKEY_IDX + 7) % NUM_KEY_WORDS_WITH_PARITY) });
        $state_words[7] = s.wrapping_add(k.wrapping_add(SUBKEY_IDX as u64)).to_le();
    }}
}
macro_rules! permute {
    ($state_words:expr) =>
    {{
        let mut w0: u64;
        let     w1: u64;
        unsafe
        {
            w0 = *$state_words.get_unchecked_mut(6);
            *$state_words.get_unchecked_mut(6) = *$state_words.get_unchecked_mut(0);
            w1 = *$state_words.get_unchecked_mut(4);
            *$state_words.get_unchecked_mut(4) = w0;
            w0 = *$state_words.get_unchecked_mut(2);
            *$state_words.get_unchecked_mut(2) = w1;
            *$state_words.get_unchecked_mut(0) = w0;
            w0 = *$state_words.get_unchecked_mut(3);
            *$state_words.get_unchecked_mut(3) = *$state_words.get_unchecked_mut(7);
            *$state_words.get_unchecked_mut(7) = w0;
        }
    }}
}
macro_rules! mix4_permute {
    ($state_words:expr,
     $rotate_const_0:literal,
     $rotate_const_1:literal,
     $rotate_const_2:literal,
     $rotate_const_3:literal) =>
    {{
        do_mix!($state_words, 0usize, $rotate_const_0);
        do_mix!($state_words, 1usize, $rotate_const_1);
        do_mix!($state_words, 2usize, $rotate_const_2);
        do_mix!($state_words, 3usize, $rotate_const_3);
        permute!($state_words);
    }}
}
macro_rules! encrypt_round_static {
    ($key_schedule_words:expr,
     $state_words:expr,
     $round_start:literal,
     $rc0_0:literal, $rc0_1:literal, $rc0_2:literal, $rc0_3:literal,
     $rc1_0:literal, $rc1_1:literal, $rc1_2:literal, $rc1_3:literal,
     $rc2_0:literal, $rc2_1:literal, $rc2_2:literal, $rc2_3:literal,
     $rc3_0:literal, $rc3_1:literal, $rc3_2:literal, $rc3_3:literal) =>
    {{
        add_subkey_static!($key_schedule_words, $state_words, $round_start);
        mix4_permute!($state_words, $rc0_0, $rc0_1, $rc0_2, $rc0_3);
        mix4_permute!($state_words, $rc1_0, $rc1_1, $rc1_2, $rc1_3);
        mix4_permute!($state_words, $rc2_0, $rc2_1, $rc2_2, $rc2_3);
        mix4_permute!($state_words, $rc3_0, $rc3_1, $rc3_2, $rc3_3);
    }}
}
macro_rules! encrypt_round_dynamic {
    ($key_words:expr,
     $state_words:expr,
     $tweak_words:expr,
     $round_start:literal,
     $rc0_0:literal, $rc0_1:literal, $rc0_2:literal, $rc0_3:literal,
     $rc1_0:literal, $rc1_1:literal, $rc1_2:literal, $rc1_3:literal,
     $rc2_0:literal, $rc2_1:literal, $rc2_2:literal, $rc2_3:literal,
     $rc3_0:literal, $rc3_1:literal, $rc3_2:literal, $rc3_3:literal) =>
    {{
        add_subkey_dynamic!($key_words, $state_words, $tweak_words, $round_start);
        mix4_permute!($state_words, $rc0_0, $rc0_1, $rc0_2, $rc0_3);
        mix4_permute!($state_words, $rc1_0, $rc1_1, $rc1_2, $rc1_3);
        mix4_permute!($state_words, $rc2_0, $rc2_1, $rc2_2, $rc2_3);
        mix4_permute!($state_words, $rc3_0, $rc3_1, $rc3_2, $rc3_3);
    }}
}
macro_rules! encrypt_static_phase_0 {
    ($key_schedule_words:expr,
     $state_words:expr,
     $round_start:literal) =>
    {
        encrypt_round_static!(
            $key_schedule_words,
            $state_words,
            $round_start,
            46, 36, 19, 37,
            33, 27, 14, 42,
            17, 49, 36, 39,
            44,  9, 54, 56
        );
    }
}
macro_rules! encrypt_dynamic_phase_0 {
    ($key_words:expr,
     $state_words:expr,
     $tweak_words:expr,
     $round_start:literal) =>
    {
        encrypt_round_dynamic!(
            $key_words,
            $state_words,
            $tweak_words,
            $round_start,
            46, 36, 19, 37,
            33, 27, 14, 42,
            17, 49, 36, 39,
            44,  9, 54, 56
        );
    }
}
macro_rules! encrypt_static_phase_1 {
    ($key_schedule_words:expr,
     $state_words:expr,
     $round_start:literal) =>
    {
        encrypt_round_static!(
            $key_schedule_words,
            $state_words,
            $round_start,
            39, 30, 34, 24,
            13, 50, 10, 17,
            25, 29, 39, 43,
             8, 35, 56, 22
        );
    }
}
macro_rules! encrypt_dynamic_phase_1 {
    ($key_words:expr,
     $state_words:expr,
     $tweak_words:expr,
     $round_start:literal) =>
    {
        encrypt_round_dynamic!(
            $key_words,
            $state_words,
            $tweak_words,
            $round_start,
            39, 30, 34, 24,
            13, 50, 10, 17,
            25, 29, 39, 43,
             8, 35, 56, 22
        );
    }
}
macro_rules! encrypt_static {
    ($static:expr) => {
        encrypt_static_phase_0!($static.key_schedule, $static.state,  0);
        encrypt_static_phase_1!($static.key_schedule, $static.state,  4);
        encrypt_static_phase_0!($static.key_schedule, $static.state,  8);
        encrypt_static_phase_1!($static.key_schedule, $static.state, 12);
        encrypt_static_phase_0!($static.key_schedule, $static.state, 16);
        encrypt_static_phase_1!($static.key_schedule, $static.state, 20);
        encrypt_static_phase_0!($static.key_schedule, $static.state, 24);
        encrypt_static_phase_1!($static.key_schedule, $static.state, 28);
        encrypt_static_phase_0!($static.key_schedule, $static.state, 32);
        encrypt_static_phase_1!($static.key_schedule, $static.state, 36);
        encrypt_static_phase_0!($static.key_schedule, $static.state, 40);
        encrypt_static_phase_1!($static.key_schedule, $static.state, 44);
        encrypt_static_phase_0!($static.key_schedule, $static.state, 48);
        encrypt_static_phase_1!($static.key_schedule, $static.state, 52);
        encrypt_static_phase_0!($static.key_schedule, $static.state, 56);
        encrypt_static_phase_1!($static.key_schedule, $static.state, 60);
        encrypt_static_phase_0!($static.key_schedule, $static.state, 64);
        encrypt_static_phase_1!($static.key_schedule, $static.state, 68);
        add_subkey_static!($static.key_schedule, $static.state, 72);
    }
}
macro_rules! encrypt_dynamic {
    ($dynamic:expr) => {
        encrypt_dynamic_phase_0!($dynamic.key, $dynamic.state, $dynamic.tweak,  0);
        encrypt_dynamic_phase_1!($dynamic.key, $dynamic.state, $dynamic.tweak,  4);
        encrypt_dynamic_phase_0!($dynamic.key, $dynamic.state, $dynamic.tweak,  8);
        encrypt_dynamic_phase_1!($dynamic.key, $dynamic.state, $dynamic.tweak, 12);
        encrypt_dynamic_phase_0!($dynamic.key, $dynamic.state, $dynamic.tweak, 16);
        encrypt_dynamic_phase_1!($dynamic.key, $dynamic.state, $dynamic.tweak, 20);
        encrypt_dynamic_phase_0!($dynamic.key, $dynamic.state, $dynamic.tweak, 24);
        encrypt_dynamic_phase_1!($dynamic.key, $dynamic.state, $dynamic.tweak, 28);
        encrypt_dynamic_phase_0!($dynamic.key, $dynamic.state, $dynamic.tweak, 32);
        encrypt_dynamic_phase_1!($dynamic.key, $dynamic.state, $dynamic.tweak, 36);
        encrypt_dynamic_phase_0!($dynamic.key, $dynamic.state, $dynamic.tweak, 40);
        encrypt_dynamic_phase_1!($dynamic.key, $dynamic.state, $dynamic.tweak, 44);
        encrypt_dynamic_phase_0!($dynamic.key, $dynamic.state, $dynamic.tweak, 48);
        encrypt_dynamic_phase_1!($dynamic.key, $dynamic.state, $dynamic.tweak, 52);
        encrypt_dynamic_phase_0!($dynamic.key, $dynamic.state, $dynamic.tweak, 56);
        encrypt_dynamic_phase_1!($dynamic.key, $dynamic.state, $dynamic.tweak, 60);
        encrypt_dynamic_phase_0!($dynamic.key, $dynamic.state, $dynamic.tweak, 64);
        encrypt_dynamic_phase_1!($dynamic.key, $dynamic.state, $dynamic.tweak, 68);
        add_subkey_dynamic!($dynamic.key, $dynamic.state, $dynamic.tweak, 72);
    }
}
macro_rules! xor_8 {
    ($into:expr, $from:expr) => { unsafe {
        *$into.get_unchecked_mut(0) ^= *$from.get_unchecked(0);
        *$into.get_unchecked_mut(1) ^= *$from.get_unchecked(1);
        *$into.get_unchecked_mut(2) ^= *$from.get_unchecked(2);
        *$into.get_unchecked_mut(3) ^= *$from.get_unchecked(3);
        *$into.get_unchecked_mut(4) ^= *$from.get_unchecked(4);
        *$into.get_unchecked_mut(5) ^= *$from.get_unchecked(5);
        *$into.get_unchecked_mut(6) ^= *$from.get_unchecked(6);
        *$into.get_unchecked_mut(7) ^= *$from.get_unchecked(7);
    }}
}
macro_rules! xor_64 {
    ($into:expr, $from:expr) => {
        xor_8!($into, $from);
        $into = &mut $into[8..];
        $from = &$from[8..];
        xor_8!($into, $from);
        $into = &mut $into[8..];
        $from = &$from[8..];
        xor_8!($into, $from);
        $into = &mut $into[8..];
        $from = &$from[8..];
        xor_8!($into, $from);
        $into = &mut $into[8..];
        $from = &$from[8..];
        xor_8!($into, $from);
        $into = &mut $into[8..];
        $from = &$from[8..];
        xor_8!($into, $from);
        $into = &mut $into[8..];
        $from = &$from[8..];
        xor_8!($into, $from);
        $into = &mut $into[8..];
        $from = &$from[8..];
        xor_8!($into, $from);
        /* We do not increment the $into or $from slices on the last XOR to avoid unused assignment warnings.
         * Consider whether incrementing either slice is appropriate at the macro invocation site.
         */
    }
}

fn compute_tweak_parity_word(tweak: &mut [u64])
{
    debug_assert!(tweak.len() >= NUM_TWEAK_WORDS_WITH_PARITY);
    unsafe {
        *tweak.get_unchecked_mut(NUM_TWEAK_WORDS) = {
            // Accumulate the xor of the two tweak words.
            *tweak.get_unchecked_mut(0) ^ *tweak.get_unchecked_mut(1)
        };
    }
}

fn compute_key_parity_word(key: &mut [u64])
{
    debug_assert!(key.len() >= NUM_KEY_WORDS_WITH_PARITY);
    unsafe {
        *key.get_unchecked_mut(NUM_KEY_WORDS) = {
            // Accumulate the xor of all the key words together.
            *key.get_unchecked_mut(0) ^
            *key.get_unchecked_mut(1) ^
            *key.get_unchecked_mut(2) ^
            *key.get_unchecked_mut(3) ^
            *key.get_unchecked_mut(4) ^
            *key.get_unchecked_mut(5) ^
            *key.get_unchecked_mut(6) ^
            *key.get_unchecked_mut(7) ^
            // Don't forget the constant, CONST_240.
            CONST_240
        };
    }
}

fn compute_parity_words(
    key:   &mut [u64],
    tweak: &mut [u64])
{
    compute_key_parity_word(key);
    compute_tweak_parity_word(tweak);
}

pub const NUM_STATIC_KEYSCHEDULE_WORDS: usize = NUM_KEY_WORDS * NUM_SUBKEYS;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Threefish512Static {
    pub state:        [u64; NUM_BLOCK_WORDS],
    pub key_schedule: [u64; NUM_STATIC_KEYSCHEDULE_WORDS],
}

impl Default for Threefish512Static {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Threefish512Dynamic {
    pub state: [u64; NUM_BLOCK_WORDS],
    pub key:   [u64; NUM_KEY_WORDS_WITH_PARITY],
    pub tweak: [u64; NUM_TWEAK_WORDS_WITH_PARITY],
}

impl Default for Threefish512Dynamic {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Threefish512Ctr {
    pub threefish512: Threefish512Static,
    pub keystream:    [u64; NUM_BLOCK_WORDS],
    pub buffer:       [u64; NUM_BLOCK_WORDS],
}

//TODO: We intend to implement a dynamically-keyed Threefish512 counter mode implementation.
// We will start with this type alias and later remove the original unspecified type.
pub type Threefish512CtrStatic = Threefish512Ctr;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Threefish512CtrDynamic {
    pub threefish512: Threefish512Dynamic,
    pub keystream:    [u64; NUM_BLOCK_WORDS],
    pub buffer:       [u64; NUM_BLOCK_WORDS],
}

impl Default for Threefish512Ctr {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

impl Default for Threefish512CtrDynamic {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

impl Threefish512Static {
    pub fn new(
        key:   &mut [u64],
        tweak: &mut [u64]) -> Self
    {
        debug_assert!(key.len()   == NUM_KEY_WORDS_WITH_PARITY);
        debug_assert!(tweak.len() == NUM_TWEAK_WORDS_WITH_PARITY);
        let mut tf = Threefish512Static {
            key_schedule: [0; NUM_STATIC_KEYSCHEDULE_WORDS],
            state:        [0; NUM_BLOCK_WORDS]
        };
        tf.init(key, tweak);

        tf
    }
    pub fn init(&mut self, key: &mut [u64], tweak: &mut [u64])
    {
        compute_parity_words(key, tweak);
        make_subkey!(self.key_schedule, key, tweak,  0);
        make_subkey!(self.key_schedule, key, tweak,  1);
        make_subkey!(self.key_schedule, key, tweak,  2);
        make_subkey!(self.key_schedule, key, tweak,  3);
        make_subkey!(self.key_schedule, key, tweak,  4);
        make_subkey!(self.key_schedule, key, tweak,  5);
        make_subkey!(self.key_schedule, key, tweak,  6);
        make_subkey!(self.key_schedule, key, tweak,  7);
        make_subkey!(self.key_schedule, key, tweak,  8);
        make_subkey!(self.key_schedule, key, tweak,  9);
        make_subkey!(self.key_schedule, key, tweak, 10);
        make_subkey!(self.key_schedule, key, tweak, 11);
        make_subkey!(self.key_schedule, key, tweak, 12);
        make_subkey!(self.key_schedule, key, tweak, 13);
        make_subkey!(self.key_schedule, key, tweak, 14);
        make_subkey!(self.key_schedule, key, tweak, 15);
        make_subkey!(self.key_schedule, key, tweak, 16);
        make_subkey!(self.key_schedule, key, tweak, 17);
        make_subkey!(self.key_schedule, key, tweak, 18);
    }
    pub fn encipher_1(
        &mut self,
        encipher_io: &mut [u64])
    {
        self.state.copy_from_slice(encipher_io);
        encrypt_static!(self);
        encipher_io.copy_from_slice(&self.state);
    }
    pub fn encipher_2<'a>(
        &mut self,
        ciphertext_output: &'a mut [u64],
        plaintext_input:   &'a     [u64]
    )
    {
        self.state.copy_from_slice(plaintext_input);
        encrypt_static!(self);
        ciphertext_output.copy_from_slice(&self.state);
    }
}

impl Threefish512Dynamic {
    pub fn new(
        key:   [u64; NUM_KEY_WORDS_WITH_PARITY],
        tweak: [u64; NUM_TWEAK_WORDS_WITH_PARITY]) -> Self
    {
        let mut tf = Self {
            key,
            tweak,
            state: [0u64; NUM_BLOCK_WORDS]
        };
        tf.compute_parity();

        tf
    }
    pub fn init(&mut self, key: &[u64], tweak: &[u64])
    {
        self.set_key(key);
        self.set_tweak(tweak);
    }
    pub fn compute_parity(&mut self)
    {
        compute_parity_words(&mut self.key, &mut self.tweak);
    }
    pub fn set_key(&mut self, key: &[u64])
    {
        self.key[..NUM_KEY_WORDS].copy_from_slice(&key[..NUM_KEY_WORDS]);
        compute_key_parity_word(&mut self.key);
    }
    pub fn set_tweak(&mut self, tweak: &[u64])
    {
        self.tweak[..NUM_TWEAK_WORDS].copy_from_slice(&tweak[..NUM_TWEAK_WORDS]);
        compute_tweak_parity_word(&mut self.tweak);
    }
    pub fn encipher_1(
        &mut self,
        encipher_io: &mut [u64])
    {
        self.state.copy_from_slice(encipher_io);
        encrypt_dynamic!(self);
        encipher_io.copy_from_slice(&self.state);
    }
    pub fn encipher_2(
        &mut self,
        ciphertext_output: &mut [u64],
        plaintext_input:   &    [u64])
    {
        self.state.copy_from_slice(plaintext_input);
        encrypt_dynamic!(self);
        ciphertext_output.copy_from_slice(&self.state);
    }
    pub fn encipher_into_key(
        &mut self,
        plaintext_input: &[u64])
    {
        self.state.copy_from_slice(plaintext_input);
        encrypt_dynamic!(self);
        self.key[..NUM_KEY_WORDS].copy_from_slice(&self.state);
    }
}

/// The xor_1 and xor_2 implementations are basically identical for Threefish512CtrStatic and
/// Threefish512CtrDynamic, so implement them both as macros.
macro_rules! ctr_xor_1 {
    ($self:expr,
     $input_output:expr,
     $keystream_start:expr) => {{
        let mut io = &mut $input_output[..];
        if $keystream_start == 0 {
            $self.keystream[0] = 0u64;
        } else {
            let starting_block: usize = {$keystream_start as usize} / NUM_BLOCK_BYTES;
            let offset: usize = {$keystream_start as usize} % NUM_BLOCK_BYTES;
            let bytes: usize  = NUM_BLOCK_BYTES - offset; 
            /* The first 8 bytes of a CTR Keystream is the block number, so copy the block number
             * as determined from where we're starting in the keystream into the first 8 bytes of
             * keystream.
             */
           $self.keystream[0] = {starting_block as u64}.to_le();
           $self.threefish512.encipher_2(&mut $self.buffer, &$self.keystream);
           $self.keystream[0] = {u64::from_le($self.keystream[0]) + 1}.to_le(); // Inrement keystream idx.
           let off = unsafe {
               std::slice::from_raw_parts_mut(
                   (&mut $self.buffer as *mut _ as *mut u8).offset(offset as isize),
                   (std::mem::size_of::<u64>() * $self.buffer.len()) - offset
               )
           };
           let left = if io.len() >= bytes {
               bytes
           } else {
               io.len()
           };
           for i in 0usize..left {
               unsafe { *io.get_unchecked_mut(i) ^= *off.get_unchecked_mut(i) };
           }
           io = &mut io[left..];
        }
        while io.len() >= NUM_BLOCK_BYTES {
            $self.threefish512.encipher_2(&mut $self.buffer, &$self.keystream);
            $self.keystream[0] = {u64::from_le($self.keystream[0]) + 1}.to_le(); // Increment keystream idx.
            let mut buf_bytes = unsafe {
                std::slice::from_raw_parts(
                    &mut $self.buffer as *const _ as *const u8,
                    std::mem::size_of::<u64>() * $self.buffer.len()
                )
            };
            xor_64!(io, buf_bytes);
            io = &mut io[8..];
        }
        if io.len() > 0 {
            $self.threefish512.encipher_2(&mut $self.buffer, &$self.keystream);
            let buf_bytes = unsafe {
                std::slice::from_raw_parts(
                    &$self.buffer as *const _ as *const u8,
                    std::mem::size_of::<u64>() * $self.buffer.len()
                )
            };
            for i in 0usize..io.len() {
                unsafe { *io.get_unchecked_mut(i) ^= *buf_bytes.get_unchecked(i); }
            }
        }
     }}
}

/// The xor_1 and xor_2 implementations are basically identical for Threefish512CtrStatic and
/// Threefish512CtrDynamic, so implement them both as macros.
macro_rules! ctr_xor_2 {
    ($self:expr,
     $output:expr,
     $input:expr,
     $keystream_start:expr) => {{
        let mut out = &mut $output[..];
        let mut inp = &$input[..];
        if $keystream_start == 0 {
            $self.keystream[0] = 0u64;
        } else {
            let starting_block: usize = {$keystream_start as usize} / NUM_BLOCK_BYTES;
            let offset: usize = {$keystream_start as usize} % NUM_BLOCK_BYTES;
            let bytes:  usize = NUM_BLOCK_BYTES - offset;
            /* The first 8 bytes of a CTR Keystream is the block number, so copy the block number
             * as determined from where we're starting in the keystream into the first 8 bytes of
             * keystream.
             */
            $self.keystream[0] = {starting_block as u64}.to_le();
            $self.threefish512.encipher_2(&mut $self.buffer, &$self.keystream);
            $self.keystream[0] = {u64::from_le($self.keystream[0]) + 1}.to_le(); // Increment keystream idx.
            let off = unsafe {
                std::slice::from_raw_parts_mut(
                    (&mut $self.buffer as *mut _ as *mut u8).offset(offset as isize),
                    (std::mem::size_of::<u64>() * $self.buffer.len()) - offset
                )
            };
            let left = if inp.len() >= bytes {
                bytes
            } else {
                inp.len()
            };
            for i in 0usize..left {
                unsafe { *off.get_unchecked_mut(i) ^= *inp.get_unchecked(i) };
            }
            out[..left].copy_from_slice(&off[..left]);
            inp = &inp[left..];
            out = &mut out[left..];
        }
        while inp.len() >= NUM_BLOCK_BYTES {
            $self.threefish512.encipher_2(&mut $self.buffer, &$self.keystream);
            $self.keystream[0] = {u64::from_le($self.keystream[0]) + 1}.to_le(); // Increment keystream idx.
            {
                let mut buf_bytes = unsafe {
                    std::slice::from_raw_parts_mut(
                        &mut $self.buffer as *mut _ as *mut u8,
                        std::mem::size_of::<u64>() * $self.buffer.len()
                    )
                };
                xor_64!(buf_bytes, inp); // This consumes input bytes and reduces the .len() of @inp by (NUM_BLOCK_BYTES - 8).
                inp = &inp[8..];
            }
            let buf_bytes = unsafe {
                std::slice::from_raw_parts(
                    &$self.buffer as *const _ as *const u8,
                    std::mem::size_of::<u64>() * $self.buffer.len()
                )
            };
            out[..NUM_BLOCK_BYTES].copy_from_slice(&buf_bytes);
            out = &mut out[NUM_BLOCK_BYTES..];
        }
        if inp.len() > 0 {
            $self.threefish512.encipher_2(&mut $self.buffer, &$self.keystream);
            let buf_bytes = unsafe {
                std::slice::from_raw_parts_mut(
                    &mut $self.buffer as *mut _ as *mut u8,
                    std::mem::size_of::<u64>() * $self.buffer.len()
                )
            };
            for i in 0usize..inp.len() {
                unsafe { *buf_bytes.get_unchecked_mut(i) ^= *inp.get_unchecked(i); }
            }
            out[..inp.len()].copy_from_slice(&buf_bytes[..inp.len()]);
        }
    }}
}

impl Threefish512Ctr {
    pub fn init(
        &mut self,
        key: &mut [u64],
        tweak: &mut [u64],
        ctr_iv: &[u64])
    {
        self.threefish512 = Threefish512Static::new(key, tweak);
        self.keystream    = [0u64; NUM_BLOCK_WORDS];
        self.buffer       = [0u64; NUM_BLOCK_WORDS];
        self.keystream[NUM_CTR_IV_WORDS..].copy_from_slice(ctr_iv);
    }

    pub fn new(
        key:    &mut [u64],
        tweak:  &mut [u64],
        ctr_iv: &[u64]) -> Self
    {
        let mut ctr = Self {
            threefish512: Threefish512Static::new(key, tweak),
            keystream:    [0u64; NUM_BLOCK_WORDS],
            buffer:       [0u64; NUM_BLOCK_WORDS],
        };
        ctr.keystream[NUM_CTR_IV_WORDS..].copy_from_slice(ctr_iv);
        ctr
    }

    pub fn xor_1(
        &mut self,
        input_output: &mut [u8],
        keystream_start: u64)
    {
        ctr_xor_1!(self, input_output, keystream_start);
    }

    pub fn xor_2(
        &mut self,
        output: &mut [u8],
        input:  &[u8],
        keystream_start: u64)
    {
        ctr_xor_2!(self, output, input, keystream_start);
    }
}

impl Threefish512CtrDynamic {
    pub fn init(
        &mut self,
        key:   &mut [u64],
        tweak: &mut [u64],
        ctr_iv:    &[u64])
    {
        self.threefish512 = Threefish512Dynamic::new(key.try_into().unwrap(), tweak.try_into().unwrap());
        self.keystream    = [0u64; NUM_BLOCK_WORDS];
        self.buffer       = [0u64; NUM_BLOCK_WORDS];
        self.keystream[NUM_CTR_IV_WORDS..].copy_from_slice(ctr_iv);
    }

    pub fn new(
        key:   &mut [u64],
        tweak: &mut [u64],
        ctr_iv:    &[u64]) -> Self
    {
        let mut ctr = Self {
            threefish512: Threefish512Dynamic::new(key.try_into().unwrap(), tweak.try_into().unwrap()),
            keystream:    [0u64; NUM_BLOCK_WORDS],
            buffer:       [0u64; NUM_BLOCK_WORDS],
        };
        ctr.keystream[NUM_CTR_IV_WORDS..].copy_from_slice(ctr_iv);
        ctr
    }

    pub fn xor_1(
        &mut self,
        input_output: &mut [u8],
        keystream_start: u64)
    {
        ctr_xor_1!(self, input_output, keystream_start);
    }

    pub fn xor_2(
        &mut self,
        output: &mut [u8],
        input:      &[u8],
        keystream_start: u64)
    {
        ctr_xor_2!(self, output, input, keystream_start);
    }
}

#[repr(C)]
pub struct Threefish512Ocbt {
    /// 62-bit message nonce (upper 2 bits unused).
    pub nonce: u64,
    /// AD/Payload block counter (used in the tweak).
    pub block_counter: u64,
    /// The underlying Threefish512 instance; dynamically calculated key-schedule.
    pub tf: Threefish512Dynamic,
    /// Accumulator for associated data (512 bits).
    pub ad_acc: [u64; NUM_BLOCK_WORDS],
    /// Accumulator for payload data (512 bits).
    pub data_acc: [u64; NUM_BLOCK_WORDS],
}

enum OcbtFinalBlock {
    Whole(&[u64; NUM_BLOCK_WORDS]),
    Partial(&[u8]),
}

impl Threefish512Ocbt {
    /// Create a new OCB-T instance with a 512-bit key and a 62-bit nonce.
    pub fn new(key: &[u64; NUM_KEY_WORDS], nonce: u64) -> Self {
        let mut tweak = [0u64; NUM_TWEAK_WORDS_WITH_PARITY];

        // The two domain bits are initially zero.
        tweak[0] = nonce << 2;
        // tweak[1] (the block counter) is already initialized to zero.

        let mut tf = Threefish512Dynamic::new(*key, tweak);

        Self {
            nonce,
            block_counter: 0u64,
            tf,
            ad_acc:   [0u64; NUM_BLOCK_WORDS],
            data_acc: [0u64; NUM_BLOCK_WORDS],
        }
    }

    #[inline]
    fn set_tweak(&mut self, domain: u64, counter: u64) {
        // domain: low 2 bits of tweak[0]
        // nonce:  stored in self.nonce
        // counter: stored in tweak[1]

        let t0 = (self.nonce << 2) | (domain & 0x3);
        let t1 = counter;

        self.tf.tweak[0] = t0.to_le();
        self.tf.tweak[1] = t1.to_le();

        // Recompute the tweak parity word.
        compute_tweak_parity_word(&mut self.tf.tweak);
    }

    fn process_ad_block_full(
        &mut self,
        tmp: &mut [u64; NUM_BLOCK_WORDS],
        block: &[u64; NUM_BLOCK_WORDS])
    {
        self.set_tweak(OCBT_DOMAIN_AD_CRYPT, self.block_counter);
        self.tf.encipher_2(tmp, block);
        for i in 0usize..NUM_BLOCK_WORDS {
            self.ad_acc[i] ^= tmp[i];
        }
        self.block_counter += 1;
    }

    fn process_ad_block_final(
        &mut self,
        tmp: &mut [u64; NUM_BLOCK_WORDS],
        finalblk: OcbtFinalBlock)
    {
        // Set the tweak for AD finalization.
        self.set_tweak(OCBT_DOMAIN_AD_FINALIZE, self.block_counter);
        match finalblk {
            OcbtFinalBlock::Whole(whole) => {
                self.tf.encipher_2(tmp, whole);
                for i in 0usize..NUM_BLOCK_WORDS {
                    self.ad_acc[i] ^= tmp[i];
                }
                self.block_counter += 1;
            },
            OcbtFinalBlock::Partial(partial) => {
                let tmp_bytes: &mut [u8; NUM_BLOCK_BYTES] = unsafe {
                    &mut *(tmp as *mut [u64; NUM_BLOCK_WORDS] as *mut [u8; NUM_BLOCK_BYTES])
                };
                // 1. Copy the partial bytes directly into tmp_bytes.
                let plen = partial.len();
                tmp_bytes[..plen].copy_from_slice(partial);
                // 2. Append 0x80.
                tmp_bytes[plen] = 0x80u8;
                // 3. Zero-pad the remainder.
                for b in &mut tmp_bytes[plen+1..] {
                    *b= 0u8;
                }
                // 4. Run Threefish512 on the padded block
                self.tf.encipher_1(tmp);
                // 5. XOR into AD accumulator.
                for i in 0usize..NUM_BLOCK_WORDS {
                    self.ad_acc[i] ^= tmp[i];
                }
                // 6. Increment block counter.
                self.block_counter += 1;
            },
        }
    }

    fn encrypt_full_block(
        &mut self,
        block_out: &mut [u64; NUM_BLOCK_WORDS],
        block_in: &[u64; NUM_BLOCK_WORDS])
    {
        // 1. Set the tweak for enciphering payload.
        self.set_tweak(OCBT_DOMAIN_DATA_CRYPT, self.block_counter);
        // 2. Encrypt the plaintext block.
        self.tf.encipher_2(block_out, block_in);
        // 3. Update the data accumulator using the plaintext for authentication.
        for i in 0usize..NUM_BLOCK_WORDS {
            self.data_acc[i] ^= block_in[i];
        }
        // 4. Increment the unified block counter.
        self.block_counter += 1;
    }

    fn encrypt_final_block(
        &mut self,
        block_out: &mut [u64; NUM_BLOCK_WORDS],
        tmp:       &mut [u64; NUM_BLOCK_WORDS],
        final_in:  OcbtFinalBlock)
    {
        self.set_tweak(OCBT_DOMAIN_DATA_FINALIZE, self.block_counter);
        match final_in {
            OcbtFinalBlock::Whole(whole) => {
                // 1. Encrypt the plaintext.
                self.tf.encipher_2(block_out, whole);
                // 2. Update the data accumulator using the plaintext for authentication.
                for i in 0usize..NUM_BLOCK_WORDS {
                    self.data_acc[i] ^= whole[i];
                }
                // 3. Increment the unified block counter.
                self.block_counter += 1;
            },
            OcbtFinalBlock::Partial(partial) => {
                let plen = partial.len();
                // 1. Build padded plaintext in @tmp.
                {
                    let padded_bytes: &mut [u8; NUM_BLOCK_BYTES] = unsafe {
                        &mut *(tmp as *mut [u64; NUM_BLOCK_WORDS] as *mut [u8; NUM_BLOCK_BYTES])
                    };
                    padded_bytes[..plen].copy_from_slice(partial);
                    padded_bytes[plen] = 0x80u8;
                    for b in &mut padded_bytes[plen + 1 ..] {
                        *b = 0u8;
                    }
                }

                // 2. Update data accumulator with padded plaintext (authentication).
                for i in 0usize..NUM_BLOCK_WORDS {
                    self.data_acc[i] ^= tmp[i];
                }

                // 3. Set tweak for DATA_FINALIZE and encrypt the padded plaintext in place.
                self.tf.encipher_1(&mut tmp);

                // 4. Ciphertext is the first @plen bytes of the encrypted padded block,
                //    so copy only those bytes into @block_out; the rest is unspecified.
                let enc_bytes: &[u8; NUM_BLOCK_BYTES] = unsafe {
                    &*(tmp as *const [u64; NUM_BLOCK_WORDS] as *const [u8; NUM_BLOCK_BYTES])
                };
                let out_bytes: &mut [u8; NUM_BLOCK_BYTES] = unsafe {
                    &mut *(block_out as *mut [u64; NUM_BLOCK_WORDS] as *mut [u8; NUM_BLOCK_BYTES])
                };
                out_bytes[..plen].copy_from_slice(&enc_bytes[..plen]);

                // 5. Increment unified block counter.
                self.block_counter += 1;
            },
        }
    }

    fn encrypt_partial_block(&mut self, tmp: &mut [u64; NUM_BLOCK_WORDS], finalblk: OcbtFinalBlock) {
        match finalblk {
            OcbtFinalBlock::Whole(whole) => {
            },
            OcbtFinalBlock::Partial(partial) => {
            },
        }
        //TODO: Implement.
    }

    //TODO: Define parameters.
    fn finalize_tag(&mut self) {
        //TODO: Implement.
    }
}
