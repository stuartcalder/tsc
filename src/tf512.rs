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
#![allow(unused)] // FIXME: Remove me.

use rssc::op::secure_zero;

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

pub const OCB_FLAG_AD: u64      = 0b0001u64;
pub const OCB_FLAG_DATA: u64    = 0b0010u64;
pub const OCB_FLAG_PARTIAL: u64 = 0b0100u64;
pub const OCB_FLAG_TAG: u64     = 0b1000u64;

pub const OCB_TOP_4_BITS: u64 = 0b1111u64 << 60;

pub const OCB_TAG_WORDS: usize = 8;
pub const OCB_TAG_BYTES: usize = 64;

pub enum OcbError {
    TagMismatch,
    InvalidLength
}

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
        // 1. Increment @w0 by @w1 and store it.
        w0 = w0.wrapping_add(w1);
        $state_words[W0] = w0.to_le();
        // 2. Rotate @w1 left by a constant, XOR with @w0 and store it.
        $state_words[W1] = (w1.rotate_left($rot_const) ^ w0).to_le();
     }}
}
macro_rules! undo_mix {
    ($state_words:expr,
     $state_idx:literal,
     $rot_const:literal) =>
     {{
         const W0: usize = $state_idx * 2;
         const W1: usize = W0 + 1;
         let mut w0: u64 = u64::from_le($state_words[W0]);
         let mut w1: u64 = u64::from_le($state_words[W1]);
         // 1. Rotate @w1 right by a constant, XOR with @w0.
         w1 = (w1 ^ w0).rotate_right($rot_const);
         // 2. Decrement @w0 by @w1.
         w0 = w0.wrapping_sub(w1);
         // 3. Store both.
         $state_words[W0] = w0.to_le();
         $state_words[W1] = w1.to_le();
     }}
}
macro_rules! subkey_idx    { ($round_num:literal) => ($round_num / 4usize) }
macro_rules! subkey_offset { ($round_num:literal) => (subkey_idx!($round_num) * NUM_BLOCK_WORDS) }
macro_rules! add_subkey_static {
    ($key_schedule_words:expr, $state_words:expr, $round_num:literal) =>
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
macro_rules! sub_subkey_static {
    ($key_schedule_words:expr, $state_words:expr, $round_num:literal) =>
    {{
        let state:  u64 = u64::from_le($state_words[0]);
        let keysch: u64 = u64::from_le($key_schedule_words[subkey_offset!($round_num)]);
        $state_words[0] = state.wrapping_sub(keysch).to_le();

        let state:  u64 = u64::from_le($state_words[1]);
        let keysch: u64 = u64::from_le($key_schedule_words[subkey_offset!($round_num) + 1]);
        $state_words[1] = state.wrapping_sub(keysch).to_le();

        let state:  u64 = u64::from_le($state_words[2]);
        let keysch: u64 = u64::from_le($key_schedule_words[subkey_offset!($round_num) + 2]);
        $state_words[2] = state.wrapping_sub(keysch).to_le();

        let state:  u64 = u64::from_le($state_words[3]);
        let keysch: u64 = u64::from_le($key_schedule_words[subkey_offset!($round_num) + 3]);
        $state_words[3] = state.wrapping_sub(keysch).to_le();

        let state:  u64 = u64::from_le($state_words[4]);
        let keysch: u64 = u64::from_le($key_schedule_words[subkey_offset!($round_num) + 4]);
        $state_words[4] = state.wrapping_sub(keysch).to_le();

        let state:  u64 = u64::from_le($state_words[5]);
        let keysch: u64 = u64::from_le($key_schedule_words[subkey_offset!($round_num) + 5]);
        $state_words[5] = state.wrapping_sub(keysch).to_le();

        let state:  u64 = u64::from_le($state_words[6]);
        let keysch: u64 = u64::from_le($key_schedule_words[subkey_offset!($round_num) + 6]);
        $state_words[6] = state.wrapping_sub(keysch).to_le();

        let state:  u64 = u64::from_le($state_words[7]);
        let keysch: u64 = u64::from_le($key_schedule_words[subkey_offset!($round_num) + 7]);
        $state_words[7] = state.wrapping_sub(keysch).to_le();
    }}
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
macro_rules! sub_subkey_dynamic {
    ($key_words:expr,
     $state_words:expr,
     $tweak_words:expr,
     $round_num:literal) =>
     {{
        const SUBKEY_IDX: usize = subkey_idx!($round_num);

        let s = u64::from_le($state_words[0]);
        let k = u64::from_le(unsafe{ *$key_words.get_unchecked_mut(SUBKEY_IDX % NUM_KEY_WORDS_WITH_PARITY) });
        $state_words[0] = s.wrapping_sub(k).to_le();

        let s = u64::from_le($state_words[1]);
        let k = u64::from_le(unsafe{ *$key_words.get_unchecked_mut((SUBKEY_IDX + 1) % NUM_KEY_WORDS_WITH_PARITY) });
        $state_words[1] = s.wrapping_sub(k).to_le();

        let s = u64::from_le($state_words[2]);
        let k = u64::from_le(unsafe{ *$key_words.get_unchecked_mut((SUBKEY_IDX + 2) % NUM_KEY_WORDS_WITH_PARITY) });
        $state_words[2] = s.wrapping_sub(k).to_le();

        let s = u64::from_le($state_words[3]);
        let k = u64::from_le(unsafe{ *$key_words.get_unchecked_mut((SUBKEY_IDX + 3) % NUM_KEY_WORDS_WITH_PARITY) });
        $state_words[3] = s.wrapping_sub(k).to_le();

        let s = u64::from_le($state_words[4]);
        let k = u64::from_le(unsafe{ *$key_words.get_unchecked_mut((SUBKEY_IDX + 4) % NUM_KEY_WORDS_WITH_PARITY) });
        $state_words[4] = s.wrapping_sub(k).to_le();

        let s = u64::from_le($state_words[5]);
        let k = u64::from_le(unsafe{ *$key_words.get_unchecked_mut((SUBKEY_IDX + 5) % NUM_KEY_WORDS_WITH_PARITY) });
        let t = u64::from_le(unsafe{ *$tweak_words.get_unchecked_mut(SUBKEY_IDX % 3) });
        $state_words[5] = s.wrapping_sub(k.wrapping_add(t)).to_le();

        let s = u64::from_le($state_words[6]);
        let k = u64::from_le(unsafe{ *$key_words.get_unchecked_mut((SUBKEY_IDX + 6) % NUM_KEY_WORDS_WITH_PARITY) });
        let t = u64::from_le(unsafe{ *$tweak_words.get_unchecked_mut((SUBKEY_IDX + 1) % 3) });
        $state_words[6] = s.wrapping_sub(k.wrapping_add(t)).to_le();

        let s = u64::from_le($state_words[7]);
        let k = u64::from_le(unsafe{ *$key_words.get_unchecked_mut((SUBKEY_IDX + 7) % NUM_KEY_WORDS_WITH_PARITY) });
        $state_words[7] = s.wrapping_sub(k.wrapping_add(SUBKEY_IDX as u64)).to_le();
     }}
}
macro_rules! permute {
    ($state_words:expr) =>
    {{
        unsafe {
             let a0 = *$state_words.get_unchecked(0);
             //let a1 = *$state_words.get_unchecked(1);
             let a2 = *$state_words.get_unchecked(2);
             let a3 = *$state_words.get_unchecked(3);
             let a4 = *$state_words.get_unchecked(4);
             // let a5 = *$state_words.get_unchecked(5);
             let a6 = *$state_words.get_unchecked(6);
             let a7 = *$state_words.get_unchecked(7);
             *$state_words.get_unchecked_mut(0) = a2;
             //*$state_words.get_unchecked_mut(1) = a1;
             *$state_words.get_unchecked_mut(2) = a4;
             *$state_words.get_unchecked_mut(3) = a7;
             *$state_words.get_unchecked_mut(4) = a6;
             //*$state_words.get_unchecked_mut(5) = a5;
             *$state_words.get_unchecked_mut(6) = a0;
             *$state_words.get_unchecked_mut(7) = a3;
        }
    }}
}
macro_rules! undo_permute {
    ($state_words:expr) =>
    {{
        unsafe {
             let a0 = *$state_words.get_unchecked(0);
             //let a1 = *$state_words.get_unchecked(1);
             let a2 = *$state_words.get_unchecked(2);
             let a3 = *$state_words.get_unchecked(3);
             let a4 = *$state_words.get_unchecked(4);
             //let a5 = *$state_words.get_unchecked(5);
             let a6 = *$state_words.get_unchecked(6);
             let a7 = *$state_words.get_unchecked(7);
             *$state_words.get_unchecked_mut(0) = a6;
             //*$state_words.get_unchecked_mut(1) = a1;
             *$state_words.get_unchecked_mut(2) = a0;
             *$state_words.get_unchecked_mut(3) = a7;
             *$state_words.get_unchecked_mut(4) = a2;
             //*$state_words.get_unchecked_mut(5) = a5;
             *$state_words.get_unchecked_mut(6) = a4;
             *$state_words.get_unchecked_mut(7) = a3;
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
macro_rules! undo_mix4_permute {
    ($state_words:expr,
     $rotate_const_0:literal,
     $rotate_const_1:literal,
     $rotate_const_2:literal,
     $rotate_const_3:literal) =>
     {{
         undo_permute!($state_words);
         undo_mix!($state_words, 3usize, $rotate_const_3);
         undo_mix!($state_words, 2usize, $rotate_const_2);
         undo_mix!($state_words, 1usize, $rotate_const_1);
         undo_mix!($state_words, 0usize, $rotate_const_0);
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
macro_rules! decrypt_round_static {
    ($key_schedule_words:expr,
     $state_words:expr,
     $round_start:literal,
     $rc0_0:literal, $rc0_1:literal, $rc0_2:literal, $rc0_3:literal,
     $rc1_0:literal, $rc1_1:literal, $rc1_2:literal, $rc1_3:literal,
     $rc2_0:literal, $rc2_1:literal, $rc2_2:literal, $rc2_3:literal,
     $rc3_0:literal, $rc3_1:literal, $rc3_2:literal, $rc3_3:literal) =>
     {{
        undo_mix4_permute!($state_words, $rc3_0, $rc3_1, $rc3_2, $rc3_3);
        undo_mix4_permute!($state_words, $rc2_0, $rc2_1, $rc2_2, $rc2_3);
        undo_mix4_permute!($state_words, $rc1_0, $rc1_1, $rc1_2, $rc1_3);
        undo_mix4_permute!($state_words, $rc0_0, $rc0_1, $rc0_2, $rc0_3);
        sub_subkey_static!($key_schedule_words, $state_words, $round_start);
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
macro_rules! decrypt_round_dynamic {
    ($key_words:expr,
     $state_words:expr,
     $tweak_words:expr,
     $round_start:literal,
     $rc0_0:literal, $rc0_1:literal, $rc0_2:literal, $rc0_3:literal,
     $rc1_0:literal, $rc1_1:literal, $rc1_2:literal, $rc1_3:literal,
     $rc2_0:literal, $rc2_1:literal, $rc2_2:literal, $rc2_3:literal,
     $rc3_0:literal, $rc3_1:literal, $rc3_2:literal, $rc3_3:literal) =>
     {{
        undo_mix4_permute!($state_words, $rc3_0, $rc3_1, $rc3_2, $rc3_3);
        undo_mix4_permute!($state_words, $rc2_0, $rc2_1, $rc2_2, $rc2_3);
        undo_mix4_permute!($state_words, $rc1_0, $rc1_1, $rc1_2, $rc1_3);
        undo_mix4_permute!($state_words, $rc0_0, $rc0_1, $rc0_2, $rc0_3);
        sub_subkey_dynamic!($key_words, $state_words, $tweak_words, $round_start);
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
macro_rules! decrypt_static_phase_0 {
    ($key_schedule_words:expr,
     $state_words:expr,
     $round_start:literal) =>
    {
        decrypt_round_static!(
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
macro_rules! decrypt_dynamic_phase_0 {
    ($key_words:expr,
     $state_words:expr,
     $tweak_words:expr,
     $round_start:literal) =>
    {
        decrypt_round_dynamic!(
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
macro_rules! decrypt_static_phase_1 {
    ($key_schedule_words:expr,
     $state_words:expr,
     $round_start:literal) =>
    {
        decrypt_round_static!(
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
macro_rules! decrypt_dynamic_phase_1 {
    ($key_words:expr,
     $state_words:expr,
     $tweak_words:expr,
     $round_start:literal) =>
    {
        decrypt_round_dynamic!(
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
macro_rules! decrypt_static {
    ($static:expr) => {
        sub_subkey_static!($static.key_schedule, $static.state, 72);
        decrypt_static_phase_1!($static.key_schedule, $static.state, 68);
        decrypt_static_phase_0!($static.key_schedule, $static.state, 64);
        decrypt_static_phase_1!($static.key_schedule, $static.state, 60);
        decrypt_static_phase_0!($static.key_schedule, $static.state, 56);
        decrypt_static_phase_1!($static.key_schedule, $static.state, 52);
        decrypt_static_phase_0!($static.key_schedule, $static.state, 48);
        decrypt_static_phase_1!($static.key_schedule, $static.state, 44);
        decrypt_static_phase_0!($static.key_schedule, $static.state, 40);
        decrypt_static_phase_1!($static.key_schedule, $static.state, 36);
        decrypt_static_phase_0!($static.key_schedule, $static.state, 32);
        decrypt_static_phase_1!($static.key_schedule, $static.state, 28);
        decrypt_static_phase_0!($static.key_schedule, $static.state, 24);
        decrypt_static_phase_1!($static.key_schedule, $static.state, 20);
        decrypt_static_phase_0!($static.key_schedule, $static.state, 16);
        decrypt_static_phase_1!($static.key_schedule, $static.state, 12);
        decrypt_static_phase_0!($static.key_schedule, $static.state,  8);
        decrypt_static_phase_1!($static.key_schedule, $static.state,  4);
        decrypt_static_phase_0!($static.key_schedule, $static.state,  0);
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
macro_rules! decrypt_dynamic {
    ($dynamic:expr) => {
        sub_subkey_dynamic!($dynamic.key, $dynamic.state, $dynamic.tweak, 72);
        decrypt_dynamic_phase_1!($dynamic.key, $dynamic.state, $dynamic.tweak, 68);
        decrypt_dynamic_phase_0!($dynamic.key, $dynamic.state, $dynamic.tweak, 64);
        decrypt_dynamic_phase_1!($dynamic.key, $dynamic.state, $dynamic.tweak, 60);
        decrypt_dynamic_phase_0!($dynamic.key, $dynamic.state, $dynamic.tweak, 56);
        decrypt_dynamic_phase_1!($dynamic.key, $dynamic.state, $dynamic.tweak, 52);
        decrypt_dynamic_phase_0!($dynamic.key, $dynamic.state, $dynamic.tweak, 48);
        decrypt_dynamic_phase_1!($dynamic.key, $dynamic.state, $dynamic.tweak, 44);
        decrypt_dynamic_phase_0!($dynamic.key, $dynamic.state, $dynamic.tweak, 40);
        decrypt_dynamic_phase_1!($dynamic.key, $dynamic.state, $dynamic.tweak, 36);
        decrypt_dynamic_phase_0!($dynamic.key, $dynamic.state, $dynamic.tweak, 32);
        decrypt_dynamic_phase_1!($dynamic.key, $dynamic.state, $dynamic.tweak, 28);
        decrypt_dynamic_phase_0!($dynamic.key, $dynamic.state, $dynamic.tweak, 24);
        decrypt_dynamic_phase_1!($dynamic.key, $dynamic.state, $dynamic.tweak, 20);
        decrypt_dynamic_phase_0!($dynamic.key, $dynamic.state, $dynamic.tweak, 16);
        decrypt_dynamic_phase_1!($dynamic.key, $dynamic.state, $dynamic.tweak, 12);
        decrypt_dynamic_phase_0!($dynamic.key, $dynamic.state, $dynamic.tweak,  8);
        decrypt_dynamic_phase_1!($dynamic.key, $dynamic.state, $dynamic.tweak,  4);
        decrypt_dynamic_phase_0!($dynamic.key, $dynamic.state, $dynamic.tweak,  0);
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
macro_rules! block_as_u8 {
    ($blk:expr) => {unsafe {
        &*($blk.as_ptr() as *const [u8; NUM_BLOCK_BYTES])
    }}
}
macro_rules! block_as_u8_mut {
    ($blk:expr) => {unsafe {
        &mut *($blk.as_mut_ptr() as *mut [u8; NUM_BLOCK_BYTES])
    }}
}

#[inline]
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

#[inline]
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

#[inline]
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
    pub fn decipher_1(
        &mut self,
        decipher_io: &mut [u64])
    {
        self.state.copy_from_slice(decipher_io);
        decrypt_static!(self);
        decipher_io.copy_from_slice(&self.state);
    }
    pub fn encipher_2<'a>(
        &mut self,
        ciphertext_output: &'a mut [u64],
        plaintext_input:   &'a     [u64])
    {
        self.state.copy_from_slice(plaintext_input);
        encrypt_static!(self);
        ciphertext_output.copy_from_slice(&self.state);
    }
    pub fn decipher_2<'a>(
        &mut self,
        plaintext_output: &'a mut [u64],
        ciphertext_input: &'a     [u64])
    {
        self.state.copy_from_slice(ciphertext_input);
        decrypt_static!(self);
        plaintext_output.copy_from_slice(&self.state);
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
    pub fn decipher_1(
        &mut self,
        decipher_io: &mut [u64])
    {
        self.state.copy_from_slice(decipher_io);
        decrypt_dynamic!(self);
        decipher_io.copy_from_slice(&self.state);
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
    pub fn decipher_2(
        &mut self,
        plaintext_output: &mut [u64],
        ciphertext_input: &    [u64])
    {
        self.state.copy_from_slice(ciphertext_input);
        decrypt_dynamic!(self);
        plaintext_output.copy_from_slice(&self.state);
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
pub struct Threefish512Ocb {
    /// 60-bit message nonce (Upper 4 bits unused).
    pub nonce: u64,
    /// AD/Payload block counter (used in the tweak).
    pub block_counter: u64,
    /// The underlying Threefish512 instance; dynamically calculated key-schedule.
    pub tf: Threefish512Dynamic,
    /// Authentication accumulator.
    pub ad_acc: [u64; NUM_BLOCK_WORDS],
    /// Data accumulator.
    pub data_acc: [u64; NUM_BLOCK_WORDS],
}

enum OcbFinalBlock<'a> {
    Whole(&'a   [u64; NUM_BLOCK_WORDS]),
    Partial(&'a [u8]),
}

enum OcbFinalBlockMut<'a> {
    Whole(&'a   mut [u64; NUM_BLOCK_WORDS]),
    Partial(&'a mut [u8]),
}

impl Drop for Threefish512Ocb {
    fn drop(&mut self) {
        self.sanitize();
    }
}

impl Threefish512Ocb {
    /// Create a new OCB-T instance. Keying material passed on each invocation, not on
    /// initialization.
    pub fn new() -> Self {
        Self {
            nonce: 0u64,
            block_counter: 0u64,
            tf: Threefish512Dynamic::default(),
            ad_acc:   [0u64; NUM_BLOCK_WORDS],
            data_acc: [0u64; NUM_BLOCK_WORDS],
        }
    }

    #[inline]
    fn set_tweak(&mut self, flags: u64) {
        // domain: low 4 bits of tweak[0]
        // nonce:  stored in self.nonce
        // counter: stored in tweak[1]

        let t0 = (self.nonce << 4) | (flags & 0b1111u64);
        let t1 = self.block_counter;

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
        // 1. Set the tweak for enciphering additional data.
        self.set_tweak(OCB_FLAG_AD);
        // 2. Encipher it into the temporary buffer.
        self.tf.encipher_2(tmp, block);
        // 3. XOR the resulting ciphertext into the AD accumulator.
        xor_8!(self.ad_acc, tmp);
        // 4. Increment the unified block counter.
        self.block_counter += 1;
    }

    fn process_ad_block_final_partial(
        &mut self,
        tmp: &mut [u64; NUM_BLOCK_WORDS],
        partial: &[u8])
    {
        // 1. Set the tweak for enciphering a final, partial AD block.
        self.set_tweak(OCB_FLAG_AD | OCB_FLAG_PARTIAL);
        {
            let tmp_bytes = block_as_u8_mut!(tmp);
            // 2. Copy the partial bytes directly into @tmp_bytes.
            let plen = partial.len();
            tmp_bytes[..plen].copy_from_slice(partial);
            // 3. Append 0x80.
            tmp_bytes[plen] = 0x80u8;
            // 4. Zero-pad the remainder.
            tmp_bytes[plen + 1 ..].fill(0u8);
        }
        // 5. Run Threefish512 on the padded block
        self.tf.encipher_1(tmp);
        // 6. XOR into AD accumulator.
        xor_8!(self.ad_acc, tmp);
        // 7. Increment the unified block counter.
        self.block_counter += 1;
    }

    fn encrypt_full_block(
        &mut self,
        block_out: &mut [u64; NUM_BLOCK_WORDS],
        block_in: &[u64; NUM_BLOCK_WORDS])
    {
        // 1. Set the tweak for enciphering payload.
        self.set_tweak(OCB_FLAG_DATA);
        // 2. Encrypt the plaintext block.
        self.tf.encipher_2(block_out, block_in);
        // 3. Update the data accumulator using the plaintext for authentication.
        xor_8!(self.data_acc, block_in);
        // 4. Increment the unified block counter.
        self.block_counter += 1;
    }

    fn encrypt_final_block(
        &mut self,
        final_out: OcbFinalBlockMut,
        tmp:       &mut [u64; NUM_BLOCK_WORDS],
        final_in:  OcbFinalBlock)
    {
        match (final_out, final_in) {
            (OcbFinalBlockMut::Whole(out_ctext_blk), OcbFinalBlock::Whole(in_ptext_blk)) => {
                self.set_tweak(OCB_FLAG_DATA);
                // 1. Encrypt the plaintext.
                self.tf.encipher_2(out_ctext_blk, in_ptext_blk);
                // 2. Update data accumulator with plaintext for authentication.
                xor_8!(self.data_acc, in_ptext_blk);
            },
            (OcbFinalBlockMut::Partial(out_ctext_bytes), OcbFinalBlock::Partial(in_ptext_bytes)) => {
                self.set_tweak(OCB_FLAG_DATA | OCB_FLAG_PARTIAL);
                if out_ctext_bytes.len() != in_ptext_bytes.len() {
                    panic!("out_ctext_bytes.len() != in_ptext_bytes.len()!");
                }
                let len = in_ptext_bytes.len();
                // 1. Derive an "XOR-Pad" by encrypting all zero.
                tmp.fill(0u64);
                self.tf.encipher_1(tmp);
                {
                    // 2. XOR the XOR-Pad with the plaintext bytes and write to @out_ctext_bytes.
                    let tmp_bytes = block_as_u8_mut!(tmp);
                    for i in 0usize..len {
                        out_ctext_bytes[i] = tmp_bytes[i] ^ in_ptext_bytes[i];
                    }
                    // 3. Pad then authenticate the plaintext.
                    tmp_bytes[..len].copy_from_slice(&in_ptext_bytes);
                    tmp_bytes[len] = 0x80u8;
                    tmp_bytes[len + 1 ..].fill(0u8);
                    xor_8!(self.data_acc, tmp);
                }
            },
            _ => {
                panic!("OcbFinalBlockMut/OcbFinalBlock Mismatch!");
            },
        }
        // Increment the unified block counter.
        self.block_counter += 1;
    }

    fn decrypt_full_block(
        &mut self,
        ptext_block_out: &mut [u64; NUM_BLOCK_WORDS],
        ctext_block_in:  &[u64; NUM_BLOCK_WORDS])
    {
        // 1. Set the tweak for deciphering payload.
        self.set_tweak(OCB_FLAG_DATA);
        // 2. Decrypt the ciphertext block.
        self.tf.decipher_2(ptext_block_out, ctext_block_in);
        // 3. Update the data accumulator using the plaintext for authentication.
        xor_8!(self.data_acc, ptext_block_out);
        // 4. Increment the unified block counter.
        self.block_counter += 1;
    }

    fn decrypt_final_block(
        &mut self,
        final_out: OcbFinalBlockMut,
        tmp:       &mut [u64; NUM_BLOCK_WORDS],
        final_in:  OcbFinalBlock)
    {
        match (final_out, final_in) {
            // <---------------- Whole final block (no padding) -------------------->
            (OcbFinalBlockMut::Whole(ptext_block_out), OcbFinalBlock::Whole(ctext_block_in)) => {
                self.set_tweak(OCB_FLAG_DATA);
                // 1. Decrypt the ciphertext block.
                self.tf.decipher_2(ptext_block_out, ctext_block_in);
                // 2. Update the data accumulator using the plaintext for authentication.
                xor_8!(self.data_acc, ptext_block_out);
            },
            // <---------------- Partial final block (with padding) ------------------>
            (OcbFinalBlockMut::Partial(ptext_bytes_out), OcbFinalBlock::Partial(ctext_bytes_in)) => {
                self.set_tweak(OCB_FLAG_DATA | OCB_FLAG_PARTIAL);
                if ptext_bytes_out.len() != ctext_bytes_in.len() {
                    panic!("ptext_bytes_out.len() != ctext_bytes_in.len()!")
                }
                let len = ptext_bytes_out.len();
                // 1. Derive an "XOR-Pad" by encrypting all zero.
                tmp.fill(0u64);
                self.tf.encipher_1(tmp);
                // 2. XOR the XOR-Pad with the ciphertext bytes and write to @ptext_bytes_out.
                {
                    let tmp_bytes = block_as_u8_mut!(tmp);
                    for i in 0usize..len {
                        ptext_bytes_out[i] = tmp_bytes[i] ^ ctext_bytes_in[i];
                    }
                    // 3. Pad the plaintext.
                    tmp_bytes[..len].copy_from_slice(ptext_bytes_out);
                    tmp_bytes[len] = 0x80u8;
                    tmp_bytes[len + 1 ..].fill(0u8);
                }
                // 4. Authenticate the padded plaintext.
                xor_8!(self.data_acc, tmp);
            },
            _ => {
                panic!("OcbFinalBlockMut/OcbFinalBlock Mismatch!");
            },
        }
        // Increment the unified block counter.
        self.block_counter += 1;
    }

    pub fn finalize_tag(
        &mut self,
        tag_out: &mut [u8; OCB_TAG_BYTES],
        flags: u64)
    {
        // 1. Set the tweak with the chosen flags.
        self.set_tweak(OCB_FLAG_TAG | flags);
        // 2. Encipher the DATA accumulator.
        self.tf.encipher_1(&mut self.data_acc);
        // 3. XOR the AD accumulator into the enciphered DATA accumulator.
        xor_8!(self.data_acc, self.ad_acc);
        // 4. Export as bytes.
        tag_out.copy_from_slice(block_as_u8!(&self.data_acc));
    }

    pub fn sanitize(&mut self) {
        self.tf = Threefish512Dynamic::default();
        secure_zero(&mut self.ad_acc);
        secure_zero(&mut self.data_acc);
    }

    pub fn absorb_ad(&mut self, ad: &[u8]) {
        let mut i         = 0usize;
        let mut tmp       = [0u64; NUM_BLOCK_WORDS];
        let mut block_u64 = [0u64; NUM_BLOCK_WORDS];

        // 1. Process full 64-byte blocks.
        while i + NUM_BLOCK_BYTES <= ad.len() {
            block_as_u8_mut!(block_u64).copy_from_slice(&ad[i .. i + NUM_BLOCK_BYTES]);
            self.process_ad_block_full(&mut tmp, &block_u64);
            i += NUM_BLOCK_BYTES;
        }

        // 2. Process final partial block (if there are any leftover).
        let final_partial = &ad[i..];
        if !final_partial.is_empty() {
            self.process_ad_block_final_partial(&mut tmp, final_partial);
        }

        // 3. Clean-up.
        secure_zero(&mut tmp);
        secure_zero(&mut block_u64);
    }

    pub fn encrypt(&mut self, ct_out: &mut [u8], pt: &[u8])
        -> bool /* (Was the final block partial? */
    {
        let mut tmp           = [0u64; NUM_BLOCK_WORDS];
        let mut block_u64_in  = [0u64; NUM_BLOCK_WORDS];
        let mut block_u64_out = [0u64; NUM_BLOCK_WORDS];
        let mut final_was_partial = true;

        if ct_out.len() != pt.len() {
            panic!("ct_out.len() != pt.len()!");
        }

        let len = pt.len();
        // Finalize now if there's one block or less.
        if len <= NUM_BLOCK_BYTES {
            let (output, input) = match len {
                NUM_BLOCK_BYTES => {
                    final_was_partial = false;
                    // Copy the plaintext into the aligned input buffer.
                    block_as_u8_mut!(block_u64_in).copy_from_slice(&pt[..NUM_BLOCK_BYTES]);
                    // Pass the input and output buffers.
                    (OcbFinalBlockMut::Whole(&mut block_u64_out),
                     OcbFinalBlock::Whole(&block_u64_in))
                },
                _ => {
                    let block_u8_in  = block_as_u8_mut!(block_u64_in);
                    let block_u8_out = block_as_u8_mut!(block_u64_out);
                    // Copy the plaintext into the aligned input buffer.
                    block_u8_in[..len].copy_from_slice(pt);
                    // Pass the input and output buffers.
                    (OcbFinalBlockMut::Partial(&mut block_u8_out[..len]),
                     OcbFinalBlock::Partial(&block_u8_in[..len]))
                },
            };
            // Encrypt the input buffer into the output buffer.
            self.encrypt_final_block(output, &mut tmp, input);
            // Copy the requested number of bytes out into the ciphertext buffer.
            ct_out.copy_from_slice(&block_as_u8!(block_u64_out)[..len]);
            // Cleanup.
            secure_zero(&mut tmp);
            secure_zero(&mut block_u64_in);
            secure_zero(&mut block_u64_out);
            return final_was_partial;
        } // ~ if len <= NUM_BLOCK_BYTES

        // Getting here implies there are at least two blocks.
        // We're checking for strictly less than the length so we can handle the final block
        // explicitly, lastly.
        let mut i = 0usize;
        while i + NUM_BLOCK_BYTES < len {
            // Copy 64 bytes into the aligned input buffer.
            block_as_u8_mut!(block_u64_in).copy_from_slice(&pt[i .. i + NUM_BLOCK_BYTES]);
            // Encrypt the input buffer into the output buffer.
            self.encrypt_full_block(&mut block_u64_out, &block_u64_in);
            // Copy 64 bytes out of the aligned output buffer into @ct_out for the caller.
            ct_out[i .. i + NUM_BLOCK_BYTES].copy_from_slice(block_as_u8!(block_u64_out));
            // Increment the byte counter.
            i += NUM_BLOCK_BYTES;
        }

        // We have reached the final block.
        // Copy the plaintext into the aligned input buffer.
        let remain = len - i;
        block_as_u8_mut!(block_u64_in)[..remain].copy_from_slice(&pt[i..]);
        let (output, input) = match remain {
            NUM_BLOCK_BYTES => {
                final_was_partial = false;
                // Last block is whole. Pass the input and output u64 buffers.
                (OcbFinalBlockMut::Whole(&mut block_u64_out), OcbFinalBlock::Whole(&block_u64_in))
            },
            _ => {
                // last black is partial. Pass the input and output u8 buffers.
                (OcbFinalBlockMut::Partial(
                    &mut block_as_u8_mut!(block_u64_out)[..remain]
                ),
                OcbFinalBlock::Partial(
                    &block_as_u8!(block_u64_in)[..remain]
                ))
            },
        };
        // Encrypt the input buffer into the output buffer.
        self.encrypt_final_block(output, &mut tmp, input);
        // Copy the requested number of bytes out into the ciphertext buffer.
        ct_out[i .. i + remain].copy_from_slice(&block_as_u8!(block_u64_out)[..remain]);
        // Cleanup.
        secure_zero(&mut tmp);
        secure_zero(&mut block_u64_in);
        secure_zero(&mut block_u64_out);
        final_was_partial
    }

    pub fn decrypt(&mut self, pt_out: &mut [u8], ct: &[u8])
        -> bool /* (Was the final block partial?) */
    {
        let mut tmp          = [0u64; NUM_BLOCK_WORDS];
        let mut cblk_u64_in  = [0u64; NUM_BLOCK_WORDS];
        let mut pblk_u64_out = [0u64; NUM_BLOCK_WORDS];
        let mut final_was_partial = true;

        if pt_out.len() != ct.len() {
            panic!("pt_out.len() != ct.len()!");
        }

        let len = ct.len();
        // Finalize now if there's one block or less.
        if len <= NUM_BLOCK_BYTES {
            let (final_po, final_ci) = match len {
                NUM_BLOCK_BYTES => {
                    final_was_partial = false;
                    // Copy the ciphertext into the aligned input buffer.
                    block_as_u8_mut!(cblk_u64_in).copy_from_slice(&ct[..NUM_BLOCK_BYTES]);
                    // Pass the input and output buffers.
                    (OcbFinalBlockMut::Whole(&mut pblk_u64_out), OcbFinalBlock::Whole(&cblk_u64_in))
                },
                _ => {
                    let cblk_u8_in  = block_as_u8_mut!(cblk_u64_in);
                    let pblk_u8_out = block_as_u8_mut!(pblk_u64_out);
                    // Copy the ciphertext into the aligned input buffer.
                    cblk_u8_in[..len].copy_from_slice(ct);
                    // Pass the input and output buffers.
                    (OcbFinalBlockMut::Partial(&mut pblk_u8_out[..len]), OcbFinalBlock::Partial(&cblk_u8_in[..len]))
                },
            };
            // Decrypt the input buffer into the output buffer.
            self.decrypt_final_block(final_po, &mut tmp, final_ci);
            // Copy the requested number of bytes out into the plaintext buffer.
            pt_out.copy_from_slice(&block_as_u8!(pblk_u64_out)[..len]);
            // Cleanup.
            secure_zero(&mut tmp);
            secure_zero(&mut cblk_u64_in);
            secure_zero(&mut pblk_u64_out);
            return final_was_partial;
        } // ~ if len <= NUM_BLOCK_BYTES

        // Getting here implies there are at least two blocks.
        // We're checking for strictly less than the length so we can handle the final block
        // explicitly, lastly.
        let mut i = 0usize;
        while i + NUM_BLOCK_BYTES < len {
            // Copy 64 bytes into the aligned input buffer.
            block_as_u8_mut!(cblk_u64_in).copy_from_slice(&ct[i .. i + NUM_BLOCK_BYTES]);
            // Decrypt the input buffer into the output buffer.
            self.decrypt_full_block(&mut pblk_u64_out, &cblk_u64_in);
            // Copy 64 bytes out of the aligned output buffer into @pt_out for the caller.
            pt_out[i .. i + NUM_BLOCK_BYTES].copy_from_slice(block_as_u8!(pblk_u64_out));
            // Increment the byte counter.
            i += NUM_BLOCK_BYTES;
        }

        // We have reached the final block.
        // Copy the ciphertext into the aligned input buffer.
        let remain = len - i;
        block_as_u8_mut!(cblk_u64_in)[..remain].copy_from_slice(&ct[i..]);
        let (final_po, final_ci) = match remain {
            NUM_BLOCK_BYTES => {
                final_was_partial = false;
                // Last block is whole. Pass the input and output u64 buffers.
                (OcbFinalBlockMut::Whole(&mut pblk_u64_out), OcbFinalBlock::Whole(&cblk_u64_in))
            },
            _ => {
                // Last block is partial. Pass the input and output u8 buffers.
                (OcbFinalBlockMut::Partial(&mut block_as_u8_mut!(pblk_u64_out)[..remain]),
                 OcbFinalBlock::Partial(&block_as_u8!(cblk_u64_in)[..remain]))
            },
        };
        // Decrypt the input buffer into the output buffer.
        self.decrypt_final_block(final_po, &mut tmp, final_ci);
        // Copy the requested number of bytes out into the plaintext buffer.
        pt_out[i .. i + remain].copy_from_slice(&block_as_u8!(pblk_u64_out)[..remain]);
        // Cleanup.
        secure_zero(&mut tmp);
        secure_zero(&mut cblk_u64_in);
        secure_zero(&mut pblk_u64_out);
        final_was_partial
    }

    pub fn seal(
        &mut self,
        ct_out: &mut [u8], // Ciphertext output.
        tag_out: &mut [u8; OCB_TAG_BYTES], // Authentication-Tag output.
        key:     &[u64; NUM_KEY_WORDS], // Input encryption key.
        nonce:   u64,  // UNIQUE 62-bit nonce for tweak differentiation.
        ad:      &[u8], // Additional data to simultaneously authenticate.
        pt:      &[u8], // Input plaintext to encipher.
    ) -> Result<(), OcbError> {
        // Size check.
        if ct_out.len() != pt.len() {
            return Err(OcbError::InvalidLength);
        }
        // 1. Reset internal state (nonce, block counter, accumulators, load cipher key)
        self.nonce         = nonce & !OCB_TOP_4_BITS; // Update the UNIQUE nonce.
        self.block_counter = 0u64; // Reset the block counter.
        self.tf.set_key(key);      // Load the cipher key.
        self.ad_acc.fill(0u64);    // Zero the AD accumulator.
        self.data_acc.fill(0u64);  // Zero the DATA accumulator.

        let mut tag_flags = OCB_FLAG_TAG;

        // 2. Absorb additional data.
        if !ad.is_empty() {
            self.absorb_ad(ad);
            tag_flags |= OCB_FLAG_AD;
        }

        // 3. Encrypt the plaintext.
        if !pt.is_empty() {
            tag_flags |= OCB_FLAG_DATA;
            if self.encrypt(ct_out, pt) {
                tag_flags |= OCB_FLAG_PARTIAL;
            }
        }

        // 4. Finalize the authentication tag.
        self.finalize_tag(tag_out, tag_flags);

        // 5. Sanitize internal state.
        self.sanitize();
        Ok(())
    }

    /// Constant-time byte comparison.
    fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() { return false; }
        let mut diff = 0u8;
        for i in 0usize..a.len() {
            diff |= a[i] ^ b[i];
        }
        diff == 0u8
    }

    pub fn open(
        &mut self,
        pt_out: &mut [u8],
        key: &[u64; NUM_KEY_WORDS],
        nonce: u64,
        ad: &[u8],
        ct: &[u8],
        tag: &[u8; OCB_TAG_BYTES],
    ) -> Result<(), OcbError> {
        // Size check.
        if pt_out.len() != ct.len() {
            return Err(OcbError::InvalidLength);
        }

        // 1. Reset internal state (nonce, block counter, accumulators, load cipher key)
        self.nonce         = nonce & !OCB_TOP_4_BITS;
        self.block_counter = 0u64; // Reset the block counter.
        self.tf.set_key(key); // Load the cipher key.
        self.ad_acc.fill(0u64); // Zero the AD accumulator.
        self.data_acc.fill(0u64); // Zero the DATA accumulator.

        let mut tag_flags = OCB_FLAG_TAG;

        // 2. Absorb AD
        if !ad.is_empty() {
            self.absorb_ad(ad);
            tag_flags |= OCB_FLAG_AD;
        }

        // 3. Decrypt ciphertext into @pt_out.
        if !ct.is_empty() {
            tag_flags |= OCB_FLAG_DATA;
            if self.decrypt(pt_out, ct) {
                tag_flags |= OCB_FLAG_PARTIAL;
            }
        }

        // 4. Recompute tag
        let mut computed_tag = [0u8; OCB_TAG_BYTES];
        self.finalize_tag(&mut computed_tag, tag_flags);

        // 5. Constant-time compare
        let is_equal: bool = Self::ct_eq(&computed_tag, tag);
        secure_zero(&mut computed_tag);

        // 6. Sanitize internal state.
        self.sanitize();

        // 7. Verify that the tags match.
        if !is_equal {
            return Err(OcbError::TagMismatch);
        }

        // Successful decryption.
        Ok(())
    }
} // ~ impl Threefish512Ocb

#[cfg(test)]
mod ocb_tests {
    use super::*;

    // Helper: Generate deterministic pseudo-random bytes.
    fn fill_rand(buf: &mut [u8], seed: u64) {
        let mut x = seed;
        for b in buf {
            x ^= x << 7;
            x ^= x >> 9;
            x ^= x << 8;
            *b = (x & 0xff) as u8;
        }
    }

    enum Handle {
        SEAL,
        OPEN
    }

    fn handle(res: Result<(), OcbError>, hnd: Handle) {
        match hnd {
            Handle::SEAL => {
                match res {
                    Ok(_) => {},
                    Err(OcbError::InvalidLength) => {
                        panic!("ocb.seal() failed with InvalidLength!");
                    },
                    Err(OcbError::TagMismatch) => {
                        panic!("ocb.seal() failed with a TagMismatch error! It's not even supposed to be capable of returning that!");
                    },
                }
            },
            Handle::OPEN => {
                match res {
                    Ok(_) => {},
                    Err(OcbError::InvalidLength) => {
                        panic!("ocb.open() failed with InvalidLength!");
                    },
                    Err(OcbError::TagMismatch) => {
                        panic!("ocb.open() failed with a TagMismatch error!");
                    },
                }
            },
        }
    }

    // 1. Empty AD + Empty PT.
    #[test]
    fn test_empty_ad_empty_pt() {
        let mut ocb  = Threefish512Ocb::new();
        let key       = [0u64; NUM_KEY_WORDS];
        let nonce     = 0x1111_2222_3333_4444u64;
        let ad: &[u8] = &[];
        let pt: &[u8] = &[];
        let mut ct: &mut [u8] = &mut [];
        let mut tag = [0u8; OCB_TAG_BYTES];

        let res = ocb.seal(ct, &mut tag, &key, nonce, ad, pt);
        handle(res, Handle::SEAL);
        let mut ocb2 = Threefish512Ocb::new();
        let mut out: &mut[u8] = &mut[];

        let res2 = ocb2.open(out, &key, nonce & !OCB_TOP_4_BITS, ad, ct, &mut tag);
        println!("normal nonce: {:x}", nonce);
        println!("nonce mased: {:x}", nonce & !OCB_TOP_4_BITS);
        handle(res2, Handle::OPEN);
    }

    // 2. Empty AD + non-empty PT.
    #[test]
    fn empty_ad_nonempty_pt() {
        let mut ocb = Threefish512Ocb::new();
        let key      = [1u64; NUM_KEY_WORDS];
        let nonce    = 0xABCD_EF01_2345_6789u64;

        let ad = &[];
        let pt = b"Hello world!";
        let mut ct  = vec![0u8; pt.len()];
        let mut tag = [0u8; OCB_TAG_BYTES];

        let res = ocb.seal(&mut ct, &mut tag, &key, nonce, ad, pt);
        handle(res, Handle::SEAL);

        let mut ocb2 = Threefish512Ocb::new();
        let mut out   = vec![0u8; pt.len()];
        let res2      = ocb2.open(&mut out, &key, nonce, ad, &ct, &tag);
        handle(res2, Handle::OPEN);

        assert_eq!(out, pt);
    }

    // 3. Non-empty AD + empty PT.
    #[test]
    fn nonempty_ad_empty_pt() {
        let mut ocb = Threefish512Ocb::new();
        let key   = [2u64; NUM_KEY_WORDS];
        let nonce = 0xDEAD_BEEF_DEAD_BEEF;

        let ad = b"metadata";
        let pt = &[];
        let mut ct = [];
        let mut tag = [0u8; OCB_TAG_BYTES];

        let res = ocb.seal(&mut ct, &mut tag, &key, nonce, ad, pt);
        handle(res, Handle::SEAL);

        let mut ocb2 = Threefish512Ocb::new();
        let mut out = [];
        
        let res2 = ocb2.open(&mut out, &key, nonce, ad, &ct, &tag);
        handle(res2, Handle::OPEN);
    }

    // 4. Multi-block plaintext.
    #[test]
    fn multiblock_pt() {
        let mut ocb = Threefish512Ocb::new();
        let key     = [3u64; NUM_KEY_WORDS];
        let nonce   = 0xCAFEBABECAFEBABE;

        let mut pt = vec![0u8; 200];
        fill_rand(&mut pt, 12345u64);

        let ad = b"header";
        let mut ct = vec![0u8; pt.len()];
        let mut tag = [0u8; OCB_TAG_BYTES];

        let res = ocb.seal(&mut ct, &mut tag, &key, nonce, ad, &pt);
        handle(res, Handle::SEAL);

        let mut ocb2 = Threefish512Ocb::new();
        let mut out   = vec![0u8; pt.len()];
        let res2 = ocb2.open(&mut out, &key, nonce, ad, &ct, &tag);
        handle(res2, Handle::OPEN);

        assert_eq!(out, pt);
    }

    // 5. Payload tampering detection.
    #[test]
    fn payload_tamper_detection() {
        let mut ocb = Threefish512Ocb::new();
        let key = [4u64; NUM_KEY_WORDS];
        let nonce = 0x9999_8888_7777_6666u64;

        let pt = b"Attack at dawn";
        let ad = b"orders";
        let mut ct = vec![0u8; pt.len()];
        let mut tag = [0u8; OCB_TAG_BYTES];

        let res = ocb.seal(&mut ct, &mut tag, &key, nonce, ad, pt);
        handle(res, Handle::SEAL);

        ct[0] ^= 0xFFu8;

        let mut ocb2 = Threefish512Ocb::new();
        let mut out   = vec![0u8; pt.len()];
        let res2      = ocb2.open(&mut out, &key, nonce, ad, &ct, &tag);

        assert!(matches!(res2, Err(OcbError::TagMismatch)));
    }

    // 6. AD tampering detection.
    #[test]
    fn ad_tamper_detection() {
        let mut ocb = Threefish512Ocb::new();
        let key = [5u64; NUM_KEY_WORDS];
        let nonce = 0x5555_4444_3333_2222u64;

        let pt = b"Attack at dawn";
        let mut ad = Vec::<u8>::from(b"orders");
        let mut ct = vec![0u8; pt.len()];
        let mut tag = [0u8; OCB_TAG_BYTES];

        let res = ocb.seal(&mut ct, &mut tag, &key, nonce, &ad, pt);
        handle(res, Handle::SEAL);

        ad[5] = b'z'; // "orderz"

        let mut ocb2 = Threefish512Ocb::new();
        let mut out   = vec![0u8; pt.len()];
        let res2      = ocb2.open(&mut out, &key, nonce, &ad, &ct, &tag);

        assert!(matches!(res2, Err(OcbError::TagMismatch)));
    }

    // 7. Randomized round-trip fuzzing.
    #[test]
    fn fuzz_roundtrip() {
        let mut ocb_0 = Threefish512Ocb::new();
        let mut ocb_1 = Threefish512Ocb::new();

        let mut key = [0u64; NUM_KEY_WORDS];
        fill_rand(block_as_u8_mut!(&mut key), 777);

        for i in 0usize..50usize {
            let nonce = 0xABCD_EF00_0000_0000u64 + i as u64;

            let mut pt = vec![0u8; (i * 13) % 257];
            fill_rand(&mut pt, i as u64);

            let mut ad = vec![0u8; (i * 7) % 113];
            fill_rand(&mut ad, (i * 999) as u64);

            let mut ct  = vec![0u8; pt.len()];
            let mut tag = [0u8; OCB_TAG_BYTES];

            let res_0 = ocb_0.seal(&mut ct, &mut tag, &key, nonce, &ad, &pt);
            handle(res_0, Handle::SEAL);

            let mut out = vec![0u8; pt.len()];
            let res_1 = ocb_1.open(&mut out, &key, nonce, &ad, &ct, &tag);
            handle(res_1, Handle::OPEN);

            assert_eq!(out, pt);
        }
    }
}
