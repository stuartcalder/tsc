
pub const NUM_BLOCK_BITS: usize = 512;
pub const NUM_BLOCK_BYTES: usize = 64;
pub const NUM_BLOCK_WORDS: usize = 8;

pub const NUM_KEY_BITS: usize = NUM_BLOCK_BITS;
pub const NUM_KEY_BYTES: usize = NUM_BLOCK_BYTES;
pub const NUM_KEY_WORDS: usize = NUM_BLOCK_WORDS;

pub const NUM_TWEAK_BITS: usize = 128;
pub const NUM_TWEAK_BYTES: usize = 16;
pub const NUM_TWEAK_WORDS: usize = 2;

pub const NUM_ROUNDS: usize = 72;
pub const NUM_SUBKEYS: usize = 19;
pub const NUM_KEY_WORDS_WITH_PARITY: usize = 9;
pub const NUM_TWEAK_WORDS_WITH_PARITY: usize = 3;

pub const CONST_240: u64 = 0x1bd11bdaa9fc1a22;
pub const NUM_CTR_IV_BYTES: usize = 32;

macro_rules! store_word {
    ($key_schedule:expr,
     $key_words:expr,
     $subkey_num:literal,
     $subkey_idx:literal,
     $increment:expr) =>
     {{
        const KEY_SCHEDULE_IDX: usize = ($subkey_num * NUM_KEY_WORDS) + $subkey_idx;
        const KEY_WORD_IDX: usize     = ($subkey_num + $subkey_idx) % NUM_KEY_WORDS_WITH_PARITY;
        unsafe {
        let word: &mut u64 = $key_schedule.get_unchecked_mut(KEY_SCHEDULE_IDX);
        *word = *$key_words.get_unchecked_mut(KEY_WORD_IDX) + $increment;
        }
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
        let increment: u64 = unsafe {
            *$tweak_words.get_unchecked_mut($subkey_num % 3)
        };
        store_word!($key_schedule, $key_words, $subkey_num, 5usize, increment);
        let increment: u64 = unsafe {
            *$tweak_words.get_unchecked_mut(($subkey_num + 1) % 3)
        };
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
        let w0: mut u64 = unsafe { *$state_words.get_unchecked_mut(W0) };
        let w1:     u64 = unsafe { *$state_words.get_unchecked_mut(W1) };
        w0 += w1;
        unsafe {
            *$state_words.get_unchecked_mut(W0) = w0;
            *$state_words.get_unchecked_mut(W1) = w1.rotate_left($rot_const) ^ w0;
        }
     }}
}
macro_rules! subkey_idx    { ($round_num:literal) => ($round_num / 4usize) }
macro_rules! subkey_offset { ($round_num:literal) => (subkey_idx!($round_num) * NUM_BLOCK_WORDS) }
macro_rules! use_subkey_static {
    ($key_schedule_words:expr, $state_words:expr,
     $operation:tt, $round_num:literal) =>
    {{
        let state : mut u64 = unsafe { *$state_words.get_unchecked_mut(0) };
        let keysch: mut u64 = unsafe { *$key_schedule.get_unchecked_mut(subkey_offset!($round_num)) };
        *$state_words.get_unchecked_mut(0) = state $operation keysch;

        state  = unsafe { *$state_words.get_unchecked_mut(1) };
        keysch = unsafe { *$key_schedule.get_unchecked_mut(subkey_offset!($round_num) + 1) };
        *$state_words.get_unchecked_mut(1) = state $operation keysch;

        state = unsafe  { *$state_words.get_unchecked_mut(2) };
        keysch = unsafe { *$key_schedule.get_unchecked_mut(subkey_offset!($round_num) + 2) };
        *$state_words.get_unchecked_mut(2) = state $operation keysch;

        state = unsafe  { *$state_words.get_unchecked_mut(3) };
        keysch = unsafe { *$key_schedule.get_unchecked_mut(subkey_offset!($round_num) + 3) };
        *$state_words.get_unchecked_mut(3) = state $operation keysch;

        state = unsafe  { *$state_words.get_unchecked_mut(4) };
        keysch = unsafe { *$key_schedule.get_unchecked_mut(subkey_offset!($round_num) + 4) };
        *$state_words.get_unchecked_mut(4) = state $operation keysch;

        state = unsafe  { *$state_words.get_unchecked_mut(5) };
        keysch = unsafe { *$key_schedule.get_unchecked_mut(subkey_offset!($round_num) + 5) };
        *$state_words.get_unchecked_mut(5) = state $operation keysch;

        state = unsafe  { *$state_words.get_unchecked_mut(6) };
        keysch = unsafe { *$key_schedule.get_unchecked_mut(subkey_offset!($round_num) + 6) };
        *$state_words.get_unchecked_mut(6) = state $operation keysch;

        state = unsafe  { *$state_words.get_unchecked_mut(7) };
        keysch = unsafe { *$key_schedule.get_unchecked_mut(subkey_offset!($round_num) + 7) };
        *$state_words.get_unchecked_mut(7) = state $operation keysch;
    }}
}
macro_rules! add_subkey_static {
    ($key_schedule_words:expr, $state_words:expr, $round_num:literal) =>
    {
        use_subkey_static!($key_schedule_words, $state_words, +, $round_num);
    }
}
macro_rules! subtract_subkey_static {
    ($key_schedule_words:expr, $state_words:expr, $round_num:literal) =>
    {
        use_subkey_static!($key_schedule_words, $state_words, -, $round_num);
    }
}
macro_rules! permute {
    ($state_words:expr) =>
    { unsafe {
        let w0: mut u64 = *$state_words.get_unchecked_mut(6);
        *$state_words.get_unchecked_mut(6) = *$state_words.get_unchecked_mut(0);
        let w1:     u64 = *$state_words.get_unchecked_mut(4);
        *$state_words.get_unchecked_mut(4) = w0;
        w0 = *$state_words.get_unchecked_mut(2);
        *$state_words.get_unchecked_mut(2) = w1;
        *$state_words.get_unchecked_mut(0) = w0;
        w0 = *$state_words.get_unchecked_mut(3);
        *$state_words.get_unchecked_mut(3) = *$state_words.get_unchecked_mut(7);
        *$state_words.get_unchecked_mut(7) = w0;
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

pub trait ThreeFish {
    /// Methods.
    fn init(
        self:  &mut Self,
        key:   &mut [u64],
        tweak: &mut [u64]
    );
    fn encipher_1(
        self: &mut Self,
        encipher_io: &mut [u8]
    );
    fn encipher_2<'a>(
        self: &mut Self,
        ciphertext_output: &'a mut [u8],
        plaintext_input:   &'a     [u8]
    );

    /// Procedures.
    fn compute_parity_words(
        key:   & mut [u64],
        tweak: & mut [u64]
    )
    {
        assert!(key.len()   == NUM_KEY_WORDS_WITH_PARITY);
        assert!(tweak.len() == NUM_TWEAK_WORDS_WITH_PARITY);
        // Accumulate the xor of all the words together.
        let key_parity: u64 = unsafe {
            *key.get_unchecked(0) ^
            *key.get_unchecked(1) ^
            *key.get_unchecked(2) ^
            *key.get_unchecked(3) ^
            *key.get_unchecked(4) ^
            *key.get_unchecked(5) ^
            *key.get_unchecked(6) ^
            *key.get_unchecked(7)
        };
        // Accumulate the xor of the two tweak words.
        let tweak_parity: u64 = unsafe {
            *tweak.get_unchecked(0) ^
            *tweak.get_unchecked(1)
        };

        unsafe {
            *key.get_unchecked_mut(NUM_KEY_WORDS)     = key_parity;
            *tweak.get_unchecked_mut(NUM_TWEAK_WORDS) = tweak_parity;
        }
    } // ~ compute_parity_words()
}

pub trait StreamCipher {
    fn init(
        self: &mut Self,
        initialization_vector: &[u8]
    );
    fn xor_1(
        self: &mut Self,
        xor_io: &mut [u8],
        xor_count: u64,
        keystream_index: u64
    );
    fn xor_2(
        self: &mut Self,
        xor_output: &mut [u8],
        xor_input:  &    [u8],
        xor_count:       u64,
        keystream_index: u64
    );
}

pub const NUM_STATIC_KEYSCHEDULE_WORDS: usize = NUM_KEY_WORDS * NUM_SUBKEYS;

pub struct Threefish512Static {
    key_schedule: [u64; NUM_STATIC_KEYSCHEDULE_WORDS],
    state:        [u64; NUM_BLOCK_WORDS],
}
pub struct Threefish512Dynamic {
    parity_key:   [u64; NUM_KEY_WORDS_WITH_PARITY],
    parity_tweak: [u64; NUM_TWEAK_WORDS_WITH_PARITY],
    state:        [u64; NUM_BLOCK_WORDS],
}

impl ThreeFish for Threefish512Static {
    fn init<'a>(
        &mut self,
        key:   &'a mut [u64],
        tweak: &'a mut [u64]
    )
    {
        Self::compute_parity_words(key, tweak);
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
    fn encipher_1(
        self: &mut Self,
        encipher_io: &mut [u8]
    )
    {
        //TODO
    }
    fn encipher_2<'a>(
        self: &mut Self,
        ciphertext_output: &'a mut [u8],
        plaintext_input:   &'a     [u8]
    )
    {
        assert!(ciphertext_output.len() == plaintext_input.len() && ciphertext_output.len() == self.state.len());
    }
}
