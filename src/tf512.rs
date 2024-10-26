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
pub const CONST_240: u64 = u64::from_le(0x1bd11bdaa9fc1a22);
pub const NUM_CTR_IV_BYTES: usize = 32;
pub const NUM_CTR_IV_WORDS: usize = 4;

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

        let s: u64 = u64::from_le($state_words[0]);
        let k: u64 = u64::from_le($key_words[SUBKEY_IDX % NUM_KEY_WORDS_WITH_PARITY]);
        $state_words[0] = s.wrapping_add(k).to_le();

        let s: u64 = u64::from_le($state_words[1]);
        let k: u64 = u64::from_le($key_words[(SUBKEY_IDX + 1) % NUM_KEY_WORDS_WITH_PARITY]);
        $state_words[1] = s.wrapping_add(k).to_le();

        let s: u64 = u64::from_le($state_words[2]);
        let k: u64 = u64::from_le($key_words[(SUBKEY_IDX + 2) % NUM_KEY_WORDS_WITH_PARITY]);
        $state_words[2] = s.wrapping_add(k).to_le();

        let s: u64 = u64::from_le($state_words[3]);
        let k: u64 = u64::from_le($key_words[(SUBKEY_IDX + 3) % NUM_KEY_WORDS_WITH_PARITY]);
        $state_words[3] = s.wrapping_add(k).to_le();

        let s: u64 = u64::from_le($state_words[4]);
        let k: u64 = u64::from_le($key_words[(SUBKEY_IDX + 4) % NUM_KEY_WORDS_WITH_PARITY]);
        $state_words[4] = s.wrapping_add(k).to_le();

        let s: u64 = u64::from_le($state_words[5]);
        let k: u64 = u64::from_le($key_words[(SUBKEY_IDX + 5) % NUM_KEY_WORDS_WITH_PARITY]);
        let t: u64 = u64::from_le($tweak_words[SUBKEY_IDX % 3]);
        $state_words[5] = s.wrapping_add(k.wrapping_add(t)).to_le();

        let s: u64 = u64::from_le($state_words[6]);
        let k: u64 = u64::from_le($key_words[(SUBKEY_IDX + 6) % NUM_KEY_WORDS_WITH_PARITY]);
        let t: u64 = u64::from_le($tweak_words[(SUBKEY_IDX + 1) % 3]);
        $state_words[6] = s.wrapping_add(k.wrapping_add(t)).to_le();

        let s: u64 = u64::from_le($state_words[7]);
        let k: u64 = u64::from_le($key_words[(SUBKEY_IDX + 7) % NUM_KEY_WORDS_WITH_PARITY]);
        $state_words[7] = s.wrapping_add(k.wrapping_add(SUBKEY_IDX as u64)).to_le();
    }}
}
macro_rules! permute {
    ($state_words:expr) =>
    { 
        let mut w0: u64 = $state_words[6];
        $state_words[6] = $state_words[0];
        let w1: u64     = $state_words[4];
        $state_words[4] = w0;
        w0 = $state_words[2];
        $state_words[2] = w1;
        $state_words[0] = w0;
        w0 = $state_words[3];
        $state_words[3] = $state_words[7];
        $state_words[7] = w0;
    }
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

pub trait Threefish512 {
    /// Methods.
    fn encipher_1(
        &mut self,
        encipher_io: &mut [u64; NUM_BLOCK_WORDS]
    );
    fn encipher_2<'a>(
        &mut self,
        ciphertext_output: &'a mut [u64; NUM_BLOCK_WORDS],
        plaintext_input:   &'a     [u64; NUM_BLOCK_WORDS]
    );

    /// Procedures.
    fn compute_parity_words(
        key:   &mut [u64],
        tweak: &mut [u64]
    )
    {
        debug_assert!(key.len()   >= NUM_KEY_WORDS_WITH_PARITY);
        debug_assert!(tweak.len() >= NUM_TWEAK_WORDS_WITH_PARITY);
        // Accumulate the xor of all the key words together.
        let key_parity: u64 = unsafe {
            *key.get_unchecked_mut(0) ^
            *key.get_unchecked_mut(1) ^
            *key.get_unchecked_mut(2) ^
            *key.get_unchecked_mut(3) ^
            *key.get_unchecked_mut(4) ^
            *key.get_unchecked_mut(5) ^
            *key.get_unchecked_mut(6) ^
            *key.get_unchecked_mut(7) ^
            CONST_240
        };
        // Accumulate the xor of the two tweak words.
        let tweak_parity: u64 = unsafe {
            *tweak.get_unchecked_mut(0) ^ *tweak.get_unchecked_mut(1)
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
        initialization_vector: & [u8]
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
        xor_input:     & [u8],
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

impl Threefish512 for Threefish512Static {
    fn encipher_1(
        &mut self,
        encipher_io: &mut [u64; NUM_BLOCK_WORDS]
    )
    {
        self.state = *encipher_io;

        encrypt_static_phase_0!(self.key_schedule, self.state,  0);
        encrypt_static_phase_1!(self.key_schedule, self.state,  4);
        encrypt_static_phase_0!(self.key_schedule, self.state,  8);
        encrypt_static_phase_1!(self.key_schedule, self.state, 12);
        encrypt_static_phase_0!(self.key_schedule, self.state, 16);
        encrypt_static_phase_1!(self.key_schedule, self.state, 20);
        encrypt_static_phase_0!(self.key_schedule, self.state, 24);
        encrypt_static_phase_1!(self.key_schedule, self.state, 28);
        encrypt_static_phase_0!(self.key_schedule, self.state, 32);
        encrypt_static_phase_1!(self.key_schedule, self.state, 36);
        encrypt_static_phase_0!(self.key_schedule, self.state, 40);
        encrypt_static_phase_1!(self.key_schedule, self.state, 44);
        encrypt_static_phase_0!(self.key_schedule, self.state, 48);
        encrypt_static_phase_1!(self.key_schedule, self.state, 52);
        encrypt_static_phase_0!(self.key_schedule, self.state, 56);
        encrypt_static_phase_1!(self.key_schedule, self.state, 60);
        encrypt_static_phase_0!(self.key_schedule, self.state, 64);
        encrypt_static_phase_1!(self.key_schedule, self.state, 68);
        add_subkey_static!(self.key_schedule, self.state, 72);

        *encipher_io = self.state;
    }
    fn encipher_2<'a>(
        self: &mut Self,
        ciphertext_output: &'a mut [u64; NUM_BLOCK_WORDS],
        plaintext_input:   &'a     [u64; NUM_BLOCK_WORDS]
    )
    {
        self.state = *plaintext_input;

        encrypt_static_phase_0!(self.key_schedule, self.state,  0);
        encrypt_static_phase_1!(self.key_schedule, self.state,  4);
        encrypt_static_phase_0!(self.key_schedule, self.state,  8);
        encrypt_static_phase_1!(self.key_schedule, self.state, 12);
        encrypt_static_phase_0!(self.key_schedule, self.state, 16);
        encrypt_static_phase_1!(self.key_schedule, self.state, 20);
        encrypt_static_phase_0!(self.key_schedule, self.state, 24);
        encrypt_static_phase_1!(self.key_schedule, self.state, 28);
        encrypt_static_phase_0!(self.key_schedule, self.state, 32);
        encrypt_static_phase_1!(self.key_schedule, self.state, 36);
        encrypt_static_phase_0!(self.key_schedule, self.state, 40);
        encrypt_static_phase_1!(self.key_schedule, self.state, 44);
        encrypt_static_phase_0!(self.key_schedule, self.state, 48);
        encrypt_static_phase_1!(self.key_schedule, self.state, 52);
        encrypt_static_phase_0!(self.key_schedule, self.state, 56);
        encrypt_static_phase_1!(self.key_schedule, self.state, 60);
        encrypt_static_phase_0!(self.key_schedule, self.state, 64);
        encrypt_static_phase_1!(self.key_schedule, self.state, 68);
        add_subkey_static!(self.key_schedule, self.state, 72);

        *ciphertext_output = self.state;
    }
}
impl Threefish512Static {
    pub fn new(
        key:   &mut [u64],
        tweak: &mut [u64]
    ) -> Self
    {
        debug_assert!(key.len()   == NUM_KEY_WORDS_WITH_PARITY);
        debug_assert!(tweak.len() == NUM_TWEAK_WORDS_WITH_PARITY);
        let mut tf = Threefish512Static {
            key_schedule: [0; NUM_STATIC_KEYSCHEDULE_WORDS],
            state:        [0; NUM_BLOCK_WORDS]
        };
        Self::compute_parity_words(key, tweak);
        make_subkey!(tf.key_schedule, key, tweak,  0);
        make_subkey!(tf.key_schedule, key, tweak,  1);
        make_subkey!(tf.key_schedule, key, tweak,  2);
        make_subkey!(tf.key_schedule, key, tweak,  3);
        make_subkey!(tf.key_schedule, key, tweak,  4);
        make_subkey!(tf.key_schedule, key, tweak,  5);
        make_subkey!(tf.key_schedule, key, tweak,  6);
        make_subkey!(tf.key_schedule, key, tweak,  7);
        make_subkey!(tf.key_schedule, key, tweak,  8);
        make_subkey!(tf.key_schedule, key, tweak,  9);
        make_subkey!(tf.key_schedule, key, tweak, 10);
        make_subkey!(tf.key_schedule, key, tweak, 11);
        make_subkey!(tf.key_schedule, key, tweak, 12);
        make_subkey!(tf.key_schedule, key, tweak, 13);
        make_subkey!(tf.key_schedule, key, tweak, 14);
        make_subkey!(tf.key_schedule, key, tweak, 15);
        make_subkey!(tf.key_schedule, key, tweak, 16);
        make_subkey!(tf.key_schedule, key, tweak, 17);
        make_subkey!(tf.key_schedule, key, tweak, 18);

        tf
    }
}

impl Threefish512 for Threefish512Dynamic {
    fn encipher_1(
        &mut self,
        encipher_io: &mut [u64; NUM_BLOCK_WORDS]
    )
    {
        self.state = *encipher_io;
        encrypt_dynamic_phase_0!(self.parity_key, self.state, self.parity_tweak,  0);
        encrypt_dynamic_phase_1!(self.parity_key, self.state, self.parity_tweak,  4);
        encrypt_dynamic_phase_0!(self.parity_key, self.state, self.parity_tweak,  8);
        encrypt_dynamic_phase_1!(self.parity_key, self.state, self.parity_tweak, 12);
        encrypt_dynamic_phase_0!(self.parity_key, self.state, self.parity_tweak, 16);
        encrypt_dynamic_phase_1!(self.parity_key, self.state, self.parity_tweak, 20);
        encrypt_dynamic_phase_0!(self.parity_key, self.state, self.parity_tweak, 24);
        encrypt_dynamic_phase_1!(self.parity_key, self.state, self.parity_tweak, 28);
        encrypt_dynamic_phase_0!(self.parity_key, self.state, self.parity_tweak, 32);
        encrypt_dynamic_phase_1!(self.parity_key, self.state, self.parity_tweak, 36);
        encrypt_dynamic_phase_0!(self.parity_key, self.state, self.parity_tweak, 40);
        encrypt_dynamic_phase_1!(self.parity_key, self.state, self.parity_tweak, 44);
        encrypt_dynamic_phase_0!(self.parity_key, self.state, self.parity_tweak, 48);
        encrypt_dynamic_phase_1!(self.parity_key, self.state, self.parity_tweak, 52);
        encrypt_dynamic_phase_0!(self.parity_key, self.state, self.parity_tweak, 56);
        encrypt_dynamic_phase_1!(self.parity_key, self.state, self.parity_tweak, 60);
        encrypt_dynamic_phase_0!(self.parity_key, self.state, self.parity_tweak, 64);
        encrypt_dynamic_phase_1!(self.parity_key, self.state, self.parity_tweak, 68);
        add_subkey_dynamic!(self.parity_key, self.state, self.parity_tweak, 72);
        *encipher_io = self.state;
    }
    fn encipher_2<'a>(
        self: &mut Self,
        ciphertext_output: &'a mut [u64; NUM_BLOCK_WORDS],
        plaintext_input:   &'a     [u64; NUM_BLOCK_WORDS]
    )
    {
        self.state = *plaintext_input;
        encrypt_dynamic_phase_0!(self.parity_key, self.state, self.parity_tweak,  0);
        encrypt_dynamic_phase_1!(self.parity_key, self.state, self.parity_tweak,  4);
        encrypt_dynamic_phase_0!(self.parity_key, self.state, self.parity_tweak,  8);
        encrypt_dynamic_phase_1!(self.parity_key, self.state, self.parity_tweak, 12);
        encrypt_dynamic_phase_0!(self.parity_key, self.state, self.parity_tweak, 16);
        encrypt_dynamic_phase_1!(self.parity_key, self.state, self.parity_tweak, 20);
        encrypt_dynamic_phase_0!(self.parity_key, self.state, self.parity_tweak, 24);
        encrypt_dynamic_phase_1!(self.parity_key, self.state, self.parity_tweak, 28);
        encrypt_dynamic_phase_0!(self.parity_key, self.state, self.parity_tweak, 32);
        encrypt_dynamic_phase_1!(self.parity_key, self.state, self.parity_tweak, 36);
        encrypt_dynamic_phase_0!(self.parity_key, self.state, self.parity_tweak, 40);
        encrypt_dynamic_phase_1!(self.parity_key, self.state, self.parity_tweak, 44);
        encrypt_dynamic_phase_0!(self.parity_key, self.state, self.parity_tweak, 48);
        encrypt_dynamic_phase_1!(self.parity_key, self.state, self.parity_tweak, 52);
        encrypt_dynamic_phase_0!(self.parity_key, self.state, self.parity_tweak, 56);
        encrypt_dynamic_phase_1!(self.parity_key, self.state, self.parity_tweak, 60);
        encrypt_dynamic_phase_0!(self.parity_key, self.state, self.parity_tweak, 64);
        encrypt_dynamic_phase_1!(self.parity_key, self.state, self.parity_tweak, 68);
        add_subkey_dynamic!(self.parity_key, self.state, self.parity_tweak, 72);
        *ciphertext_output = self.state;
    }
}
impl Threefish512Dynamic {
    pub fn new(
        key:   & [u64],
        tweak: & [u64]
    ) -> Self
    {
        let mut tf = Self {
            parity_key:   [0u64; NUM_KEY_WORDS_WITH_PARITY],
            parity_tweak: [0u64; NUM_TWEAK_WORDS_WITH_PARITY],
            state:        [0u64; NUM_BLOCK_WORDS]
        };
        tf.rekey(key, tweak);

        tf
    }
    pub fn rekey(
        &mut self,
        key:   & [u64],
        tweak: & [u64]
    )
    {
        debug_assert!(key.len()   >= NUM_KEY_WORDS);
        debug_assert!(tweak.len() >= NUM_TWEAK_WORDS);
        self.parity_key[..NUM_KEY_WORDS].copy_from_slice(&key[..NUM_KEY_WORDS]);
        self.parity_tweak[..NUM_TWEAK_WORDS].copy_from_slice(&tweak[..NUM_TWEAK_WORDS]);
        Self::compute_parity_words(&mut self.parity_key, &mut self.parity_tweak);
    }
}
