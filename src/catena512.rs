use crate::tf512;
use crate::ubi512;
use crate::skein512;

use tf512::{
    NUM_BLOCK_BYTES,
    NUM_BLOCK_WORDS,
    NUM_KEY_BYTES,
    NUM_KEY_WORDS
};
use ubi512::Ubi512;
use skein512::{
    Skein512,
    NUM_HASH_WORDS,
};

macro_rules! idx {
    ($i:expr) => {
        (($i) as usize * (NUM_HASH_BYTES as usize))
    }
}

macro_rules! hash_native {
    ($ubi:expr, $dest:expr, $src:expr) => {
        $ubi.threefish512.key[..NUM_KEY_WORDS].copy_from_slice(&skein512::NATIVE_INIT);
        $ubi.chain_message($src);
        $ubi.chain_output_native($dest);
    }
}

pub const WITHOUT_PHI_VERSION_ID: [u8; NUM_KEY_BYTES] = [
    0x79u8, 0xB5u8, 0x79u8, 0x1Eu8, 0x9Au8, 0xACu8, 0x02u8, 0x64u8,
    0x2Au8, 0xAAu8, 0x99u8, 0x1Bu8, 0xD5u8, 0x47u8, 0xEDu8, 0x14u8,
    0x74u8, 0x4Du8, 0x72u8, 0xBFu8, 0x13u8, 0x22u8, 0x54u8, 0xC9u8,
    0xADu8, 0xD6u8, 0xB9u8, 0xBEu8, 0xE8u8, 0x70u8, 0x18u8, 0xE2u8,
    0xAAu8, 0x51u8, 0x50u8, 0xE2u8, 0x1Fu8, 0xCDu8, 0x90u8, 0x19u8,
    0xB6u8, 0x1Fu8, 0x0Eu8, 0xC6u8, 0x05u8, 0x00u8, 0xD6u8, 0xEDu8,
    0x7Cu8, 0xF2u8, 0x03u8, 0x53u8, 0xFDu8, 0x42u8, 0xA5u8, 0xA3u8,
    0x7Au8, 0x0Eu8, 0xBBu8, 0xB4u8, 0xA7u8, 0xEBu8, 0xDBu8, 0xABu8,
];

pub const WITH_PHI_VERSION_ID: [u8; NUM_KEY_BYTES] = [
    0x1Fu8, 0x23u8, 0x89u8, 0x58u8, 0x4Au8, 0x4Au8, 0xBBu8, 0xA5u8,
    0x9Fu8, 0x09u8, 0xCAu8, 0xD4u8, 0xEFu8, 0xACu8, 0x43u8, 0x1Du8,
    0xDEu8, 0x9Au8, 0xB0u8, 0xF8u8, 0x69u8, 0xAAu8, 0x50u8, 0xF3u8,
    0xEDu8, 0xCCu8, 0xB4u8, 0x7Du8, 0x6Du8, 0x4Fu8, 0x10u8, 0xB9u8,
    0x8Eu8, 0x6Au8, 0x68u8, 0xABu8, 0x6Eu8, 0x53u8, 0xBCu8, 0xD6u8,
    0xCFu8, 0xFCu8, 0xA7u8, 0x63u8, 0x94u8, 0x44u8, 0xBDu8, 0xC7u8,
    0xB9u8, 0x6Du8, 0x09u8, 0xF5u8, 0x66u8, 0x31u8, 0xA3u8, 0xC5u8,
    0xF3u8, 0x26u8, 0xEBu8, 0x6Fu8, 0xA6u8, 0xACu8, 0xB0u8, 0xA6u8,
];

pub const NUM_HASH_BYTES: usize = NUM_HASH_WORDS * 8;

pub const NUM_SALT_BYTES:     usize = 32;
pub const NUM_SALT_WORDS:     usize = NUM_SALT_BYTES / 8;
pub const MAX_PASSWORD_BYTES: usize = 125;
pub const NUM_TWEAK_BYTES:    usize = {
    NUM_BLOCK_BYTES + 1 + 1 + 2 + 2
};
pub const NUM_RNG_BYTES: usize = NUM_BLOCK_BYTES + 16;

pub const DOMAIN_PW_SCRAMBLER: u8 = 0u8;
pub const DOMAIN_KDF:          u8 = 1u8;
pub const DOMAIN_POW:          u8 = 2u8;

pub const NUM_MHF_BYTES: usize = NUM_BLOCK_BYTES * 2;
pub const NUM_MHF_WORDS: usize = NUM_MHF_BYTES / 8;

pub const NUM_TWEAK_PW_SALT_BYTES: usize = {
    NUM_TWEAK_BYTES + MAX_PASSWORD_BYTES + NUM_SALT_BYTES
};

pub const NUM_FLAP_BYTES:   usize = NUM_BLOCK_BYTES * 3;
pub const NUM_FLAP_WORDS:   usize = NUM_FLAP_BYTES / 8;
pub const NUM_PHI_BYTES:    usize = NUM_BLOCK_BYTES * 2;
pub const NUM_PHI_WORDS:    usize = NUM_PHI_BYTES / 8;

pub const NUM_CATENA_BYTES: usize = NUM_BLOCK_BYTES + 1;

pub const NUM_GAMMA_BUFFER_BYTES: usize = NUM_BLOCK_BYTES * 2;
pub const NUM_GAMMA_BUFFER_WORDS: usize = NUM_GAMMA_BUFFER_BYTES / 8;

pub const NUM_X_WORDS: usize = NUM_BLOCK_WORDS;
pub const NUM_X_BYTES: usize = NUM_X_WORDS * 8;

pub const NUM_HASH_INPUT_WORDS: usize = NUM_HASH_WORDS * 2;
pub const NUM_HASH_INPUT_BYTES: usize = NUM_HASH_INPUT_WORDS * 8;

pub const ERR_PW_TOO_LARGE: i32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Gamma {
    buffer: [u8; NUM_GAMMA_BUFFER_BYTES],
    rng:    [u8; NUM_RNG_BYTES],
}

#[repr(C)]
pub union Temp {
    gamma:         Gamma,
    flap:          [u8; NUM_FLAP_BYTES],
    phi:           [u8; NUM_PHI_BYTES],
    mhf:           [u8; NUM_MHF_BYTES],
    tweak_pw_salt: [u8; NUM_TWEAK_PW_SALT_BYTES],
    catena:        [u8; NUM_CATENA_BYTES],
}

#[repr(C)]
pub struct Catena {
    pub skein512:     Skein512,
    pub graph_memory: Box::<[u8]>,
    pub x:            [u8; NUM_X_BYTES],
    pub temp:         Temp,
    pub salt:         [u8; NUM_SALT_BYTES],
    pub g_high:       u8
}

impl Catena {
    // PUBLIC INTERFACE.
    pub fn new(g_high: u8) -> Catena {
        let num_allocated_bytes = {1usize << {g_high + 6}};
        let v = vec![0u8;  num_allocated_bytes];
        Catena {
            skein512:     Skein512::new(),
            temp:         unsafe { std::mem::zeroed() },
            x:            [0u8; NUM_X_BYTES],
            salt:         [0u8; NUM_SALT_BYTES],
            graph_memory: v.into_boxed_slice(),
            g_high
        }
    }
    pub fn get(
        &mut self,
        output: &mut [u8],
        password: &[u8],
        g_low:   u8,
        lambda:  u8,
        use_phi: bool) -> Result<(), i32>
    {
        if password.len() > MAX_PASSWORD_BYTES {
            return Err(ERR_PW_TOO_LARGE);
        }
        let g_low = if g_low > self.g_high {
            self.g_high
        } else {
            g_low
        };
        self.make_tweak(lambda, use_phi);
        {
            let ubi = &mut self.skein512.ubi512;
            let salt_offset = NUM_TWEAK_BYTES + password.len();
            let tps = unsafe {&mut self.temp.tweak_pw_salt};
            tps[NUM_TWEAK_BYTES..salt_offset].copy_from_slice(
                &password
            );
            tps[salt_offset..salt_offset + NUM_SALT_BYTES].copy_from_slice(
                &self.salt
            );
            hash_native!(ubi, &mut self.x, &tps[..salt_offset + NUM_SALT_BYTES]);
            // Initial flap.
        }
        self.flap((g_low + 1) / 2, lambda, use_phi);
        // Hash the X buffer into itself.
        hash_native!(&mut self.skein512.ubi512, &mut self.x, &self.x);
        // Iterate over the garlics with g, from g_low to g_high.
        for g in g_low..=self.g_high {
            self.flap(g, lambda, use_phi);
            unsafe {
                *self.temp.catena.get_unchecked_mut(0) = g;
                self.temp.catena[1..].copy_from_slice(&self.x);
            }
            hash_native!(&mut self.skein512.ubi512, &mut self.x, unsafe {&self.temp.catena});
        }
        // Zero over and free the memory. Copy the buffer out of the function.
        ssc::op::secure_zero(&mut self.graph_memory);
        output[..NUM_HASH_BYTES].copy_from_slice(&self.x);
        Ok(())
    }
    // PRIVATE IMPLEMENTATION.
    fn make_tweak(&mut self, lambda: u8, use_phi: bool) {
        let version_id = if use_phi {
            &WITH_PHI_VERSION_ID
        } else {
            &WITHOUT_PHI_VERSION_ID
        };
        unsafe { self.temp.tweak_pw_salt[..NUM_KEY_BYTES].copy_from_slice(version_id) };
        let mut i = NUM_KEY_BYTES;
        unsafe {*self.temp.tweak_pw_salt.get_unchecked_mut(i) = DOMAIN_KDF};
        i += 1;
        unsafe {*self.temp.tweak_pw_salt.get_unchecked_mut(i) = lambda};
        i += 1;
        unsafe {*self.temp.tweak_pw_salt.get_unchecked_mut(i) = NUM_BLOCK_BYTES as u8};
        i += 1;
        unsafe {*self.temp.tweak_pw_salt.get_unchecked_mut(i) = (NUM_BLOCK_BYTES >> 8) as u8};
        i += 1;
        unsafe {*self.temp.tweak_pw_salt.get_unchecked_mut(i) = NUM_SALT_BYTES as u8};
        i += 1;
        unsafe {*self.temp.tweak_pw_salt.get_unchecked_mut(i) = (NUM_SALT_BYTES >> 8) as u8};
    }
    fn flap(&mut self, garlic: u8, lambda: u8, use_phi: bool) {
        let ubi = &mut self.skein512.ubi512;
        let flap = unsafe{ &mut self.temp.flap };
        {
            const CONFIG: &[u64; NUM_KEY_WORDS] = &skein512::OUTPUT_16_WORDS_INIT;
            ubi.threefish512.key[..NUM_KEY_WORDS].copy_from_slice(
                CONFIG
            );
            ubi.chain_message(&self.x);
            ubi.chain_output(&mut flap[..NUM_HASH_BYTES * 2]);
        }
        hash_native!(ubi, &mut flap[idx!(1)..idx!(2)], &flap[idx!(0)..idx!(2)]);
        {
            let (low, high) = unsafe {
                flap.split_at_mut_unchecked(idx!(1))
            };
            // low  -> [tmp{0}],
            // high -> [tmp{1}, tmp{2}]
            high[idx!(1)..idx!(2)].copy_from_slice(low);
        }
        hash_native!(ubi, &mut flap[..idx!(1)], &flap[idx!(1)..idx!(3)]);
        self.graph_memory[idx!(0)..idx!(1)].copy_from_slice(&flap[idx!(1)..idx!(2)]);
        self.graph_memory[idx!(1)..idx!(2)].copy_from_slice(&flap[idx!(0)..idx!(1)]);
        let max_hash_index = (1u64 << garlic) - 1u64;
        if max_hash_index > 1 {
            hash_native!(ubi, &mut flap[idx!(2)..idx!(3)], &flap[idx!(0)..idx!(2)]);
            self.graph_memory[idx!(2)..idx!(3)].copy_from_slice(&flap[idx!(2)..idx!(3)]);
            {
                let (low, high) = unsafe {
                    flap.split_at_mut_unchecked(idx!(2))
                };
                // low  -> [tmp{0}, tmp{1}],
                // high -> [tmp{2}]
                low[idx!(1)..idx!(2)].copy_from_slice(&high[..idx!(1)]);
                high[..idx!(1)].copy_from_slice(&low[..idx!(1)]);
            }
            hash_native!(ubi, &mut flap[..idx!(1)], &flap[idx!(1)..idx!(3)]);
            self.graph_memory[idx!(3)..idx!(4)].copy_from_slice(
                &flap[..idx!(1)]
            );
        }
        let mut i = 4u64;
        while i <= max_hash_index {
            let next = i + 1;
            hash_native!(ubi, &mut flap[idx!(2)..idx!(3)], &flap[idx!(0)..idx!(2)]);
            let (temp_0, high) = unsafe {
                flap.split_at_mut_unchecked(idx!(1))
            };
            let (temp_1, temp_2) = unsafe {
                high.split_at_mut_unchecked(idx!(1))
            };
            temp_1.copy_from_slice(&temp_0);
            temp_0.copy_from_slice(&temp_2[..idx!(1)]);
            self.graph_memory[idx!(i)..idx!(next)].copy_from_slice(
                &temp_0
            );
            i = next;
        }
        self.gamma(garlic); //TODO: gamma()
        self.graph_hash(garlic, lambda); //TODO: graph_hash()
        if use_phi {
            self.phi(garlic);
        } else {
            self.x.copy_from_slice(
                &self.graph_memory[idx!(max_hash_index)..idx!(max_hash_index + 1)]
            );
        }
    }// ~ fn flap()
    fn gamma(&mut self, garlic: u8) {
        const RNG_CONFIG: [u64; NUM_KEY_WORDS] = [
            0xF0EFCBCABFD0047Bu64.to_be(),
            0xC05D3E3A1D53E49Fu64.to_be(),
            0x07BF4FF5CE675353u64.to_be(),
            0x9F0EF7FB22E6F4C3u64.to_be(),
            0x74CCB9EDC0502381u64.to_be(),
            0x65277AC2B2EAFB96u64.to_be(),
            0xCB91E29759941F6Du64.to_be(),
            0x51C39FE52731D1C5u64.to_be(),
        ];
        const NUM_RNG_OUTPUT_BYTES: usize = NUM_BLOCK_BYTES + 16;
        const J1_OFFSET:            usize = NUM_BLOCK_BYTES;
        const J2_OFFSET:            usize = J1_OFFSET + 8;
        const J2_END:               usize = J2_OFFSET + 8;
        let ubi = &mut self.skein512.ubi512;
        let mem = unsafe { &mut self.temp.gamma };
        mem.rng[..NUM_SALT_BYTES].copy_from_slice(&self.salt);
        unsafe { *mem.rng.get_unchecked_mut(NUM_SALT_BYTES) = garlic; }
        hash_native!(ubi, &mut mem.rng[..NUM_HASH_BYTES], &mem.rng[..NUM_SALT_BYTES + 1]);
        let count  = 1u64 << (((3 * garlic) + 3) / 4);
        let rshift = 64 - garlic;
        for _i in 0u64..count {
            ubi.threefish512.key[..NUM_KEY_WORDS].copy_from_slice(&RNG_CONFIG);
            ubi.chain_message(&mem.rng[..NUM_BLOCK_BYTES]);
            ubi.chain_output(&mut mem.rng[..NUM_RNG_OUTPUT_BYTES]);
            let mut j1 = u64::from_le_bytes(mem.rng[J1_OFFSET..J2_OFFSET].try_into().unwrap());
            j1 >>= rshift;
            let mut j2 = u64::from_le_bytes(mem.rng[J2_OFFSET..J2_END].try_into().unwrap());
            j2 >>= rshift;
            mem.buffer[idx!(0)..idx!(1)].copy_from_slice(&self.graph_memory[idx!(j1)..idx!(j1 + 1)]);
            mem.buffer[idx!(1)..idx!(2)].copy_from_slice(&self.graph_memory[idx!(j2)..idx!(j2 + 1)]);
            hash_native!(ubi, &mut self.graph_memory[idx!(j1)..idx!(j1 + 1)], &mem.buffer[..idx!(2)]);
        }
    }
    fn bit_reversal_idx(i: u64, garlic: u8) -> u64 {
        let mut i = i.swap_bytes();
        i = ((i & 0x0F0F0F0F0F0F0F0Fu64) << 4) |
            ((i & 0xF0F0F0F0F0F0F0F0u64) >> 4);
        i = ((i & 0x3333333333333333u64) << 2) |
            ((i & 0xCCCCCCCCCCCCCCCCu64) >> 2);
        i = ((i & 0x5555555555555555u64) << 1) |
            ((i & 0xAAAAAAAAAAAAAAAAu64) >> 1);
        i >> (64 - garlic)
    }
    fn graph_hash(&mut self, garlic: u8, lambda: u8) {
        let ubi = &mut self.skein512.ubi512;
        let mhf = unsafe {&mut self.temp.mhf};
        let garlic_end = (1u64 << garlic) - 1;

        for _j in 1u8..=lambda {
            mhf[idx!(0)..idx!(1)].copy_from_slice(&self.graph_memory[idx!(garlic_end)..idx!(garlic_end + 1)]);
            mhf[idx!(1)..idx!(2)].copy_from_slice(&self.graph_memory[idx!(0         )..idx!(1             )]);
            hash_native!(ubi, &mut self.graph_memory[..idx!(1)], &mhf[idx!(0)..idx!(2)]);
            for i in 1u64..=garlic_end {
                let bri = Self::bit_reversal_idx(i, garlic);
                mhf[idx!(0)..idx!(1)].copy_from_slice(&self.graph_memory[idx!(i - 1)..idx!(i      )]);
                mhf[idx!(1)..idx!(2)].copy_from_slice(&self.graph_memory[idx!(bri  )..idx!(bri + 1)]);
                hash_native!(ubi, &mut self.graph_memory[idx!(i)..idx!(i + 1)], &mhf[idx!(0)..idx!(2)]);
            }
        }
    }
    fn phi(&mut self, garlic: u8) {
        let ubi = &mut self.skein512.ubi512;
        let phi = unsafe { &mut self.temp.phi };
        let last_word_index  = (1u64 << garlic) - 1;
        let rshift = 64 - garlic;
        let mut j  = u64::from_le_bytes(self.graph_memory[idx!(last_word_index)..idx!(last_word_index) + 8].try_into().unwrap());
        j >>= rshift;
        phi[idx!(0)..idx!(1)].copy_from_slice(&self.graph_memory[idx!(last_word_index)..idx!(last_word_index + 1)]);
        phi[idx!(1)..idx!(2)].copy_from_slice(&self.graph_memory[idx!(j              )..idx!(j + 1              )]);
        hash_native!(ubi, &mut self.graph_memory[..idx!(1)], &phi[..idx!(2)]);
        for i in 1u64..=last_word_index {
            j = u64::from_le_bytes(self.graph_memory[idx!(i - 1)..idx!(i)].try_into().unwrap());
            j >>= rshift;
            phi[idx!(0)..idx!(1)].copy_from_slice(&self.graph_memory[idx!(i - 1)..idx!(i    )]);
            phi[idx!(1)..idx!(2)].copy_from_slice(&self.graph_memory[idx!(j    )..idx!(j + 1)]);
            hash_native!(ubi, &mut self.graph_memory[idx!(i)..idx!(i + 1)], &phi[..idx!(2)]);
        }
        self.x.copy_from_slice(&self.graph_memory[idx!(last_word_index)..idx!(last_word_index + 1)]);
    }
} // ~ impl Catena

