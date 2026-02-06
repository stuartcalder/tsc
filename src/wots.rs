//! Winternitz One-Time Signatures (WOTS) over a hash function.
//!
//! This implementation uses Skein512 as the underlying hash, with output truncated
//! to N bytes. It provides deterministic keygen from a seed, signing, and verification
//! via deriving a public key from a signature.
//!
//! Notes:
//! - Requires W to be a power of two (e.g. 4, 8, 16, 32).
//! - Domain separation is done with fixed ASCII tags plus indices.
//! - A `ctx` byte-slice is accepted in keygen/sign/verify to allow SPHINCS-style
//!   addressing/tweaks later (you can pass an address encoding there).
//!
//! Typical SPHINCS+ uses W=16 and N=16/24/32; you are likely to use N=64 with Skein512.

use crate::skein512::Skein512;
use rssc::op::secure_zero;

/// WOTS generic implementation.
///
/// - `N`: number of bytes in each chain value (hash output truncated to N bytes).
/// - `W`: Winternitz base. Must be power of two.
pub struct Wots<const N: usize, const W: u32>;

impl<const N: usize, const W: u32> Wots<N, W> {
    // ---------- Parameter derivation (const) ----------

    /// log2(W). Requires W to be power of two.
    pub const LOG_W: usize = {
        // Compute trailing_zeros in const context by loop.
        // (We also validate W is power-of-two elsewhere at runtime.)
        let mut w = W;
        let mut r: usize = 0;
        while w > 1 {
            w >>= 1;
            r += 1;
        }
        r
    };

    /// Number of message digits in base W.
    pub const LEN1: usize = (8 * N + Self::LOG_W - 1) / Self::LOG_W;

    /// Number of checksum digits in base W.
    pub const LEN2: usize = {
        // len2 = floor(log_w(len1*(w-1))) + 1
        let mut v: u64 = (Self::LEN1 as u64) * ((W - 1) as u64);
        let mut cnt: usize = 1;
        while v >= (W as u64) {
            v /= W as u64;
            cnt += 1;
        }
        cnt
    };

    /// Total number of chains.
    pub const LEN: usize = Self::LEN1 + Self::LEN2;

    /// Runtime validation: call once early in your code/tests.
    #[inline]
    pub fn validate_params() {
        assert!(N > 0, "N must be > 0");
        assert!(W >= 2 && W <= 256, "W must be in [2, 256]");
        assert!(W.is_power_of_two(), "W must be a power of two");
        assert!(Self::LOG_W > 0, "LOG_W must be > 0");
    }

    // ---------- Public API types ----------

    pub type ChainValue = [u8; N];
    pub type Signature = [Self::ChainValue; Self::LEN];
    pub type PublicKey = [Self::ChainValue; Self::LEN];
    pub type SecretKey = [Self::ChainValue; Self::LEN];

    // ---------- Domain separation tags ----------
    // Keep these short + stable. You can swap them to SPHINCS+ style easily later.

    const TAG_SK_ELEM: &'static [u8] = b"WOTS-SK";
    const TAG_CHAIN: &'static [u8] = b"WOTS-CH";
    const TAG_MSG: &'static [u8] = b"WOTS-MSG";

    // ---------- Key expansion ----------

    /// Deterministically expand a seed into WOTS secret-key elements.
    ///
    /// `ctx` is optional context/tweak bytes (e.g., SPHINCS address encoding).
    pub fn sk_from_seed(
        skein: &mut Skein512,
        seed: &[u8; N],
        ctx: &[u8],
    ) -> Self::SecretKey {
        Self::validate_params();

        let mut sk: SecretKey   = [[0u8; N]; Self::LEN];
        let mut out: ChainValue = [0u8; N];

        for i in 0..Self::LEN {
            // input = TAG || ctx || seed || i_be16
            let mut input = Vec::with_capacity(Self::TAG_SK_ELEM.len() + ctx.len() + N + 2);
            input.extend_from_slice(Self::TAG_SK_ELEM);
            input.extend_from_slice(ctx);
            input.extend_from_slice(seed);
            input.extend_from_slice(&(i as u16).to_be_bytes());

            skein.hash(&mut out, &input);
            sk[i] = out;
            secure_zero(&mut input);
        }

        sk
    }

    /// Compute a WOTS public key from a secret key (apply chain to max step).
    pub fn pk_from_sk(skein: &mut Skein512, sk: &Self::SecretKey, ctx: &[u8]) -> Self::PublicKey {
        Self::validate_params();

        let mut pk = [[0u8; N]; Self::LEN];
        for i in 0..Self::LEN {
            pk[i] = Self::chain(skein, &sk[i], i as u16, (W - 1) as u32, ctx);
        }
        pk
    }

    // ---------- Signing / Verification ----------

    /// Sign `msg` (arbitrary bytes).
    ///
    /// Returns a signature array of `LEN` chain values.
    pub fn sign(
        skein: &mut Skein512,
        sk: &Self::SecretKey,
        msg: &[u8],
        ctx: &[u8],
    ) -> Self::Signature {
        Self::validate_params();

        let steps = Self::message_to_steps(skein, msg, ctx);
        let mut sig = [[0u8; N]; Self::LEN];

        for i in 0..Self::LEN {
            sig[i] = Self::chain(skein, &sk[i], i as u16, steps[i] as u32, ctx);
        }
        sig
    }

    /// Derive a WOTS public key from a signature and message (the standard verify path).
    pub fn pk_from_sig(
        skein: &mut Skein512,
        sig: &Self::Signature,
        msg: &[u8],
        ctx: &[u8],
    ) -> Self::PublicKey {
        Self::validate_params();

        let steps = Self::message_to_steps(skein, msg, ctx);
        let mut pk = [[0u8; N]; Self::LEN];

        for i in 0..Self::LEN {
            let s = steps[i] as u32;
            let remaining = (W - 1) as u32 - s;
            pk[i] = Self::chain(skein, &sig[i], i as u16, remaining, ctx);
        }
        pk
    }

    /// Verify signature by recomputing pk from sig+msg and comparing to expected pk.
    pub fn verify(
        skein: &mut Skein512,
        expected_pk: &Self::PublicKey,
        sig: &Self::Signature,
        msg: &[u8],
        ctx: &[u8],
    ) -> bool {
        let derived = Self::pk_from_sig(skein, sig, msg, ctx);
        &derived == expected_pk
    }

    // ---------- Internals ----------

    /// Hash-chain function: apply `steps` iterations, each hashing the previous value with metadata.
    ///
    /// Domain separation input = TAG_CHAIN || ctx || i_be16 || step_be32 || value
    fn chain(
        skein: &mut Skein512,
        start: &Self::ChainValue,
        i: u16,
        steps: u32,
        ctx: &[u8],
    ) -> Self::ChainValue {
        let mut x = *start;
        let mut out = [0u8; N];

        for step in 0..steps {
            let mut input = Vec::with_capacity(Self::TAG_CHAIN.len() + ctx.len() + 2 + 4 + N);
            input.extend_from_slice(Self::TAG_CHAIN);
            input.extend_from_slice(ctx);
            input.extend_from_slice(&i.to_be_bytes());
            input.extend_from_slice(&step.to_be_bytes());
            input.extend_from_slice(&x);

            skein.hash(&mut out, &input);
            x = out;
        }

        x
    }

    /// Convert message to per-chain step counts in [0, W-1], including checksum.
    ///
    /// We hash the message first to N bytes so signing is fixed-length and doesn't leak structure.
    fn message_to_steps(skein: &mut Skein512, msg: &[u8], ctx: &[u8]) -> [u8; Self::LEN] {
        // msg_digest = H(TAG_MSG || ctx || msg) truncated to N bytes
        let mut digest = [0u8; N];
        {
            let mut input = Vec::with_capacity(Self::TAG_MSG.len() + ctx.len() + msg.len());
            input.extend_from_slice(Self::TAG_MSG);
            input.extend_from_slice(ctx);
            input.extend_from_slice(msg);
            skein.hash(&mut digest, &input);
        }

        // Base-w digits for digest (LEN1 digits)
        let mut digits = [0u8; Self::LEN];
        Self::base_w(&digest, &mut digits[..Self::LEN1]);

        // Checksum: sum_{i=0..LEN1-1} (W-1 - digits[i])
        let mut csum: u32 = 0;
        for &d in digits[..Self::LEN1].iter() {
            csum += (W - 1) - (d as u32);
        }

        // Encode checksum in base-w using LEN2 digits.
        // Standard approach: represent checksum as big-endian bytes of sufficient size,
        // then base_w that.
        let csum_bits = Self::LEN2 * Self::LOG_W;
        let csum_bytes = (csum_bits + 7) / 8;
        let mut cbuf = vec![0u8; csum_bytes];

        // Place checksum into the least significant bytes (big-endian)
        let mut tmp = csum as u64;
        for j in 0..csum_bytes {
            let idx = csum_bytes - 1 - j;
            cbuf[idx] = (tmp & 0xFF) as u8;
            tmp >>= 8;
        }

        let mut cdigits = vec![0u8; Self::LEN2];
        Self::base_w(&cbuf, &mut cdigits[..]);

        for j in 0..Self::LEN2 {
            digits[Self::LEN1 + j] = cdigits[j];
        }

        digits
    }

    /// Convert byte string to base-w digits.
    ///
    /// This reads input as a bitstream, extracting LOG_W bits per digit, big-endian.
    fn base_w(input: &[u8], out: &mut [u8]) {
        let log_w = Self::LOG_W;
        debug_assert!(log_w > 0 && log_w <= 8);

        let mut in_idx = 0usize;
        let mut total: u32 = 0;
        let mut bits: usize = 0;

        for out_idx in 0..out.len() {
            while bits < log_w {
                if in_idx >= input.len() {
                    // If input exhausts (can happen for checksum buffer), pad with zeros.
                    total <<= 8;
                } else {
                    total = (total << 8) | (input[in_idx] as u32);
                    in_idx += 1;
                }
                bits += 8;
            }
            bits -= log_w;
            let digit = (total >> bits) & ((W as u32) - 1);
            out[out_idx] = digit as u8;
        }
    }
}

// ------------------ Minimal tests (enable in your crate) ------------------

#[cfg(test)]
mod tests {
    use super::Wots;
    use crate::skein512::Skein512;

    #[test]
    fn wots_roundtrip_n64_w16() {
        type W = Wots<64, 16>;
        let mut skein = Skein512::new();

        let seed = [0x42u8; 64];
        let ctx = b"test-context";

        let sk = W::sk_from_seed(&mut skein, &seed, ctx);
        let pk = W::pk_from_sk(&mut skein, &sk, ctx);

        let msg = b"hello world";
        let sig = W::sign(&mut skein, &sk, msg, ctx);

        assert!(W::verify(&mut skein, &pk, &sig, msg, ctx));
        assert!(!W::verify(&mut skein, &pk, &sig, b"tampered", ctx));
    }
}

