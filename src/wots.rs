//! WOTS (Winternitz One-Time Signature) specialized to:
//! - n = 64 bytes
//! - w = 16 (SPHINCS+)
//!
//! API style:
//! - no generics
//! - outputs via &mut out-parameters
//! - no secrets returned by value

use crate::skein512::Skein512;
use rssc::op::secure_zero;

// ----------------------------- Parameters -----------------------------

pub const N: usize = 64;
pub const W: u32 = 16;
pub const LOG_W: usize = 4; // log2(16)

// len1 = ceil((8*n)/log2(w)) = 512/4 = 128
pub const LEN1: usize = 128;

// len2 = floor(log_w(len1*(w-1))) + 1
// len1*(w-1) = 128*15 = 1920 = 0x780 => 3 base-16 digits => len2 = 3
pub const LEN2: usize = 3;

pub const LEN: usize = LEN1 + LEN2; // 131

// ----------------------------- Type aliases -----------------------------

pub type Block = [u8; N];          // 64-byte value (hash output / chain value)
pub type Steps = [u8; LEN];        // 131 base-w digits
pub type SecretKey = [Block; LEN]; // 131 * 64 bytes
pub type Signature = [Block; LEN];
pub type PublicKey = [Block; LEN];

// ----------------------------- Domain tags -----------------------------

const TAG_SK: &[u8] = b"WOTS-SK";
const TAG_CH: &[u8] = b"WOTS-CH";
const TAG_MSG: &[u8] = b"WOTS-MSG";

// ----------------------------- Public API -----------------------------

#[inline]
pub fn validate_params() {
    debug_assert!(N == 64);
    debug_assert!(W == 16);
    debug_assert!(LOG_W == 4);
    debug_assert!(LEN1 == 128);
    debug_assert!(LEN2 == 3);
    debug_assert!(LEN == 131);
}

/// Expand a seed into a WOTS secret key.
/// `ctx` is a tweak/context hook (e.g., SPHINCS address bytes later).
pub fn sk_from_seed(skein: &mut Skein512, out_sk: &mut SecretKey, seed: &Block, ctx: &[u8]) {
    validate_params();

    let mut tmp = [0u8; N];

    // Reuse a single Vec to avoid reallocating in the loop.
    let mut buf: Vec<u8> = Vec::with_capacity(TAG_SK.len() + ctx.len() + N + 2);

    for i in 0..LEN {
        buf.clear();
        buf.extend_from_slice(TAG_SK);
        buf.extend_from_slice(ctx);
        buf.extend_from_slice(seed);
        buf.extend_from_slice(&(i as u16).to_be_bytes());

        skein.hash(&mut tmp, &buf);
        out_sk[i] = tmp;
    }

    // Wipe temporaries (best effort; relies on rssc::op::secure_zero semantics)
    secure_zero(tmp.as_mut_slice());
    secure_zero(buf.as_mut_slice());
}

/// Derive public key from secret key.
pub fn pk_from_sk(skein: &mut Skein512, out_pk: &mut PublicKey, sk: &SecretKey, ctx: &[u8]) {
    validate_params();

    for i in 0..LEN {
        chain(skein, &mut out_pk[i], &sk[i], i as u16, (W - 1) as u32, ctx);
    }
}

/// Sign a message.
pub fn sign(
    skein: &mut Skein512,
    out_sig: &mut Signature,
    sk: &SecretKey,
    msg: &[u8],
    ctx: &[u8],
) {
    validate_params();

    let mut steps = [0u8; LEN];
    message_to_steps(skein, &mut steps, msg, ctx);

    for i in 0..LEN {
        chain(skein, &mut out_sig[i], &sk[i], i as u16, steps[i] as u32, ctx);
    }

    secure_zero(steps.as_mut_slice());
}

/// Derive public key from signature+message (verification path).
pub fn pk_from_sig(
    skein: &mut Skein512,
    out_pk: &mut PublicKey,
    sig: &Signature,
    msg: &[u8],
    ctx: &[u8],
) {
    validate_params();

    let mut steps = [0u8; LEN];
    message_to_steps(skein, &mut steps, msg, ctx);

    for i in 0..LEN {
        let s = steps[i] as u32;
        let rem = (W - 1) as u32 - s;
        chain(skein, &mut out_pk[i], &sig[i], i as u16, rem, ctx);
    }

    secure_zero(steps.as_mut_slice());
}

/// Verify signature: recompute pk from sig+msg and compare.
pub fn verify(
    skein: &mut Skein512,
    expected_pk: &PublicKey,
    sig: &Signature,
    msg: &[u8],
    ctx: &[u8],
) -> bool {
    validate_params();

    let mut derived: PublicKey = [[0u8; N]; LEN];
    pk_from_sig(skein, &mut derived, sig, msg, ctx);

    // pk is public; normal equality is fine. If you want CT compare, swap this out.
    let ok = &derived == expected_pk;

    secure_zero(derived.as_mut_slice().concat().as_mut_slice()); // best-effort wipe; see note below
    ok
}

// ----------------------------- Internals -----------------------------

/// Hash chain:
/// x_{j+1} = H(TAG_CH || ctx || i_be16 || step_be32 || x_j)
/// Apply `steps` iterations.
/// Writes final value into `out`.
fn chain(
    skein: &mut Skein512,
    out: &mut Block,
    start: &Block,
    i: u16,
    steps: u32,
    ctx: &[u8],
) {
    let mut x = *start;
    let mut tmp = [0u8; N];

    let mut buf: Vec<u8> = Vec::with_capacity(TAG_CH.len() + ctx.len() + 2 + 4 + N);
    let i_be = i.to_be_bytes();

    for step in 0..steps {
        buf.clear();
        buf.extend_from_slice(TAG_CH);
        buf.extend_from_slice(ctx);
        buf.extend_from_slice(&i_be);
        buf.extend_from_slice(&step.to_be_bytes());
        buf.extend_from_slice(&x);

        skein.hash(&mut tmp, &buf);
        x = tmp;
    }

    *out = x;

    secure_zero(x.as_mut_slice());
    secure_zero(tmp.as_mut_slice());
    secure_zero(buf.as_mut_slice());
}

/// Convert message to WOTS steps:
/// - digest = H(TAG_MSG || ctx || msg) (64 bytes)
/// - steps[0..128) = base-16 digits (nibbles) of digest (128 digits)
/// - checksum = sum(15 - steps[i]) for i in 0..128
/// - steps[128..131) = checksum as 3 base-16 digits
fn message_to_steps(skein: &mut Skein512, out_steps: &mut Steps, msg: &[u8], ctx: &[u8]) {
    let mut digest = [0u8; N];

    // Hash message with domain separation.
    let mut buf: Vec<u8> = Vec::with_capacity(TAG_MSG.len() + ctx.len() + msg.len());
    buf.extend_from_slice(TAG_MSG);
    buf.extend_from_slice(ctx);
    buf.extend_from_slice(msg);
    skein.hash(&mut digest, &buf);

    // Base-16 digits from digest (128 nibbles)
    for i in 0..N {
        out_steps[2 * i] = digest[i] >> 4;
        out_steps[2 * i + 1] = digest[i] & 0x0f;
    }

    // Checksum
    let mut csum: u32 = 0;
    for i in 0..LEN1 {
        csum += 15u32 - (out_steps[i] as u32);
    }

    // Append checksum as 3 hex digits (big-endian nibble order)
    out_steps[LEN1 + 0] = ((csum >> 8) & 0x0f) as u8;
    out_steps[LEN1 + 1] = ((csum >> 4) & 0x0f) as u8;
    out_steps[LEN1 + 2] = (csum & 0x0f) as u8;

    // Wipe
    secure_zero(digest.as_mut_slice());
    secure_zero(buf.as_mut_slice());
}

// ----------------------------- Tests -----------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skein512::Skein512;

    #[test]
    fn wots_roundtrip() {
        let mut skein = Skein512::new();

        let seed = [0x42u8; N];
        let ctx = b"test-context";

        let mut sk: SecretKey = [[0u8; N]; LEN];
        let mut pk: PublicKey = [[0u8; N]; LEN];

        sk_from_seed(&mut skein, &mut sk, &seed, ctx);
        pk_from_sk(&mut skein, &mut pk, &sk, ctx);

        let msg = b"hello world";
        let mut sig: Signature = [[0u8; N]; LEN];

        sign(&mut skein, &mut sig, &sk, msg, ctx);
        assert!(verify(&mut skein, &pk, &sig, msg, ctx));
        assert!(!verify(&mut skein, &pk, &sig, b"tampered", ctx));

        // Wipe test buffers (optional)
        secure_zero(sk.as_mut_slice().concat().as_mut_slice());
        secure_zero(sig.as_mut_slice().concat().as_mut_slice());
        secure_zero(pk.as_mut_slice().concat().as_mut_slice());
    }
}

