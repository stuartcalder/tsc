pub mod tf512;
pub mod ubi512;


// THREEFISH
use crate::tf512::*;

#[no_mangle]
pub extern "C" fn TSC_Threefish512Static_rekey(
    ctx: *mut   Threefish512Static,
    key: *mut   u64,
    tweak: *mut u64)
{
    let k = unsafe {std::slice::from_raw_parts_mut(key, NUM_KEY_WORDS_WITH_PARITY)};
    let t = unsafe {std::slice::from_raw_parts_mut(tweak, NUM_TWEAK_WORDS_WITH_PARITY)};
    unsafe {&mut *ctx}.rekey(k, t);
}

#[no_mangle]
pub extern "C" fn TSC_Threefish512Static_encipher_1(
    ctx_p: *mut Threefish512Static,
    io_p:  *mut u64)
{
    let ctx = unsafe {&mut *ctx_p};
    let io  = unsafe {std::slice::from_raw_parts_mut(io_p, NUM_BLOCK_WORDS)};
    ctx.encipher_1(io);
}

#[no_mangle]
pub extern "C" fn TSC_Threefish512Static_encipher_2(
    ctx_p: *mut Threefish512Static,
    ciphertext_p: *mut u64,
    plaintext_p:  *const u64)
{
    let ctx = unsafe {&mut *ctx_p};
    let ciphertext = unsafe {std::slice::from_raw_parts_mut(ciphertext_p, NUM_BLOCK_WORDS)};
    let plaintext  = unsafe {std::slice::from_raw_parts(plaintext_p, NUM_BLOCK_WORDS)};
    ctx.encipher_2(ciphertext, plaintext);
}

#[no_mangle]
pub extern "C" fn TSC_Threefish512Dynamic_rekey(
    ctx_p:   *mut   Threefish512Dynamic,
    key_p:   *const u64,
    tweak_p: *const u64)
{
    let ctx   = unsafe {&mut *ctx_p};
    let key   = unsafe {std::slice::from_raw_parts(key_p, NUM_KEY_WORDS)};
    let tweak = unsafe {std::slice::from_raw_parts(tweak_p, NUM_TWEAK_WORDS)};
    ctx.key[..NUM_KEY_WORDS].copy_from_slice(key);
    ctx.tweak[..NUM_TWEAK_WORDS].copy_from_slice(tweak);
    ctx.rekey();
}

#[no_mangle]
pub extern "C" fn TSC_Threefish512Dynamic_encipher_1(
    ctx_p: *mut Threefish512Dynamic,
    io_p:  *mut u64)
{
    let ctx = unsafe {&mut *ctx_p};
    let io  = unsafe {std::slice::from_raw_parts_mut(io_p, NUM_BLOCK_WORDS)};
    ctx.encipher_1(io);
}

#[no_mangle]
pub extern "C" fn TSC_Threefish512Dynamic_encipher_2(
    ctx_p: *mut Threefish512Dynamic,
    ciphertext_p: *mut u64,
    plaintext_p: *const u64)
{
    let ctx = unsafe {&mut *ctx_p};
    let ciphertext = unsafe {std::slice::from_raw_parts_mut(ciphertext_p, NUM_BLOCK_WORDS)};
    let plaintext  = unsafe {std::slice::from_raw_parts(plaintext_p, NUM_BLOCK_WORDS)};
    ctx.encipher_2(ciphertext, plaintext);
}

// UBI512
use crate::ubi512::*;

#[no_mangle]
pub extern "C" fn TSC_UBI512_chainConfig(
    ctx_p: *mut Ubi512,
    num_output_bits: u64)
{
    let ctx = unsafe {&mut *ctx_p};
    ctx.chain_config(num_output_bits);
}

#[no_mangle]
pub extern "C" fn TSC_UBI512_chainMessage(
    ctx_p: *mut Ubi512,
    input_p: *const u8,
    input_size: u64)
{
    let ctx = unsafe {&mut *ctx_p};
    let input = unsafe {
        std::slice::from_raw_parts(input_p, input_size as usize)
    };
    ctx.chain_message(input);
}

#[no_mangle]
pub extern "C" fn TSC_UBI512_chainOutput(
    ctx_p: *mut Ubi512,
    output_p: *mut u8,
    output_size: u64)
{
    let ctx = unsafe {&mut *ctx_p};
    let output = unsafe {
        std::slice::from_raw_parts_mut(output_p, output_size as usize)
    };
    ctx.chain_output(output);
}

#[no_mangle]
pub extern "C" fn TSC_UBI512_chainOutputNative(
    ctx_p: *mut Ubi512,
    output_p: *mut u8)
{
    let ctx = unsafe {&mut *ctx_p};
    let output = unsafe {
        std::slice::from_raw_parts_mut(output_p, NUM_BLOCK_BYTES)
    };
    ctx.chain_native_output(output);
}

#[no_mangle]
pub extern "C" fn TSC_UBI512_chainKey(
    ctx_p: *mut Ubi512,
    input_key_p: *const u8)
{
    let ctx = unsafe {&mut *ctx_p};
    let input_key = unsafe {
        std::slice::from_raw_parts(input_key_p, NUM_BLOCK_BYTES)
    };
    ctx.chain_key_u8(input_key);
}
