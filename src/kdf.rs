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

#![allow(unused_imports)]
use std::slice;
use std::thread;
use std::cmp::min;
use std::sync::atomic::{AtomicI32, Ordering};
use crate::tf512;
use crate::catena512;
use crate::skein512;

use tf512::{
    NUM_BLOCK_BYTES,
    NUM_BLOCK_WORDS,
    NUM_KEY_BYTES,
    NUM_KEY_WORDS
};

use skein512::{
    Skein512
};

use catena512::{
    NUM_SALT_BYTES,
    Catena
};

pub const NUM_OUTPUT_BYTES: usize = NUM_BLOCK_BYTES;

fn one_thread(
    output: &mut [u8; NUM_OUTPUT_BYTES],
    catena: &mut Catena,
    input_salt: &[u8; NUM_SALT_BYTES],
    input_password: &[u8],
    thread_idx: u64,
    memory_low: u8,
    memory_high: u8,
    iterations: u8,
    use_phi: bool) -> Result<(), i32>
{
    const NUM_INPUT_BYTES: usize = NUM_SALT_BYTES + std::mem::size_of::<u64>();

    let mut input:    [u8; NUM_INPUT_BYTES] = [0u8; NUM_INPUT_BYTES];

    // Initialize Catena.
    catena.new_in_place(memory_high).unwrap();
    // Copy the input salt into the 32 bytes of @input.
    input[..NUM_SALT_BYTES].copy_from_slice(input_salt);
    // Get a little-endian version of the thread index.
    let mut ti: u64 = thread_idx.to_le();
    // Copy that version into the last 8 bytes of @input.
    input[NUM_SALT_BYTES..NUM_INPUT_BYTES].copy_from_slice(unsafe {
        std::slice::from_raw_parts(
            &mut ti as *mut _ as *mut u8, std::mem::size_of::<u64>()
        )
    });
    // Hash @input directly into @catena's salt buffer.
    catena.skein512.hash(&mut catena.salt, &input);
    catena.get(
        output,
        input_password, /*TODO*/
        memory_low,
        iterations,
        use_phi
    )
}

pub fn multi_threaded(
    output: &mut [u8; NUM_OUTPUT_BYTES],
    input_salt: &[u8; NUM_SALT_BYTES],
    input_password: &[u8],
    thread_count: u64,
    thread_batch_size: u64,
    memory_low: u8,
    memory_high: u8,
    iterations: u8,
    use_phi: bool,
) -> Result<(), i32> {
    let thread_count = thread_count as usize;
    let thread_batch_size = thread_batch_size as usize;
    if thread_count == 0 {
        return Err(-1);
    }

    let mut catenas: Vec<Catena> = vec![Catena::default(); thread_count];
    let mut outputs: Vec<[u8; NUM_BLOCK_BYTES]> = vec![[0u8; NUM_BLOCK_BYTES]; thread_count];
    let mut errors: Vec<i32> = vec![0i32; thread_count];

    // Use a scope so closures may borrow input_salt and input_password
    thread::scope(|s| {
        let mut start = 0usize;
        while start < thread_count {
            let end = min(start + thread_batch_size, thread_count);
            let batch_len = end - start;
            if batch_len == 0 { break; }

            // Collect handles for this batch
            let mut handles = Vec::with_capacity(batch_len);
            for idx in start..end {
                // move per-slot data out with replace (arrays don't need Default)
                let out_placeholder = [0u8; NUM_BLOCK_BYTES];
                let out_slot = std::mem::replace(&mut outputs[idx], out_placeholder);

                // Catena: requires Default so we can replace
                let cat_slot = std::mem::replace(&mut catenas[idx], Catena::default());

                // capture non-'static references by borrowing under the scope
                let salt_ref = input_salt;
                let pwd_ref = input_password;
                let mem_low = memory_low;
                let mem_high = memory_high;
                let iters = iterations;
                let phi = use_phi;
                let thread_idx = idx as u64;

                // spawn scoped thread
                handles.push((idx, s.spawn(move || {
                    let mut out_slot = out_slot;
                    let mut cat_slot = cat_slot;
                    let res = one_thread(
                        &mut out_slot,
                        &mut cat_slot,
                        salt_ref,
                        pwd_ref,
                        thread_idx,
                        mem_low,
                        mem_high,
                        iters,
                        phi,
                    );
                    (res, out_slot, cat_slot)
                })));
            }

            // join batch and reinsert results
            for (idx, handle) in handles {
                match handle.join() {
                    Ok((res, thread_out, thread_cat)) => {
                        match res {
                            Ok(()) => errors[idx] = 0,
                            Err(code) => errors[idx] = code,
                        }
                        outputs[idx] = thread_out;
                        catenas[idx] = thread_cat;
                    }
                    Err(_) => {
                        // thread panicked: best-effort zeroize and propagate error
                        for k in start..end {
                            rssc::op::secure_zero(&mut outputs[k]);
                        }
                        // we cannot return from inside the scope easily; store error and break
                        errors[idx] = -2;
                    }
                }
            }

            start = end;
        }
    }); // end scope; all scoped threads have been joined here

    // if any thread failed, zeroize and return its code
    if let Some(&code) = errors.iter().find(|&&e| e != 0) {
        for block in &mut outputs {
            rssc::op::secure_zero(block);
        }
        return Err(code);
    }

    // XOR-reduce into outputs[0]
    for i in 1..thread_count {
        for b in 0..NUM_BLOCK_BYTES {
            outputs[0][b] ^= outputs[i][b];
        }
    }

    // Copy only requested number of bytes (slice if sizes differ)
    output.copy_from_slice(&outputs[0][..NUM_OUTPUT_BYTES]);

    // Zeroize temporary buffers
    for block in &mut outputs {
        rssc::op::secure_zero(block);
    }

    Ok(())
}

