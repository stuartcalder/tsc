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
    const HASH_BUFFER_SIZE: usize = NUM_OUTPUT_BYTES * 2;
    // Per-thread state and outputs: one block per thread.
    let mut catenas:     Vec<Catena> = vec![Catena::default(); thread_count as usize];
    let mut errors:      Vec<i32> = vec![0i32; thread_count as usize];
    let mut outputs:     Vec<[u8; NUM_BLOCK_BYTES]> = vec![[0u8; NUM_BLOCK_BYTES]; thread_count as usize];

    // Spawn threads in batches, borrowing each thread's Catena and output in place.
    thread::scope(|s| {
        let mut i = 0usize;
        while i < thread_count as usize {
            let j_stop = if i + {thread_batch_size as usize} < {thread_count as usize} {
                thread_batch_size as usize
            } else {
                thread_count as usize - 1
            };
            let start = i;
            let end = i + j_stop;
    
            let out_batch = &mut outputs[start..end];
            let cat_batch = &mut catenas[start..end];
            let err_batch = &mut errors[start..end];
    
            let mut handles = Vec::with_capacity(j_stop);
            for (j, out_slot) in out_batch.iter_mut().enumerate() {
                let cat_slot = &mut cat_batch[j];
                let err_slot = &mut err_batch[j];
                let input_salt = input_salt; // copy or reference as appropriate
                let input_password = input_password;
    
                handles.push(s.spawn(move || {
                    let thread_idx = (start + j) as u64;
                    match one_thread(
                        out_slot,
                        cat_slot,
                        input_salt,
                        input_password,
                        thread_idx,
                        memory_low,
                        memory_high,
                        iterations,
                        use_phi,
                    ) {
                        Ok(()) => *err_slot = 0,
                        Err(code) => *err_slot = code,
                    }
                }));
            }
    
            for h in handles {
                h.join().unwrap();
            }
    
            i = end;
        }
    });

    // If any thread failed, return a global error (match C++ behavior).
    if let Some(&code) = errors.iter().find(|&&e| e != 0) {
        // Best-effort zeroization of sensitive buffers before returning error.
        for block in &mut outputs {
            rssc::op::secure_zero(block);
        }
        return Err(code);
    }

    // XOR-reduce all per-thread blocks into outputs[0], like the C++ combination step.
    for i in 1..(thread_count as usize) {
        for b in 0..NUM_BLOCK_BYTES {
            outputs[0][b] ^= outputs[i][b];
        }
    }

    // Write the reduced block to the caller-provided `output`.
    output.copy_from_slice(&outputs[0]);

    for block in &mut outputs {
        rssc::op::secure_zero(block);
    }

    Ok(())
}

