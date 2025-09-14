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
use std::sync::Arc;
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
    let mut new_salt: [u8; NUM_SALT_BYTES]  = [0u8; NUM_SALT_BYTES];

    // Initialize Catena.
    catena.new_in_place(memory_high);
    // Copy the input salt into the 32 bytes of @input.
    input[..NUM_SALT_BYTES].copy_from_slice(input_salt);
    // Get a little-endian version of the thread index.
    let mut ti: u64 = thread_idx.to_le();
    // Copy that version into the last 8 bytes of @input.
    input[NUM_SALT_BYTES..NUM_INPUT_BYTES].copy_from_slice(unsafe {
        std::slice::from_raw_parts(
            (&mut ti as *mut _ as *mut u8), std::mem::size_of::<u64>()
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

fn multi_threaded(
    output: &mut [u8; NUM_OUTPUT_BYTES],
    input_salt: &[u8; NUM_SALT_BYTES],
    input_password: &[u8],
    thread_count: u64,
    thread_batch_size: u64,
    memory_low:  u8,
    memory_high: u8,
    iterations:  u8,
    use_phi: bool
) -> Result<(), i32>
{
    let num_output_bytes = thread_count * NUM_BLOCK_BYTES;
    let mut catenas = vec![Catena::new(memory_high); thread_count as usize];
    let mut errors  = vec![0i32; thread_count as usize];
    let mut outputs = vec![0u8; num_output_bytes as usize];

    let threads = Arc::new(Mutex::new(Vec::with_capacity(num_threads as usize)));
    let mut j_stop = 0u64;
    for i in (0..num_threads).step_by(batch_size as usize) {
        j_stop = if i + batch_size < num_threads {
            batch_size
        } else {
            num_threads - i
        };

        let mut thread_handles = Vec::new();

        for j in 0u64..j_stop {
            let offset  = i + j;
            let catenas = Arc::clone(&catenas);
            let errors  = Arc::clone(&errors);
            let outputs = Arc::clone(&outputs);

            let handle = thread::spawn(move || {
                single_threaded(
                    &mut outputs[offset as usize],
                    &mut catenas[offset],
                    input_salt,
                    input_password,
                    j,
                    memory_low,
                    memory_high,
                    iterations,
                    use_phi
                );
            });

            thread_handles.push(handle);
        }

        for handle in thread_handles {
            handle.join().unwrap();
        }
    }
    //TODO
}
