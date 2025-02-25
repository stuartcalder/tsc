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

use std::io;
#[allow(unused)]
use io::Write;
use tsc::catena512;

fn main() {
    use catena512::*;
    let mut catena = Catena::new(13u8);
    let mut output = [0u8; 64];
    let pw         = [b'p', b'a', b's', b's', b'w', b'o', b'r', b'd'];

    catena.get(
        &mut output,
        &pw,
        13u8,
        1u8,
        false).unwrap();
    println!("{:02x?}", output);
}

/*
fn main() {
    use csprng::*;

    let mut out: [u8; 64] = [0u8; 64];
    let mut rng = Csprng::new();

    rng.get(&mut out);
    println!("{:02x?}", out);
}
*/

/*
fn main() {
    use skein512::*;

    let mut skein512 = Skein512::new();

    let mut hash_output: [u8; 64] = [0u8; 64];
    skein512.hash_native(&mut hash_output, b"fotwiny");
    println!("{:02x?}", hash_output);

    println!("");

/*
    let mut hash_small: [u8; 32] = [0u8; 32];
    skein512.hash(&mut hash_small, b":)");
    print_hash(&hash_small);
*/
}

*/
