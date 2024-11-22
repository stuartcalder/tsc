use tsc::*;
use std::io;
use io::Write;

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
