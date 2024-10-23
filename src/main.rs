use tsc::tf512::*;

fn main() {
    let mut key: [u64; NUM_KEY_WORDS_WITH_PARITY] = [
        0; NUM_KEY_WORDS_WITH_PARITY
    ];
    let mut twk: [u64; NUM_TWEAK_WORDS_WITH_PARITY] = [
        0; NUM_TWEAK_WORDS_WITH_PARITY
    ];
    let mut blk: [u64; NUM_BLOCK_WORDS] = [
        0; NUM_BLOCK_WORDS
    ];


    println!("Before enciphering: {:?}", blk);


    {
        let mut tf512_static = Threefish512Static::new(key.clone(), twk.clone());
        tf512_static.encipher_1(&mut blk);
        let r: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut::<u8>(
                &mut blk as *mut _ as *mut u8,
                std::mem::size_of::<u64>() * NUM_BLOCK_WORDS
            )
        };
        println!("After enciphering: {:x?}", r);
    }
}
