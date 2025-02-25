#![cfg_attr(debug_assertions, allow(dead_code, unused_imports))]
pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

pub mod tf512;
pub mod ubi512;
pub mod skein512;
pub mod csprng;
pub mod rand;
pub mod catena512;
extern crate rssc;

#[cfg(test)]
mod tests {
    use super::*;

    const fn swap_all<const N: usize>(arr: & [u64; N]) -> [u64; N]
    {
        let mut a: [u64; N] = [0; N];
        let mut i = 0usize;
        loop {
            if i == N {
                break;
            }
            a[i] = arr[i].swap_bytes();
            i += 1;
        }

        a
    }

    /**
     * Compare Threefish512Static with Threefish512Dynamic, and ensure that they produce the same
     * ciphertext outputs for the same input (key, tweak, input_block) tuples.
     */
    #[test]
    fn compare_threefish_impls() {
        use super::tf512::*;
        type Key   = [u64; NUM_KEY_WORDS_WITH_PARITY];
        type Tweak = [u64; NUM_TWEAK_WORDS_WITH_PARITY];
        type Block = [u64; NUM_BLOCK_WORDS];
        type Tpl   = (Key, Tweak, Block);

        const NULL_KEY:   Key   = [0; NUM_KEY_WORDS_WITH_PARITY];
        const NULL_TWEAK: Tweak = [0; NUM_TWEAK_WORDS_WITH_PARITY];
        const NULL_BLOCK: Block = [0; NUM_BLOCK_WORDS];

        const TEST_KEY_0: Key = {
            let mut k: Key = NULL_KEY;
            k[k.len() - 1] = 1u64;
            k
        };
        const TEST_TWEAK_0: Tweak = {
            let mut t: Tweak = NULL_TWEAK;
            t[0] = 1u64;
            t
        };
        const TEST_BLK_0: Block = {
            let mut b: Block = NULL_BLOCK;
            b[2] = 1u64;
            b
        };
        const TEST_TPL_0: Tpl = (TEST_KEY_0, TEST_TWEAK_0, TEST_BLK_0);
        const TEST_TPL_1: Tpl = (
            swap_all(&TEST_KEY_0),
            swap_all(&TEST_TWEAK_0),
            swap_all(&TEST_BLK_0)
        );

        let mut tpl: [Tpl; 2] = [TEST_TPL_0, TEST_TPL_1];

        for t in &mut tpl {
            {
                let mut tf512s = Threefish512Static::new(&mut t.0, &mut t.1);
                let mut s_out  = NULL_BLOCK;
                tf512s.encipher_2(&mut s_out, &t.2);

                let mut tf512d = Threefish512Dynamic::new(t.0.clone(), t.1.clone());
                let mut d_out  = NULL_BLOCK;
                tf512d.encipher_2(&mut d_out, &t.2);

                assert_eq!(s_out, d_out);
            }
        }
    } // ~ compare_threefish_impls()
    #[test]
    fn test_skein() {
        use skein512::*;
        let mut ubi512 = Ubi512::new();
        let mut hash_output: [u8; 64] = [0u8; 64];
        hash_native(&mut ubi512, &mut hash_output, &[]);
        println!("{:?}", hash_output);
    }
}
