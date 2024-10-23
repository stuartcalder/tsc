#![cfg_attr(debug_assertions, allow(dead_code, unused_imports))]
pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

pub mod tf512;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
