use crate::csprng;
use csprng::Csprng;

pub fn get_random_natural_num(
    rng: &mut Csprng,
    max: u64) -> u64
{
    let num_sections = max + 1;
    let local_limit = u64::MAX - (u64::MAX % num_sections);
    let quanta_per_section = local_limit / num_sections;

    let mut bytes = [0u8; 8];
    rng.get(&mut bytes);
    let rand_u64 = u64::from_le_bytes(bytes);
    let offset = if rand_u64 < local_limit {
        let rounded_down = rand_u64 - (rand_u64 % quanta_per_section);
        rounded_down / quanta_per_section
    } else {
        num_sections - 1
    };

    offset
}

pub fn get_random_u64_in_range(
    rng:   &mut Csprng,
    range: (u64, u64)) -> u64
{
    debug_assert!(range.0 <= range.1);
    range.0 + get_random_natural_num(rng, range.1 - range.0)
}
