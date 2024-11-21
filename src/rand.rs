use crate::csprng;
use csprng::Csprng;

pub fn get_random_natural_num(
    rng: &mut Csprng,
    max: u64) -> u64
{
    rng.get_random_natural_num(max)
}

pub fn get_random_u64_in_range(
    rng:   &mut Csprng,
    range: (u64, u64)) -> u64
{
    rng.get_random_u64_in_range(range)
}
