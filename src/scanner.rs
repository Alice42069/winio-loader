use memflow::prelude::v1::*;
use rayon::{iter::IndexedParallelIterator, slice::ParallelSlice};

pub struct Scanner;

impl Scanner {
    pub fn find_pattern<T: MemoryView>(
        kernel: &mut T,
        start: Address,
        range: usize,
        pattern: &str,
    ) -> Option<Address> {
        let buffer = kernel.read_raw(start, range).ok()?;

        let (pattern, mask) = Self::parse_pattern(pattern).ok()?;

        buffer
            .par_windows(pattern.len())
            .position_any(|window| Self::matches_pattern(window, &pattern, &mask))
            .map(|offset| start + offset)
    }

    fn parse_pattern(pattern: &str) -> Result<(Vec<u8>, Vec<bool>)> {
        let mut bytes = Vec::new();
        let mut mask = Vec::new();

        for chunk in pattern.split_whitespace() {
            if "??" == chunk {
                bytes.push(0); // Placeholder for wildcard
                mask.push(true);
            } else {
                bytes.push(u8::from_str_radix(chunk, 16).expect("oops"));
                mask.push(false);
            }
        }

        Ok((bytes, mask))
    }

    fn matches_pattern(buffer: &[u8], pattern: &[u8], mask: &[bool]) -> bool {
        buffer
            .iter()
            .zip(pattern.iter())
            .zip(mask.iter())
            .all(|((&b, &p), &m)| m || b == p)
    }
}
