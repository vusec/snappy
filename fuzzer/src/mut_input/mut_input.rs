use super::rw;
use crate::search;
use angora_common::{config, tag::TagSeg};

use rand::{distributions::Uniform, prelude::*};

use std::{cmp, fmt};

#[derive(Clone, Debug, Constructor)]
struct InputMeta {
    sign: bool,
    offset: usize,
    size: usize,
}

/// This structure is used to record mutations to the tainted bytes of a test
/// case. The mutated test case can then be constructed from the original test
/// case and the tainted offsets.

#[derive(Clone)]
pub struct MutInput {
    /// Contains a concatenation of all tainted ranges in the original test case.
    /// This makes it easier to modify all the bytes together.
    value: Vec<u8>,

    /// Contains ranges that refer to `value` and allows to reconstruct the
    /// original tainted ranges the struct was created from.
    meta: Vec<InputMeta>,
}

impl MutInput {
    pub fn new() -> Self {
        Self {
            value: vec![],
            meta: vec![],
        }
    }

    /// Returns the number of tainted regions.
    pub fn len(&self) -> usize {
        self.meta.len()
    }

    /// Returns the total number of bytes in all tainted regions.
    pub fn val_len(&self) -> usize {
        self.value.len()
    }

    /// Construct a new `MutInput` from a test case and a set of tainted offsets
    /// for a condition on that test case.
    pub fn from(offsets: &Vec<TagSeg>, test_case: &Vec<u8>) -> Self {
        let test_case_len = test_case.len();
        let mut mut_input = MutInput::new();
        for tainted_range in offsets {
            let tainted_range_begin = tainted_range.begin as usize;
            let tainted_range_end = tainted_range.end as usize;
            if tainted_range_begin == tainted_range_end {
                // Empty tainted range.
                continue;
            }
            if tainted_range_end <= test_case_len {
                // Tainted range within test case.
                mut_input.push(
                    (test_case[tainted_range_begin..tainted_range_end]).to_vec(),
                    tainted_range.sign,
                );
            } else {
                if tainted_range_begin >= test_case_len {
                    // Whole tainted range after end of test case.
                    let tainted_range_size = tainted_range_end - tainted_range_begin;
                    mut_input.push(vec![0u8; tainted_range_size], tainted_range.sign);
                } else {
                    // Tainted range starts within test case and ends after.
                    let mut tainted_region = test_case[tainted_range_begin..test_case_len].to_vec();
                    let non_overlap_range_size = tainted_range_end - test_case_len;
                    let mut non_overlap_region = vec![0u8; non_overlap_range_size];
                    tainted_region.append(&mut non_overlap_region);
                    mut_input.push(tainted_region, tainted_range.sign);
                }
            }
        }

        mut_input
    }

    fn push(&mut self, mut tainted_region: Vec<u8>, is_region_signed: bool) {
        if tainted_region.len() != 1
            && tainted_region.len() != 2
            && tainted_region.len() != 4
            && tainted_region.len() != 8
        {
            // If tainted region does not have a standard size, consider each
            // byte singularly.
            for _ in 0..tainted_region.len() {
                self.meta
                    .push(InputMeta::new(is_region_signed, self.value.len(), 1));
            }
        } else {
            self.meta.push(InputMeta::new(
                is_region_signed,
                self.value.len(),
                tainted_region.len(),
            ));
        }
        self.value.append(&mut tainted_region);
    }

    pub fn update(&mut self, index: usize, direction: bool, delta: u64) {
        let info = &self.meta[index];
        rw::update_val_in_buf(
            &mut self.value,
            info.sign,
            info.offset,
            info.size,
            direction,
            delta,
        );
    }

    // the return value is unsigned!!
    pub fn get_entry(&self, index: usize) -> u64 {
        let info = &self.meta[index];
        match rw::read_val_from_buf(&self.value, info.offset, info.size) {
            Ok(v) => v,
            Err(_) => {
                panic!("meta: {:?}", self.meta);
            },
        }
    }

    /// Returns the length of the tainted range at `index`.
    pub fn get_entry_len(&self, index: usize) -> usize {
        self.meta[index].size
    }

    /// Sets the tainted value at index `index` to the value `val`.
    pub fn set(&mut self, index: usize, val: u64) {
        let info = &self.meta[index];
        rw::set_val_in_buf(&mut self.value, info.offset, info.size, val);
    }

    /// Substitute the current content of the tainted regions with the content of
    /// `value`, which may get truncated to fit.
    pub fn assign(&mut self, value: &Vec<u8>) {
        let value_len = cmp::min(value.len(), self.val_len());
        if value_len > 0 {
            let scope = &mut self.value[0..value_len];
            scope.clone_from_slice(&value[0..value_len]);
        }
    }

    /// Returns a `Vec` containing the content of the tainted regions.
    pub fn get_value(&self) -> Vec<u8> {
        self.value.clone()
    }

    /// Sets the tainted byte copying their values over from `input`.
    pub fn set_value_from_input(&mut self, input: &MutInput) {
        self.value = input.get_value();
    }

    /// Flips the bit at position `i`.
    pub fn bitflip(&mut self, i: usize) {
        let byte_i = i >> 3;
        let bit_i = i & 7;
        assert!(byte_i < self.val_len());
        self.value[byte_i] ^= 128 >> bit_i;
    }

    /// Applies the mutations collected to the `input` buffer, which should contain
    /// the original test case. The `offsets` vector needs to match the one used
    /// when constructing the structure.
    pub fn write_to_input(&self, offsets: &Vec<TagSeg>, input: &mut Vec<u8>) {
        //assert_eq!(self.len(), offsets.len());
        if offsets.len() > 0 {
            let ext_len = offsets.last().unwrap().end as usize;
            let orig_len = input.len();
            if ext_len > orig_len {
                let mut v = vec![0u8; ext_len - orig_len];
                input.append(&mut v);
            }
        }
        rw::set_bytes_by_offsets(offsets, &self.value, input);
    }

    /// Randomizes all tainted bytes.
    pub fn randomize_all<R: Rng + ?Sized>(&mut self, rng: &mut R) {
        self.randomize_all_with_weight(rng, 3);
    }

    /// Randomizes all tainted bytes bytes uniformely with `1 / weight`
    /// probability, otherwise it randomly mutates them.
    pub fn randomize_all_with_weight<R: Rng + ?Sized>(&mut self, rng: &mut R, weight: u32) {
        // 1/weight true
        let coin = rng.gen_bool(1.0 / weight as f64);
        if coin {
            self.randomize_all_uniform(rng);
        } else {
            self.randomize_all_mut_based(rng);
        }
    }

    /// Randomizes all the tainted bytes uniformely.
    pub fn randomize_all_uniform<R: Rng + ?Sized>(&mut self, rng: &mut R) {
        rng.fill_bytes(&mut self.value);
    }

    /// Randomly mutates the tainted bytes with various operators.
    pub fn randomize_all_mut_based<R: Rng + ?Sized>(&mut self, rng: &mut R) {
        let entry_len = self.len() as u32;
        let byte_len = self.val_len() as u32;
        assert!(byte_len > 0 && entry_len > 0);

        let use_stacking = if byte_len <= 4 {
            1 + rng.gen_range(0..16)
        } else if byte_len <= 20 {
            1 + rng.gen_range(0..64)
        } else {
            1 + rng.gen_range(0..256)
        };

        // let choice_range = Range::new(0, 6);
        let choice_range = Uniform::new(0, 6);

        for _ in 0..use_stacking {
            match rng.sample(choice_range) {
                0 | 1 => {
                    // flip bit
                    let byte_idx: u32 = rng.gen_range(0..byte_len);
                    let bit_idx: u32 = rng.gen_range(0..8);
                    self.value[byte_idx as usize] ^= 128 >> bit_idx;
                },
                2 => {
                    //add
                    let entry_idx: u32 = rng.gen_range(0..entry_len);
                    let v: u32 = rng.gen_range(1..config::MUTATE_ARITH_MAX);
                    self.update(entry_idx as usize, true, v as u64);
                },
                3 => {
                    // sub
                    let entry_idx: u32 = rng.gen_range(0..entry_len);
                    let v: u32 = rng.gen_range(1..config::MUTATE_ARITH_MAX);
                    self.update(entry_idx as usize, false, v as u64);
                },
                4 => {
                    // set interesting value
                    let entry_idx: u32 = rng.gen_range(0..entry_len);
                    let n = self.get_entry_len(entry_idx as usize);
                    let vals = search::get_interesting_bytes(n);
                    let wh = rng.gen_range(0..vals.len());
                    self.set(entry_idx as usize, vals[wh]);
                },
                5 => {
                    // random byte
                    let byte_idx: u32 = rng.gen_range(0..byte_len);
                    // self.randomize_one_byte(byte_idx as usize);
                    self.value[byte_idx as usize] = rng.gen();
                },
                _ => {},
            }
        }
    }
}

impl fmt::Debug for MutInput {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in 0..self.len() {
            write!(f, "{}, ", self.get_entry(i))?
        }
        Ok(())
    }
}
