use super::*;
use angora_common::tag::TagSeg;
pub struct FnFuzz<'a> {
    handler: SearchHandler<'a>,
}

impl<'a> FnFuzz<'a> {
    pub fn new(handler: SearchHandler<'a>) -> Self {
        Self { handler }
    }

    /// Lengthens `self.handler.buf` by `n` bytes keeping
    /// `self.handler.cond.offsets` consistent. The bytes are inserted before the
    /// last tainted range.
    fn insert_bytes(&mut self, n: usize) {
        debug!("add {} bytes", n);
        let last_tainted_range = self.handler.cond.offsets.last().unwrap();
        if self.handler.buf.len() <= last_tainted_range.end as usize {
            self.handler
                .buf
                .resize(last_tainted_range.end as usize + 1_usize, 0);
        }

        let last_tainted_range_begin = last_tainted_range.begin as usize;
        let mut last_tainted_range_end = last_tainted_range.end;
        let tainted_value = self.handler.buf[last_tainted_range_begin];
        for _ in 0..n {
            self.handler
                .buf
                .insert(last_tainted_range_begin, tainted_value);
            let new_tainted_range_begin = last_tainted_range_end;
            last_tainted_range_end = new_tainted_range_begin + 1;
            self.handler.cond.offsets.push(TagSeg {
                sign: false,
                begin: new_tainted_range_begin,
                end: last_tainted_range_end,
            })
        }
    }

    /// Shortens `self.handler.buf` by `n` bytes keeping
    /// `self.handler.cond.offsets` consistent. The bytes are removed from the
    /// beginning of the last tainted range.
    fn remove_bytes(&mut self, n: usize) {
        debug!("remove {} bytes", n);
        for _ in 0..n {
            let last_tainted_range = self.handler.cond.offsets.last().unwrap();
            let last_tainted_range_begin = last_tainted_range.begin as usize;
            let last_tainted_range_size =
                last_tainted_range.end as usize - last_tainted_range_begin;
            self.handler.buf.remove(last_tainted_range_begin);
            if last_tainted_range_size > 1 {
                self.handler.cond.offsets.last_mut().unwrap().end = last_tainted_range.end - 1;
            } else {
                self.handler.cond.offsets.pop();
            }
        }
    }

    pub fn run(&mut self) {
        // A comparison function always reports only one operand as tainted, the
        // other is considered a constant magic byte sequence. The arguments are
        // packed together into `variables` in `get_offsets_and_variables`.

        let magic_bytes_len = self.handler.cond.base.size as usize;
        if magic_bytes_len > self.handler.cond.variables.len() {
            error!(
                "magic length is less than input length. cond: {:?}",
                self.handler.cond
            );
            return;
        }

        // The `tainted_operand_value` is the value observed when the comparison
        // function is called. The program maps the input bytes that taint the
        // operand of the comparison function to this value.

        // The constant magic bytes sequence remains in `self.handler.cond.variables`.
        let tainted_operand_value = self.handler.cond.variables.split_off(magic_bytes_len);

        // Ensure that the number of tainted bytes is the same as the length of
        // the magic bytes sequence. The tainted bytes are always inserted or
        // removed from the one-before-the-last position to preserve null
        // terminators in single-byte sequences (probably).
        let mut_input = self.handler.get_f_input();
        let tainted_input_bytes_len = mut_input.val_len();
        if tainted_input_bytes_len < magic_bytes_len {
            self.insert_bytes(magic_bytes_len - tainted_input_bytes_len);
        } else if tainted_input_bytes_len > magic_bytes_len {
            self.remove_bytes(tainted_input_bytes_len - magic_bytes_len);
        }

        let mut mut_input = self.handler.get_f_input();
        let tainted_input_bytes = mut_input.get_value();
        assert_eq!(tainted_input_bytes.len(), magic_bytes_len);
        let min_len = std::cmp::min(magic_bytes_len, tainted_operand_value.len());
        assert!(min_len <= self.handler.cond.variables.len());
        for i in 0..min_len {
            // Take into account linear mappings between the tainted input bytes
            // and the tainted operand value that is observed at the call to the
            // comparison function.
            let diff = tainted_operand_value[i] as i16 - tainted_input_bytes[i] as i16;
            self.handler.cond.variables[i] = (self.handler.cond.variables[i] as i16 - diff) as u8;
        }

        // Replace the tainted bytes with the magic bytes sequence.
        mut_input.assign(&self.handler.cond.variables);
        self.handler.execute_input(&mut_input);

        self.handler.cond.mark_as_done();
    }
}
