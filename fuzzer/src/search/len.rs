// Assume it is direct and linear
use super::{config, SearchHandler};
use rand::prelude::*;

pub struct LenFuzz<'a> {
    handler: SearchHandler<'a>,
}

impl<'a> LenFuzz<'a> {
    pub fn new(handler: SearchHandler<'a>) -> Self {
        Self { handler }
    }

    pub fn run<R: Rng + ?Sized>(&mut self, rng: &mut R) {
        if !config::ENABLE_INPUT_LEN_EXPLORATION {
            self.handler.cond.mark_as_done();
            return;
        }

        /*
        in llvm_mode/io-func.c runtime/len_label.rs:
        lb1 => read offset
        lb2 => read elem_size
        */

        let elem_size = self.handler.cond.base.lb2 as usize;
        let elem_num = self.handler.cond.base.get_output() as usize;
        let cmp_size = self.handler.cond.base.size as usize;
        let mut buf = self.handler.buf.clone();

        log::debug!(
            "len: elem_num: {}, elem_size: {}, buf_len: {}, cmp_size: {}",
            elem_num,
            elem_size,
            buf.len(),
            cmp_size,
        );

        let extended_len = if let Some(extended_len) = elem_num.checked_mul(elem_size) {
            extended_len
        } else {
            log::debug!("Length extension calculation overflows, ignoring this condition.");
            return;
        };
        let buf_len = buf.len();

        // Overflowing arithmetic is used to try to cope with compiler
        // optimizations that rely on over/underflows.

        let (total_len, _) = match cmp_size {
            4 => overflowing_add_u32(buf_len, extended_len),
            _ => buf_len.overflowing_add(extended_len),
        };
        if total_len < config::MAX_INPUT_LEN {
            // len > X
            buf.resize_with(total_len, || rng.gen());
            self.handler.execute(&buf);

            // some special chars: NULL, LF, CR, SPACE
            let special_chars = vec![0, 10, 13, 32];
            for special_char in special_chars {
                buf.push(special_char);
                self.handler.execute(&buf);
                buf.pop();
            }

            // len == X
            if buf.pop().is_some() {
                self.handler.execute(&buf);
            }
        } else {
            log::debug!("New size with add bigger than size limit, ignoring.")
        }

        let (total_len, _) = match cmp_size {
            4 => overflowing_sub_u32(buf_len, extended_len),
            _ => buf_len.overflowing_sub(extended_len),
        };
        if total_len < config::MAX_INPUT_LEN {
            // len == X
            buf.resize_with(total_len, || rng.gen());
            self.handler.execute(&buf);

            // len < X
            if buf.pop().is_some() {
                self.handler.execute(&buf);
            }
        } else {
            log::debug!("New size with sub bigger than size limit, ignoring.")
        }

        self.handler.cond.mark_as_done();
    }
}

fn overflowing_add_u32(lhs: usize, rhs: usize) -> (usize, bool) {
    let lhs = lhs as u32;
    let rhs = rhs as u32;
    let (res, has_overflown) = lhs.overflowing_add(rhs);
    (res as usize, has_overflown)
}

fn overflowing_sub_u32(lhs: usize, rhs: usize) -> (usize, bool) {
    let lhs = lhs as u32;
    let rhs = rhs as u32;
    let (res, has_overflown) = lhs.overflowing_sub(rhs);
    (res as usize, has_overflown)
}
