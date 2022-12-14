use crate::defs;
use serde_derive::{Deserialize, Serialize};

const EPS: u64 = 1;

#[derive(Debug, Clone, Default, Copy, Serialize, Deserialize)]
#[repr(C)] // It should be repr C since we will used it in shared memory
pub struct CondStmtBase {
    pub cmpid: u32,
    pub context: u32,
    pub order: u32,
    pub belong: u32,

    pub condition: u32,
    pub level: u32,
    pub op: u32,
    pub size: u32,

    pub lb1: u32,
    pub lb2: u32,

    pub arg1: u64,
    pub arg2: u64,
}

impl PartialEq for CondStmtBase {
    fn eq(&self, other: &CondStmtBase) -> bool {
        self.cmpid == other.cmpid && self.context == other.context && self.order == other.order
    }
}

impl Eq for CondStmtBase {}

impl CondStmtBase {
    pub fn flip_condition(&mut self) {
        if self.condition == defs::COND_FALSE_ST {
            self.condition = defs::COND_TRUE_ST;
        } else {
            self.condition = defs::COND_FALSE_ST;
        }
    }
    pub fn is_explore(&self) -> bool {
        self.op <= defs::COND_MAX_EXPLORE_OP
    }

    pub fn is_exploitable(&self) -> bool {
        self.op > defs::COND_MAX_EXPLORE_OP && self.op <= defs::COND_MAX_EXPLOIT_OP
    }

    pub fn is_signed(&self) -> bool {
        (self.op & defs::COND_SIGN_MASK) > 0
            || ((self.op & defs::COND_BASIC_MASK) >= defs::COND_ICMP_SGT_OP
                && (self.op & defs::COND_BASIC_MASK) <= defs::COND_ICMP_SLE_OP)
    }

    pub fn is_afl(&self) -> bool {
        self.op == defs::COND_AFL_OP
    }

    pub fn may_be_bool(&self) -> bool {
        // sign or unsigned
        self.op & 0xFF == defs::COND_ICMP_EQ_OP && self.arg1 <= 1 && self.arg2 <= 1
    }

    pub fn is_float(&self) -> bool {
        (self.op & defs::COND_BASIC_MASK) <= defs::COND_FCMP_TRUE
    }

    pub fn is_switch(&self) -> bool {
        (self.op & defs::COND_BASIC_MASK) == defs::COND_SW_OP
    }

    pub fn is_done(&self) -> bool {
        self.condition == defs::COND_DONE_ST
    }

    pub fn get_output(&self) -> u64 {
        let mut a = self.arg1;
        let mut b = self.arg2;

        if self.is_signed() {
            a = translate_signed_value(a, self.size);
            b = translate_signed_value(b, self.size);
        }

        let mut op = self.op & defs::COND_BASIC_MASK;

        if op == defs::COND_SW_OP {
            op = defs::COND_ICMP_EQ_OP;
        }

        // if its condition is true, we want its opposite constraint.
        if self.is_explore() && self.condition == defs::COND_TRUE_ST {
            op = match op {
                defs::COND_ICMP_EQ_OP => defs::COND_ICMP_NE_OP,
                defs::COND_ICMP_NE_OP => defs::COND_ICMP_EQ_OP,
                defs::COND_ICMP_UGT_OP => defs::COND_ICMP_ULE_OP,
                defs::COND_ICMP_UGE_OP => defs::COND_ICMP_ULT_OP,
                defs::COND_ICMP_ULT_OP => defs::COND_ICMP_UGE_OP,
                defs::COND_ICMP_ULE_OP => defs::COND_ICMP_UGT_OP,
                defs::COND_ICMP_SGT_OP => defs::COND_ICMP_SLE_OP,
                defs::COND_ICMP_SGE_OP => defs::COND_ICMP_SLT_OP,
                defs::COND_ICMP_SLT_OP => defs::COND_ICMP_SGE_OP,
                defs::COND_ICMP_SLE_OP => defs::COND_ICMP_SGT_OP,
                _ => op,
            };
        }

        // RELU: if f <= 0, we set f = 0.
        // In other words, if we reach our goal, f = 0.

        let output = match op {
            defs::COND_ICMP_EQ_OP => {
                // a == b : f = abs(a - b)
                sub_abs(a, b)
            },
            defs::COND_ICMP_NE_OP => {
                // a != b :
                // f = 0 if a != b, and f = 1 if a == b
                if a == b {
                    1
                } else {
                    0
                }
            },
            defs::COND_ICMP_SGT_OP | defs::COND_ICMP_UGT_OP => {
                // a > b :
                // f = 0 if a > b, and f = b - a + e if a <= b
                if a > b {
                    0
                } else {
                    b - a + EPS
                }
            },
            defs::COND_ICMP_UGE_OP | defs::COND_ICMP_SGE_OP => {
                // a > = b
                // f = 0 if a >= b, and f = b - a if a < b
                if a >= b {
                    0
                } else {
                    b - a
                }
            },
            defs::COND_ICMP_ULT_OP | defs::COND_ICMP_SLT_OP => {
                // a < b :
                // f = 0 if a < b, and f = a - b + e if a >= b
                if a < b {
                    0
                } else {
                    a - b + EPS
                }
            },
            defs::COND_ICMP_ULE_OP | defs::COND_ICMP_SLE_OP => {
                // a < = b
                // f = 0 if a <= b, and f = a - b if a > b
                if a <= b {
                    0
                } else {
                    a - b
                }
            },
            _ => {
                //TODO : support float.
                // if self.is_float() {
                sub_abs(a, b)
            },
        };

        log::debug!(
            "id: {}, op: {} -> {}, size:{}, condition: {}, arg(0x{:x} 0x{:x}), output: {}",
            self.cmpid,
            self.op,
            op,
            self.size,
            self.condition,
            a,
            b,
            output
        );

        output
    }
}

fn sub_abs(arg1: u64, arg2: u64) -> u64 {
    if arg1 < arg2 {
        arg2 - arg1
    } else {
        arg1 - arg2
    }
}

fn translate_signed_value(v: u64, size: u32) -> u64 {
    match size {
        1 => {
            let mut s = v as i8;
            if s < 0 {
                // [-128, -1] => [0, 127]
                s = s + std::i8::MAX;
                s = s + 1;
                s as u8 as u64
            } else {
                // [0, 127] -> [128, 255]
                v + (std::i8::MAX as u64 + 1)
            }
        },

        2 => {
            let mut s = v as i16;
            if s < 0 {
                s = s + std::i16::MAX;
                s = s + 1;
                s as u16 as u64
            } else {
                v + (std::i16::MAX as u64 + 1)
            }
        },

        4 => {
            let mut s = v as i32;
            if s < 0 {
                s = s + std::i32::MAX;
                s = s + 1;
                s as u32 as u64
            } else {
                v + (std::i32::MAX as u64 + 1)
            }
        },

        8 => {
            let mut s = v as i64;
            if s < 0 {
                s = s + std::i64::MAX;
                s = s + 1;
                s as u64
            } else {
                v + (std::i64::MAX as u64 + 1)
            }
        },

        _ => v,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_translate_sign() {
        assert_eq!(
            translate_signed_value(0xffffffff80000000, 8),
            0x7fffffff80000000
        );
        assert_eq!(translate_signed_value(255, 1), 127);
    }
}
