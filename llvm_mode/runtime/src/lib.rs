pub mod ffds;
pub mod heapmap;
pub mod len_label;
pub mod logger;
mod tag_set;
pub mod tag_set_wrap;
pub mod track;

use logger::Logger;
pub use crate::tag_set::TagSet;

pub type DfsanLabel = u32;
extern "C" {
    fn dfsan_read_label(addr: *const i8, size: usize) -> DfsanLabel;
}
