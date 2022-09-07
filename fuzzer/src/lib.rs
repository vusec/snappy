#[macro_use]
extern crate log;
#[macro_use]
extern crate derive_more;

pub mod branches;
pub mod cond_stmt;
pub mod depot;
pub mod executor;
mod mut_input;
mod search;
pub mod stats;
pub mod track;

mod fuzz_loop;
pub mod fuzz_main;
mod fuzz_type;

mod bind_cpu;
mod check_dep;
pub mod command;
mod tmpfs;

pub use crate::fuzz_main::fuzz_main;
