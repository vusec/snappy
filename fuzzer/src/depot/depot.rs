use super::*;
use crate::{cond_stmt::CondStmt, executor::StatusType};
use rand::prelude::*;
use std::{
    fs,
    io::prelude::*,
    mem,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};
// https://crates.io/crates/priority-queue
use angora_common::config;
use priority_queue::PriorityQueue;

pub struct Depot {
    pub queue: Mutex<PriorityQueue<CondStmt, QPriority>>,
    pub num_inputs: AtomicUsize,
    pub num_hangs: AtomicUsize,
    pub num_crashes: AtomicUsize,
    pub dirs: DepotDir,
}

impl Depot {
    pub fn new(in_dir: PathBuf, out_dir: &Path) -> Self {
        Self {
            queue: Mutex::new(PriorityQueue::new()),
            num_inputs: AtomicUsize::new(0),
            num_hangs: AtomicUsize::new(0),
            num_crashes: AtomicUsize::new(0),
            dirs: DepotDir::new(in_dir, out_dir),
        }
    }

    fn save_input(
        status: &StatusType,
        buf: &Vec<u8>,
        num: &AtomicUsize,
        cmpid: u32,
        dir: &Path,
    ) -> usize {
        let id = num.fetch_add(1, Ordering::Relaxed);
        trace!(
            "Find {} th new {:?} input by fuzzing {}.",
            id,
            status,
            cmpid
        );
        let new_path = get_file_name(dir, id);
        let mut f = fs::File::create(new_path.as_path()).expect("Could not save new input file.");
        f.write_all(buf)
            .expect("Could not write seed buffer to file.");
        f.flush().expect("Could not flush file I/O.");
        id
    }

    pub fn save(&self, status: StatusType, buf: &Vec<u8>, cmpid: u32) -> usize {
        match status {
            StatusType::Normal(_) => {
                Self::save_input(&status, buf, &self.num_inputs, cmpid, &self.dirs.inputs_dir)
            },
            StatusType::Timeout => {
                Self::save_input(&status, buf, &self.num_hangs, cmpid, &self.dirs.hangs_dir)
            },
            StatusType::Crash => Self::save_input(
                &status,
                buf,
                &self.num_crashes,
                cmpid,
                &self.dirs.crashes_dir,
            ),
            _ => 0,
        }
    }

    pub fn empty(&self) -> bool {
        self.num_inputs.load(Ordering::Relaxed) == 0
    }

    pub fn next_random<R: Rng + ?Sized>(&self, rng: &mut R) -> usize {
        rng.gen::<usize>() % self.num_inputs.load(Ordering::Relaxed)
    }

    pub fn get_input_buf(&self, id: usize) -> Vec<u8> {
        let path = get_file_name(&self.dirs.inputs_dir, id);
        read_from_file(&path)
    }

    pub fn get_entry(&self) -> Option<(CondStmt, QPriority)> {
        let mut q = match self.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Mutex poisoned! Results may be incorrect. Continuing...");
                poisoned.into_inner()
            },
        };
        q.peek()
            .and_then(|x| Some((x.0.clone(), x.1.clone())))
            .and_then(|x| {
                if !x.1.is_done() {
                    let q_inc = x.1.inc(x.0.base.op);
                    q.change_priority(&(x.0), q_inc);
                }
                Some(x)
            })
    }

    pub fn add_entries(&self, new_conditions: Vec<CondStmt>) {
        let mut queue = self.queue.lock().unwrap();

        for mut new_condition in new_conditions {
            if !new_condition.is_desirable {
                continue;
            }

            if let Some((queue_condition, _)) = queue.get_mut(&new_condition) {
                if queue_condition.is_done() {
                    continue;
                }

                // Since conditions are boolean, if the fuzzer was able to
                // record a condition with the opposite value as the one in the
                // queue, the condition has been solved.
                if queue_condition.base.condition != new_condition.base.condition {
                    queue_condition.mark_as_done();
                    queue.change_priority(&new_condition, QPriority::done());
                    continue;
                }

                // If the current test case ran substantially faster than the
                // one with which the condition was previously encountered,
                // substitute it.
                if config::PREFER_FAST_COND
                    && (new_condition.speed as f64 / queue_condition.speed as f64)
                        <= config::FAST_COND_RATIO
                {
                    mem::swap(queue_condition, &mut new_condition);

                    let priority = QPriority::init(new_condition.base.op);
                    queue.change_priority(&new_condition, priority);
                }
            } else {
                log::trace!(
                    "New condition inserted in queue: ({},{},{})",
                    new_condition.base.cmpid,
                    new_condition.base.context,
                    new_condition.base.order
                );

                let priority = QPriority::init(new_condition.base.op);
                queue.push(new_condition, priority);
            }
        }
    }

    pub fn update_entry(&self, cond: CondStmt) {
        let mut q = match self.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Mutex poisoned! Results may be incorrect. Continuing...");
                poisoned.into_inner()
            },
        };
        if let Some(v) = q.get_mut(&cond) {
            v.0.clone_from(&cond);
        } else {
            warn!("Update entry: can not find this cond");
        }
        if cond.is_discarded() {
            q.change_priority(&cond, QPriority::done());
        }
    }
}
