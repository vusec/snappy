use std::{mem, sync::Arc};

use angora::{
    branches::{BranchBuf, Branches, GlobalBranches},
    executor::StatusType,
};
use angora_common::config::BRANCHES_SIZE;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{distributions::Uniform, prelude::*};
use rand_chacha::ChaCha8Rng;

fn generate_fake_trace(density: f64) -> Box<BranchBuf> {
    let mut trace: Box<BranchBuf> = Box::new(unsafe { mem::zeroed() });

    let covered_cells_num = (BRANCHES_SIZE as f64 * density).round() as u64;
    let uniform_dist = Uniform::from(0..BRANCHES_SIZE);
    let mut rng = ChaCha8Rng::seed_from_u64(42);
    for _ in 0..covered_cells_num {
        let cell_idx = uniform_dist.sample(&mut rng);
        trace[cell_idx] = 1;
    }

    trace
}

// This is the most common case since, most of the time, the fuzzer will not
// find new coverage and thus will just hit dirty entries in the
// `global_branches`.
pub fn parse_random_trace_with_density(c: &mut Criterion) {
    for density in &[0., 0.001, 0.002, 0.005, 0.01, 0.02] {
        let global_branches = Arc::new(GlobalBranches::new());
        let mut branches = Branches::new(global_branches);

        branches.set_trace(&generate_fake_trace(*density));

        // Make global branches dirty
        branches.has_new(StatusType::Normal(Some(0)), false);

        c.bench_with_input(
            BenchmarkId::new("parse_random_trace_with_density", *density),
            density,
            |b, _density| b.iter(|| branches.has_new(StatusType::Normal(Some(0)), false)),
        );
    }
}

pub fn compare_trace_parsing_reset(c: &mut Criterion) {
    let mut group = c.benchmark_group("trace_parsing");
    for density in &[0., 0.001, 0.002, 0.005, 0.01, 0.02] {
        let global_branches = Arc::new(GlobalBranches::new());
        let mut branches = Branches::new(global_branches);
        let fake_trace = generate_fake_trace(*density);

        // Touch the global coverage map so no new coverage is found during the
        // benchmark.
        branches.set_trace(&fake_trace);
        branches.has_new(StatusType::Normal(Some(0)), false);

        group.bench_with_input(
            BenchmarkId::new("without_reset", *density),
            density,
            |b, _density| {
                b.iter(|| {
                    branches.set_trace(&fake_trace); // Reset trace to match the other benchmark
                    branches.has_new(StatusType::Normal(Some(0)), false);
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("with_reset", *density),
            density,
            |b, _density| {
                b.iter(|| {
                    branches.set_trace(&fake_trace); // Reset trace because it gets cleared
                    branches.has_new(StatusType::Normal(Some(0)), true);
                })
            },
        );
    }
}

pub fn clear_trace(c: &mut Criterion) {
    let global_branches = Arc::new(GlobalBranches::new());
    let mut branches = Branches::new(global_branches);
    c.bench_function("clear_trace", |b| b.iter(|| branches.clear_trace()));
}

pub fn reset_trace(c: &mut Criterion) {
    let global_branches = Arc::new(GlobalBranches::new());
    let mut branches = Branches::new(global_branches);
    let fake_trace = generate_fake_trace(0.10); // density should not influence time

    c.bench_function("reset_trace", |b| {
        b.iter(|| branches.set_trace(&fake_trace))
    });
}

criterion_group!(
    trace_handling,
    parse_random_trace_with_density,
    compare_trace_parsing_reset,
    clear_trace,
    reset_trace
);
criterion_main!(trace_handling);
