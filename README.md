# Snappy

Snappy is a performance optimization implemented on top of
[Angora][original-angora]. Its goal is to speed up fuzzing by aggressively
pruning redundant computations with adaptive and mutable snapshots. The key
ideas are to: (i) push the snapshot as deep in the target execution as possible
and also end its execution as early as possible, according to how the target
processes the relevant input data (adaptive placement); (ii) for each identified
placement, cache snapshots across different inputs by patching the snapshot
just-in-time with the relevant input data (mutable restore).

A thorough description of this work can be found in "Snappy: Efficient Fuzzing
with Adaptive and Mutable Snapshots", published at ACSAC 2022.

The FuzzBench fork used for our evaluation can be found [here][fuzzbench-snappy].

[original-angora]: https://github.com/AngoraFuzzer/Angora
[fuzzbench-snappy]: https://github.com/vusec/fuzzbench-snappy


## Building Angora

### Build Requirements

- libunwind 1.6.2
- Linux 5.15
- LLVM 11.1 (with custom patches)
- CMake 3.13
- Python 3.8
- Rust Nightly
- [Corrosion](https://github.com/AndrewGaspar/corrosion.git)


### Building

Detailed building instructions for Ubuntu Xenial can be found in the [FuzzBench
fork][snappy-build] that was used for our evaluation. The repository includes
the custom LLVM patches for LLVM 11.1 that are required to build the
instrumentation passes.

The corresponding `Dockerfile` includes instructions on how to build libcxx and
libcxx-abi for C++ support.

[snappy-build]: https://github.com/vusec/fuzzbench-snappy/blob/snappy/fuzzers/snappy/builder.Dockerfile


### System Configuration

As with AFL and Angora, system core dumps must be disabled.

```shell
echo core | sudo tee /proc/sys/kernel/core_pattern
```


## Running Snappy

### Build Target Program

The target program needs to be rebuilt 5 times: 2 for the original Angora
instrumentations and 3 for the Snappy-related instrumentations. All five
instrumentations provide custom compiler wrappers that are built and installed
with the fuzzer. Detailed instructions on the appropriate flags and environment
variables that need to be used to build the program can be found in the build
scripts contained in the [FuzzBench fork][target-build] that was used for our
evaluation.

[target-build]: https://github.com/vusec/fuzzbench-snappy/blob/0f2cab6dc1cf8335035f9d5f0eed8b0c58189821/fuzzers/snappy/fuzzer.py#L107-L118


### Fuzzing

Once all five instrumented versions of the target program have been built, the
fuzzer can be started referencing the instrumented binaries as command line
arguments. A list of all the arguments can be found in our [FuzzBench
fork][target-run].

[target-run]: https://github.com/vusec/fuzzbench-snappy/blob/0f2cab6dc1cf8335035f9d5f0eed8b0c58189821/fuzzers/snappy/fuzzer.py#L121-L174
