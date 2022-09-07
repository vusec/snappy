// RUN: %clang_xray_snapshot %s -o %t
// RUN: rm -f %t.map %t.stats %t.target.json
// RUN: llvm-xray extract --symbolize %t > %t.map
// RUN: %generate_snapshot_target \
// RUN:         %t.map 'print_message' --hit_count 2 > %t.target.json
// RUN: RUST_LOG=trace \
// RUN:         %ld_library_path \
// RUN:         TRACER_ENABLED=true \
// RUN:         TRACER_OUTPUT_FILE=%t.stats \
// RUN:         XRAY_SNAPSHOT_TAINTS=%S/empty.json \
// RUN:         TRACER_SNAPSHOT_TARGET=%t.target.json \
// RUN:         TRACER_STATS_ONLY=true \
// RUN:         %t 2>&1 | FileCheck --dump-input=always %s

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) void print_message(void) { puts("Hello!"); }

__attribute__((noinline)) void intermediate(bool print) {
  if (print) {
    print_message();
  }
}

int main(void) {
  print_message();
  intermediate(false);

  // CHECK: Before
  puts("Before");
  fflush(stdout);

  // CHECK: Custom handler called
  intermediate(true);

  // CHECK-NOT: Custom handler called
  intermediate(true);
  return EXIT_SUCCESS;
}