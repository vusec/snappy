// RUN: %clang_xray_snapshot %s -o %t
// RUN: rm -f %t.map %t.stats %t.target.json
// RUN: llvm-xray extract --symbolize %t > %t.map
// RUN: %generate_snapshot_target \
// RUN:         %t.map 'print_message' > %t.target.json
// RUN: RUST_LOG=trace \
// RUN:         %ld_library_path \
// RUN:         TRACER_ENABLED=true \
// RUN:         TRACER_OUTPUT_FILE=%t.stats \
// RUN:         TRACER_MACHINE_READABLE=true \
// RUN:         XRAY_SNAPSHOT_TAINTS=%S/empty.json \
// RUN:         TRACER_SNAPSHOT_TARGET=%t.target.json \
// RUN:         TRACER_STATS_ONLY=true \
// RUN:         %t 2>&1
// RUN: cat %t.stats | FileCheck %s

#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) void print_message(void) { puts("Hello!"); }

int main(void) {
  print_message();
  return EXIT_SUCCESS;
}

// CHECK:       execution_nanos,target_function_entry_to_end_nanos_opt
// CHECK-NEXT:  {{[0-9]+}},{{[0-9]+}}
