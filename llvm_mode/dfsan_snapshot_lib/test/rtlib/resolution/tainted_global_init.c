// RUN: %clang_dfsan_snapshot -g %s -o %t
// RUN: rm -f %t.caller.txt %t.map %t.target.json
// RUN: llvm-xray extract --symbolize %t > %t.map
// RUN: %generate_snapshot_target %t.map 'dfs$caller_1' \
// RUN:   > %t.target.json
// RUN: DFSAN_OPTIONS="strict_data_dependencies=0" \
// RUN:         %ld_library_path \
// RUN:         RUST_LOG=trace \
// RUN:         TRACER_ENABLED=true \
// RUN:         TRACER_OUTPUT_FILE=%t.caller.txt \
// RUN:         TRACER_INPUT_FILE=%flag_file \
// RUN:         TRACER_ALL_TAINTED=true \
// RUN:         TRACER_SNAPSHOT_TARGET=%t.target.json \
// RUN:         %t %flag_file || [ $? -eq 42 ]
// RUN: cat %t.caller.txt | FileCheck %s

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char g_buffer[10] = "init!";

__attribute__((noinline)) char caller_1() { return g_buffer[0]; }

__attribute__((noinline)) char caller_2() { return caller_1(); }

int main(int argc, char *argv[argc + 1]) {
  if (argc != 2) {
    printf("%s INPUT_PATH\n", argv[0]);
    exit(1);
  }

  FILE *stream = fopen(argv[1], "r");
  if (!stream) {
    perror("could not open file");
    exit(1);
  }

  fread(g_buffer, sizeof(char), sizeof(g_buffer), stream);
  char ret = caller_2();
  fclose(stream);

  return ret;
}

// CHECK:       [
// CHECK-NEXT:    [
// CHECK-NEXT:      {
// CHECK-NEXT:        "type": "Static",
// CHECK-NEXT:        "symbol": "g_buffer",
// CHECK-NEXT:        "symbol_idx": 0,
// CHECK-NEXT:        "offset": 0,
// CHECK-NEXT:        "binary_path":
// CHECK-NEXT:      },
// CHECK-NEXT:      0
// CHECK-NEXT:    ],
// CHECK-NEXT:    [
// CHECK-NEXT:      {
// CHECK-NEXT:        "type": "Static",
// CHECK-NEXT:        "symbol": "g_buffer",
// CHECK-NEXT:        "symbol_idx": 0,
// CHECK-NEXT:        "offset": 1,
// CHECK-NEXT:        "binary_path":
// CHECK-NEXT:      },
// CHECK-NEXT:      1
// CHECK-NEXT:    ],
// CHECK-NEXT:    [
// CHECK-NEXT:      {
// CHECK-NEXT:        "type": "Static",
// CHECK-NEXT:        "symbol": "g_buffer",
// CHECK-NEXT:        "symbol_idx": 0,
// CHECK-NEXT:        "offset": 2,
// CHECK-NEXT:        "binary_path":
// CHECK-NEXT:      },
// CHECK-NEXT:      2
// CHECK-NEXT:    ],
// CHECK-NEXT:    [
// CHECK-NEXT:      {
// CHECK-NEXT:        "type": "Static",
// CHECK-NEXT:        "symbol": "g_buffer",
// CHECK-NEXT:        "symbol_idx": 0,
// CHECK-NEXT:        "offset": 3,
// CHECK-NEXT:        "binary_path":
// CHECK-NEXT:      },
// CHECK-NEXT:      3
// CHECK-NEXT:    ]
// CHECK-NEXT:  ]