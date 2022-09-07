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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((noinline)) char caller_1(const char *buffer) {
  return buffer[0];
}

__attribute__((noinline)) char caller_2(const char *buffer) {
  return caller_1(buffer);
}

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

  char buffer[10];
  memset(buffer, 0, sizeof(buffer));
  fread(buffer, sizeof(char), sizeof(buffer), stream);
  char ret = caller_2(buffer);
  fclose(stream);

  return ret;
}

// CHECK:       [
// CHECK-NEXT:    [
// CHECK-NEXT:      {
// CHECK-NEXT:        "type": "Stack",
// CHECK-NEXT:        "record_id": {{[0-9]+}},
// CHECK-NEXT:        "location_idx": 0,
// CHECK-NEXT:        "location_offt": 0,
// CHECK-NEXT:        "stack_map_num_functions_hint": 1,
// CHECK-NEXT:        "stack_map_file_hint": "{{.+}}"
// CHECK-NEXT:      },
// CHECK-NEXT:      0
// CHECK-NEXT:    ],
// CHECK-NEXT:    [
// CHECK-NEXT:      {
// CHECK-NEXT:        "type": "Stack",
// CHECK-NEXT:        "record_id": {{[0-9]+}},
// CHECK-NEXT:        "location_idx": 0,
// CHECK-NEXT:        "location_offt": 1,
// CHECK-NEXT:        "stack_map_num_functions_hint": 1,
// CHECK-NEXT:        "stack_map_file_hint": "{{.+}}"
// CHECK-NEXT:      },
// CHECK-NEXT:      1
// CHECK-NEXT:    ],
// CHECK-NEXT:    [
// CHECK-NEXT:      {
// CHECK-NEXT:        "type": "Stack",
// CHECK-NEXT:        "record_id": {{[0-9]+}},
// CHECK-NEXT:        "location_idx": 0,
// CHECK-NEXT:        "location_offt": 2,
// CHECK-NEXT:        "stack_map_num_functions_hint": 1,
// CHECK-NEXT:        "stack_map_file_hint": "{{.+}}"
// CHECK-NEXT:      },
// CHECK-NEXT:      2
// CHECK-NEXT:    ],
// CHECK-NEXT:    [
// CHECK-NEXT:      {
// CHECK-NEXT:        "type": "Stack",
// CHECK-NEXT:        "record_id": {{[0-9]+}},
// CHECK-NEXT:        "location_idx": 0,
// CHECK-NEXT:        "location_offt": 3,
// CHECK-NEXT:        "stack_map_num_functions_hint": 1,
// CHECK-NEXT:        "stack_map_file_hint": "{{.+}}"
// CHECK-NEXT:      },
// CHECK-NEXT:      3
// CHECK-NEXT:    ]
// CHECK-NEXT:  ]