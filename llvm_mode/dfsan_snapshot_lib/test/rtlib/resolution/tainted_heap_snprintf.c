// RUN: %clang_dfsan_snapshot -g %s -o %t
// RUN: rm -f %t.caller.txt %t.map %t.target.json
// RUN: llvm-xray extract --symbolize %t > %t.map
// RUN: %generate_snapshot_target %t.map 'dfs$access_first' \
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

#define BUFFER_SIZE 10

__attribute__((noinline)) char access_first(const char *buffer) {
  return buffer[0];
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

  char buffer[BUFFER_SIZE];
  fread(buffer, sizeof(char), BUFFER_SIZE, stream);
  buffer[BUFFER_SIZE - 1] = '\0';

  char *buffer_heap = calloc(BUFFER_SIZE, sizeof(char));
  snprintf(buffer_heap, BUFFER_SIZE, "%s", "yolo"); // Untainted

  // Print here to prevent the optimizer from eliminating the previous
  // allocation.
  puts(buffer_heap);

  char *buffer_heap_2 = calloc(BUFFER_SIZE, sizeof(char));
  strncpy(buffer_heap_2, buffer, BUFFER_SIZE); // Tainted

  free(buffer_heap);

  char ret = access_first(buffer_heap_2); // Trigger snapshot
  free(buffer_heap_2);

  fclose(stream);

  return ret;
}

// CHECK:       [
// CHECK-NEXT:    [
// CHECK-NEXT:      {
// CHECK-NEXT:        "type": "Heap",
// CHECK-NEXT:        "id": 4,
// CHECK-NEXT:        "size": 10,
// CHECK-NEXT:        "offset": 0
// CHECK-NEXT:      },
// CHECK-NEXT:      0
// CHECK-NEXT:    ],
// CHECK-NEXT:    [
// CHECK-NEXT:      {
// CHECK-NEXT:        "type": "Heap",
// CHECK-NEXT:        "id": 4,
// CHECK-NEXT:        "size": 10,
// CHECK-NEXT:        "offset": 1
// CHECK-NEXT:      },
// CHECK-NEXT:      1
// CHECK-NEXT:    ],
// CHECK-NEXT:    [
// CHECK-NEXT:      {
// CHECK-NEXT:        "type": "Heap",
// CHECK-NEXT:        "id": 4,
// CHECK-NEXT:        "size": 10,
// CHECK-NEXT:        "offset": 2
// CHECK-NEXT:      },
// CHECK-NEXT:      2
// CHECK-NEXT:    ],
// CHECK-NEXT:    [
// CHECK-NEXT:      {
// CHECK-NEXT:        "type": "Heap",
// CHECK-NEXT:        "id": 4,
// CHECK-NEXT:        "size": 10,
// CHECK-NEXT:        "offset": 3
// CHECK-NEXT:      },
// CHECK-NEXT:      3
// CHECK-NEXT:    ],
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
