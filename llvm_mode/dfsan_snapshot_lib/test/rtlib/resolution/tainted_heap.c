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

  char *buffer = calloc(BUFFER_SIZE, sizeof(char));
  fread(buffer, sizeof(char), BUFFER_SIZE, stream);

  fseek(stream, 0, SEEK_SET);

  char *buffer_2 = calloc(BUFFER_SIZE, sizeof(char));
  fread(buffer_2, sizeof(char), BUFFER_SIZE, stream);

  // The freelist pointers overwrite the tainted data.
  free(buffer);

  char ret = access_first(buffer_2); // Trigger snapshot
  free(buffer_2);

  fclose(stream);

  return ret;
}

// CHECK:       [
// CHECK-NEXT:    [
// CHECK-NEXT:      {
// CHECK-NEXT:        "type": "Heap",
// CHECK-NEXT:        "id": 3,
// CHECK-NEXT:        "size": 10,
// CHECK-NEXT:        "offset": 0
// CHECK-NEXT:      },
// CHECK-NEXT:      0
// CHECK-NEXT:    ],
// CHECK-NEXT:    [
// CHECK-NEXT:      {
// CHECK-NEXT:        "type": "Heap",
// CHECK-NEXT:        "id": 3,
// CHECK-NEXT:        "size": 10,
// CHECK-NEXT:        "offset": 1
// CHECK-NEXT:      },
// CHECK-NEXT:      1
// CHECK-NEXT:    ],
// CHECK-NEXT:    [
// CHECK-NEXT:      {
// CHECK-NEXT:        "type": "Heap",
// CHECK-NEXT:        "id": 3,
// CHECK-NEXT:        "size": 10,
// CHECK-NEXT:        "offset": 2
// CHECK-NEXT:      },
// CHECK-NEXT:      2
// CHECK-NEXT:    ],
// CHECK-NEXT:    [
// CHECK-NEXT:      {
// CHECK-NEXT:        "type": "Heap",
// CHECK-NEXT:        "id": 3,
// CHECK-NEXT:        "size": 10,
// CHECK-NEXT:        "offset": 3
// CHECK-NEXT:      },
// CHECK-NEXT:      3
// CHECK-NEXT:    ]
// CHECK-NEXT:  ]
