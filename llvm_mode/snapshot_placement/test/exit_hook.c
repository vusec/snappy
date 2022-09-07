// RUN: %clang_snapshot_placement -g %s -o %t
// RUN: rm -f %t.caller.txt
// RUN: DFSAN_OPTIONS="strict_data_dependencies=0" \
// RUN:         RUST_LOG=trace \
// RUN:         TRACER_ENABLED=true \
// RUN:         TRACER_OUTPUT_FILE=%t.caller.txt \
// RUN:         TRACER_INPUT_FILE=%flag_file \
// RUN:         TRACER_ALL_TAINTED=true \
// RUN:         %t %flag_file || [ $? -eq 42 ]
// RUN: cat %t.caller.txt | FileCheck %s

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((noinline)) char caller_1(const char *buffer) {
  // Printing here prevents the optimizer from completely removing calls.
  puts("Hello!");
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

  char ret = 0;
  char buffer[10];
  memset(buffer, 0, sizeof(buffer));
  ret = caller_2(buffer);
  ret = caller_2(buffer + 1);
  fread(buffer, sizeof(char), sizeof(buffer), stream);
  ret = buffer[0];
  fclose(stream);

  return ret;
}

// CHECK:       {
// CHECK-NEXT:    "symbol_name": "caller_2",
// CHECK-NEXT:    "symbol_type": "EXIT",
// CHECK-NEXT:    "hit_count": 2
// CHECK-NEXT:  }