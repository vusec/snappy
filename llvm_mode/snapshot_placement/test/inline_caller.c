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

char caller_1(const char *buffer) { return buffer[0]; }

char caller_2(const char *buffer) { return caller_1(buffer); }

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

// CHECK:       {
// CHECK-NEXT:    "symbol_name": "main",
// CHECK-NEXT:    "symbol_type": "ENTRY",
// CHECK-NEXT:    "hit_count": 1
// CHECK-NEXT:  }