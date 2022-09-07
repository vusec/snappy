// RUN: %clang_xray_snapshot -O3 %s -o %t
// RUN: rm -f %t.map %t.stats %t.target.json
// RUN: llvm-xray extract --symbolize %t > %t.map
// RUN: %generate_snapshot_target %t.map 'main' > %t.target.json
// RUN: RUST_LOG=trace \
// RUN:         %ld_library_path \
// RUN:         TRACER_ENABLED=true \
// RUN:         TRACER_OUTPUT_FILE=%t.stats \
// RUN:         XRAY_SNAPSHOT_TAINTS=%S/empty.json \
// RUN:         TRACER_SNAPSHOT_TARGET=%t.target.json \
// RUN:         TRACER_STATS_ONLY=true \
// RUN:         %t %flag_file 2>&1 | FileCheck --dump-input=always %s

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char caller_1(const char* buffer) {
  return buffer[0];
}

char caller_2(const char* buffer) {
  return caller_1(buffer);
}

// CHECK: Custom handler called
int main(int argc, char *argv[argc + 1]) {
  // CHECK-NOT: Custom handler called
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

  return !(ret == 'f');
}
