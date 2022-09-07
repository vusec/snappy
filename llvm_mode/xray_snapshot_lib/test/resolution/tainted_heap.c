// RUN: %clang_xray_snapshot %s -o %t
// RUN: rm -f %t.map %t.stats %t.target.json
// RUN: llvm-xray extract --symbolize %t > %t.map
// RUN: %generate_snapshot_target %t.map 'caller_1' > %t.target.json
// RUN: RUST_LOG=trace \
// RUN:         %ld_library_path \
// RUN:         TRACER_ENABLED=true \
// RUN:         XRAY_SNAPSHOT_TAINTS=%s.json \
// RUN:         TRACER_SNAPSHOT_TARGET=%t.target.json \
// RUN:         %t %flag_file > %t.log.txt 2>&1 || [ $? -eq 97 ]
// RUN: FileCheck --dump-input=always %s < %t.log.txt

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 30

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

  char *buffer = calloc(BUFFER_SIZE, sizeof(char));
  fread(buffer, sizeof(char), BUFFER_SIZE, stream);

  fseek(stream, 0, SEEK_SET);

  char *buffer_2 = calloc(BUFFER_SIZE, sizeof(char));
  fread(buffer_2, sizeof(char), BUFFER_SIZE, stream);

  free(buffer);

  char ret = caller_2(buffer_2);
  free(buffer_2);

  fclose(stream);

  char *not_tracked = calloc(BUFFER_SIZE, sizeof(char));
  strcpy(not_tracked, "Not tracked!");
  puts(not_tracked);
  free(not_tracked);

  return ret;
}

// CHECK: Offset 0 taints: Heap {
// CHECK: Resolved to address:
// CHECK: Offset 1 taints: Heap {
// CHECK: Resolved to address:
// CHECK: Offset 2 taints: Heap {
// CHECK: Resolved to address:
// CHECK: Offset 3 taints: Heap {
// CHECK: Resolved to address:
// CHECK: Triggering snapshot
// CHECK-NOT: Heap allocation
// CHECK-NOT: Heap deallocation