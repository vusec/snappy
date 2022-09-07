// RUN: %clang_xray_snapshot %s -o %t
// RUN: rm -f %t.map %t.stats %t.target.json
// RUN: llvm-xray extract --symbolize %t > %t.map
// RUN: %generate_snapshot_target %t.map 'caller_1' > %t.target.json
// RUN: sed 's|%BINARY_PATH%|%t|g' %s.json > %t.json
// RUN: RECORD_ID=$(llvm-readobj --stackmap %t \
// RUN:   | grep 'Record ID' \
// RUN:   | grep -o '[0-9]\+' \
// RUN:   | head -n 1)
// RUN: sed -i "s|%RECORD_ID%|$RECORD_ID|g" %t.json
// RUN: RUST_LOG=trace \
// RUN:         %ld_library_path \
// RUN:         TRACER_ENABLED=true \
// RUN:         XRAY_SNAPSHOT_TAINTS=%t.json \
// RUN:         TRACER_SNAPSHOT_TARGET=%t.target.json \
// RUN:         %t %flag_file > %t.log.txt 2>&1 || [ $? -eq 97 ]
// RUN: FileCheck --dump-input=always %s < %t.log.txt

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 10

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

  char ret = caller_2(buffer_heap_2); // Trigger snapshot
  free(buffer_heap_2);

  fclose(stream);

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
// CHECK: Offset 0 taints: Stack {
// CHECK: Resolved to address:
// CHECK: Offset 1 taints: Stack {
// CHECK: Resolved to address:
// CHECK: Offset 2 taints: Stack {
// CHECK: Resolved to address:
// CHECK: Offset 3 taints: Stack {
// CHECK: Resolved to address: