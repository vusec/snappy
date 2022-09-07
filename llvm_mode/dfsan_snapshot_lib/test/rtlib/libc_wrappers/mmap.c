// RUN: %clang_dfsan_snapshot -g %s -o %t
// RUN: rm -f %t.caller.txt %t.map %t.target.json
// RUN: llvm-xray extract --symbolize %t > %t.map
// RUN: %generate_snapshot_target \
// RUN:     %t.map 'dfs$snapshot' --kind EXIT > %t.target.json
// RUN: DFSAN_OPTIONS="strict_data_dependencies=0" \
// RUN:     %ld_library_path \
// RUN:     RUST_LOG=trace \
// RUN:     TRACER_ENABLED=true \
// RUN:     TRACER_INPUT_FILE=%flag_file \
// RUN:     TRACER_TAINTED_OFFSETS_FILE=%S/offsets.json \
// RUN:     TRACER_OUTPUT_FILE=%t.caller.txt \
// RUN:     TRACER_SNAPSHOT_TARGET=%t.target.json \
// RUN:     %t %flag_file || [ $? -eq 42 ]
// RUN: cat %t.caller.txt | FileCheck %s

// REQUIRES: mmap_support

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void snapshot() {
  puts("Snapshot!");
}

int main(int argc, char *argv[argc + 1]) {
  if (argc != 2) {
    printf("%s INPUT_PATH\n", argv[0]);
    exit(1);
  }

  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) {
    perror("could not open file");
    exit(1);
  }

  char* content = mmap(NULL, 10, PROT_READ, MAP_PRIVATE, fd, 0);
  assert(content != MAP_FAILED);

  snapshot();

// CHECK: Map
// CHECK: Map
  char ret = content[0];

  munmap(content, 10);
  close(fd);

  return ret;
}
