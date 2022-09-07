// RUN: %clang_snapshot_placement -g %s -o %t
// RUN: rm -f %t.caller.txt
// RUN: DFSAN_OPTIONS="strict_data_dependencies=0" \
// RUN:     RUST_LOG=trace \
// RUN:     TRACER_ENABLED=true \
// RUN:     TRACER_INPUT_FILE=%flag_file \
// RUN:     TRACER_TAINTED_OFFSETS_FILE=%S/offsets.json \
// RUN:     TRACER_OUTPUT_FILE=%t.caller.txt \
// RUN:     %t %flag_file || [ $? -eq 42 ]
// RUN: cat %t.caller.txt | FileCheck %s

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

// CHECK: main
  char ret = content[0];

  munmap(content, 10);
  close(fd);

  return ret;
}
