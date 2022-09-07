// RUN: %clang_dfsan_snapshot -g %s -o %t
// RUN: rm -f %t.caller.txt %t.map %t.target.json
// RUN: touch %t.caller.txt
// RUN: llvm-xray extract --symbolize %t > %t.map
// RUN: %generate_snapshot_target \
// RUN:     %t.map 'dfs$snapshot' --kind EXIT > %t.target.json
// RUN: echo '[3]' > %t.offsets.json
// RUN: DFSAN_OPTIONS="strict_data_dependencies=0" \
// RUN:     %ld_library_path \
// RUN:     RUST_LOG=trace \
// RUN:     TRACER_ENABLED=true \
// RUN:     TRACER_INPUT_FILE=%flag_file \
// RUN:     TRACER_TAINTED_OFFSETS_FILE=%t.offsets.json \
// RUN:     TRACER_OUTPUT_FILE=%t.caller.txt \
// RUN:     TRACER_SNAPSHOT_TARGET=%t.target.json \
// RUN:     %t %flag_file || [ $? -eq 42 ]
// RUN: cat %t.caller.txt | FileCheck %s --allow-empty

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

  char buffer[10];
  memset(buffer, 0, sizeof(buffer));
  pread(fd, buffer, 2, 1);
  close(fd);

  // CHECK-NOT: {{[a-z0-9_\[\]]}}
  return (buffer[0] + buffer[1]) % 1;
}
