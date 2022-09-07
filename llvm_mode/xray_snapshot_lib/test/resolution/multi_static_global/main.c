// RUN: %clang_xray_snapshot %s %S/plugin_1.c %S/plugin_2.c -o %t
// RUN: rm -f %t.map %t.stats %t.target.json
// RUN: llvm-xray extract --symbolize %t > %t.map
// RUN: %generate_snapshot_target \
// RUN:         %t.map 'pg2_get_buffer_elem' > %t.target.json
// RUN: sed 's|%BINARY_PATH%|%t|g' %s.json > %t.json
// RUN: RUST_LOG=trace \
// RUN:         %ld_library_path \
// RUN:         TRACER_ENABLED=true \
// RUN:         XRAY_SNAPSHOT_TAINTS=%t.json \
// RUN:         TRACER_SNAPSHOT_TARGET=%t.target.json \
// RUN:         %t %flag_file > %t.log.txt 2>&1 || [ $? -eq 97 ]
// RUN: FileCheck --dump-input=always %s < %t.log.txt

#include "plugin_1.h"
#include "plugin_2.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  fgets(buffer, sizeof(buffer), stream);

  pg2_copy_to_buffer(buffer);
  char ret = pg2_get_buffer_elem(0);

  fclose(stream);

  return ret;
}

// CHECK: Offset 0 taints: Static {
// CHECK: Resolved to address:
// CHECK: Offset 1 taints: Static {
// CHECK: Resolved to address:
// CHECK: Offset 2 taints: Static {
// CHECK: Resolved to address:
// CHECK: Offset 3 taints: Static {
// CHECK: Resolved to address: