// RUN: %clang_dfsan_snapshot -g %s -o %t
// RUN: rm -f %t.caller.txt %t.map %t.target.json
// RUN: llvm-xray extract --symbolize %t > %t.map
// RUN: %generate_snapshot_target %t.map 'dfs$caller_1' > %t.target.json
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

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((noinline)) char caller_1(const char *buffer) {
  return buffer[0];
}

__attribute__((noinline)) char caller_2(const char *buffer) {
  return caller_1(buffer);
}

void *checker_task(void *input_path) {
  FILE *stream = fopen(input_path, "r");
  if (!stream) {
    perror("could not open file");
    exit(1);
  }

  char *ret = malloc(sizeof(char));

  char buffer[10];
  memset(buffer, 0, sizeof(buffer));
  fread(buffer, sizeof(char), sizeof(buffer), stream);
  *ret = caller_2(buffer);
  fclose(stream);

  return ret;
}

int main(int argc, char *argv[argc + 1]) {
  if (argc != 2) {
    printf("%s INPUT_PATH\n", argv[0]);
    exit(1);
  }

  pthread_t checker;
  pthread_create(&checker, NULL, checker_task, argv[1]);

  char *ret_ptr;
  pthread_join(checker, (void **)&ret_ptr);

  char ret = *ret_ptr;
  free(ret_ptr);

  return ret;
}

// CHECK: Stack
// CHECK: Stack
// CHECK: Stack
// CHECK: Stack