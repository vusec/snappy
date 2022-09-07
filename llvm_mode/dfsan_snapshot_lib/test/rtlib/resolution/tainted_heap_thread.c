// RUN: %clang_dfsan_snapshot -g %s -o %t
// RUN: rm -f %t.caller.txt %t.map %t.target.json
// RUN: llvm-xray extract --symbolize %t > %t.map
// RUN: %generate_snapshot_target %t.map 'dfs$caller_1' \
// RUN:   > %t.target.json
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

// REQUIRES: different_threads

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 10

__attribute__((noinline)) char access_first(const char *buffer) {
  return buffer[0];
}

void *reader_task(void *input_path) {
  FILE *stream = fopen(input_path, "r");
  if (!stream) {
    perror("could not open file");
    exit(1);
  }

  char *buffer = calloc(BUFFER_SIZE, sizeof(char));
  fread(buffer, sizeof(char), BUFFER_SIZE, stream);
  fclose(stream);

  return buffer;
}

int main(int argc, char *argv[argc + 1]) {
  if (argc != 2) {
    printf("%s INPUT_PATH\n", argv[0]);
    exit(1);
  }

  pthread_t reader_1;
  pthread_create(&reader_1, NULL, reader_task, argv[1]);

  pthread_t reader_2;
  pthread_create(&reader_2, NULL, reader_task, argv[1]);

  char *buffer_1 = NULL;
  pthread_join(reader_1, (void **)&buffer_1);

  char *buffer_2 = NULL;
  pthread_join(reader_2, (void **)&buffer_2);

  free(buffer_1);

  char ret = access_first(buffer_2); // Trigger snapshot
  free(buffer_2);

  return ret;
}

// CHECK: Heap