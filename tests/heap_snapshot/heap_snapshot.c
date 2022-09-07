#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 20

__attribute__((noinline)) void snapshot_opportunity(void) {
  puts("I am a snapshot opportunity!");
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s INPUT_FILE\n", argv[0]);
    return 1;
  }

  FILE *input_file = fopen(argv[1], "rb");
  if (!input_file) {
    fprintf(stderr, "Could not open file %s: %s\n", argv[1], strerror(errno));
    return 1;
  }

  unsigned char *buffer = malloc(BUFFER_SIZE);
  size_t bytes_read =
      fread(buffer, sizeof(unsigned char), BUFFER_SIZE, input_file);

  fclose(input_file);

  if (bytes_read < BUFFER_SIZE) {
    fprintf(stderr, "Could not read %d bytes from file\n", BUFFER_SIZE);
    return 1;
  }

  snapshot_opportunity();

  int32_t y = 0;
  memcpy(&y, buffer + 4, 4); // y <- [4,8)
  free(buffer);

  printf("y: %d\n", y); // Tainted load happens here

  if (y == 42) {
    puts("Found!");
    abort();
  }

  return EXIT_SUCCESS;
}
