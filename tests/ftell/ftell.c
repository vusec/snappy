// Test ftell wrapper

#include <stdio.h>
#include <stdlib.h>

#define MIN_FILE_LEN 20

int main(int argc, char *argv[argc + 1]) {
  if (argc < 2)
    return 1;

  FILE *stream = fopen(argv[1], "rb");
  if (!stream) {
    perror("could not open input file");
    return 1;
  }

  fseek(stream, 0, SEEK_END);
  size_t len = ftell(stream);
  fseek(stream, 0, SEEK_SET);

  fclose(stream);

  if (len < MIN_FILE_LEN) {
    fprintf(stderr, "input file too short\n");
    return 1;
  }

  abort();

  return 0;
}
