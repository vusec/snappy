#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[argc + 1]) {
  if (argc != 2) {
    printf("usage: %s INPUT_FILE", argv[0]);
    return EXIT_FAILURE;
  }

  FILE *input_file = fopen(argv[1], "r");
  if (!input_file) {
    perror("could not open input file");
    return EXIT_FAILURE;
  }

  char input_buffer[10];
  char *res = fgets(input_buffer, sizeof(input_buffer), input_file);
  if (!res) {
    printf("could not read from input file");
    return EXIT_FAILURE;
  }

  printf("%c %c %c %c\n", input_buffer[0], input_buffer[1], input_buffer[2],
         input_buffer[3]);

  return EXIT_SUCCESS;
}
