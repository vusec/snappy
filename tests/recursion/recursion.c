#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define ARRAY_SIZE 20

__attribute__((noinline))
bool bar(size_t len, uint32_t buf[len], size_t idx) {
  if (idx == ARRAY_SIZE - 3) {
    return true;
  }

  if (buf[idx % len] == 66) {
    return bar(len, buf, idx + 1);
  } else {
    return false;
  }
}

int main(int argc, char **argv) {
  if (argc < 2)
    return 0;

  FILE *fp = fopen(argv[1], "rb");
  if (!fp) {
    printf("st err\n");
    return 0;
  }

  uint32_t buf[ARRAY_SIZE];
  size_t n_elem = fread(buf, sizeof *buf, ARRAY_SIZE, fp);
  fclose(fp);
  if (n_elem < ARRAY_SIZE) {
    printf("input fail \n");
    return 0;
  }

  if (bar(ARRAY_SIZE, buf, 0)) {
    printf("Found!");
  }

  return 0;
}
