/*
  Test:
  a[x] will alloca memory.
  we test that if we can make make it try to apply large memory to triger crash.

*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int main (int argc, char** argv) {
  if (argc < 2) return 0;

  FILE *fp;
  char buf[255];
  size_t ret;

  fp = fopen(argv[1], "rb");
  if (!fp) {
    fprintf(stderr, "Could not open file (%s): %s", argv[1], strerror(errno));
    return 1;
  }

  int len = 20;
  ret = fread(buf, sizeof *buf, len, fp);
  fclose(fp);

  if (ret < len) {
    fprintf(stderr, "Could not read %d bytes from file (%s)", len, argv[1]);
    return 1;
  }

  uint16_t x = 0;
  memcpy(&x, buf + 1, 2); // x 0 - 1

  int a[x];

  memset(a, 0, x);

  int sum = 0;
  for (int i = 0; i < 1; i ++) {
    sum += a[i];
  }

  printf("sum %d\n", sum);

  return 0;
}
