#include "plugin_1.h"

#include <string.h>

static const size_t BUFFER_SIZE = 15;

static char g_buffer[BUFFER_SIZE] = "init!";

void pg2_copy_to_buffer(const char *string) {
  strncpy(g_buffer, string, BUFFER_SIZE);
}

char pg2_get_buffer_elem(size_t idx) {
  if (idx >= BUFFER_SIZE) {
    return -1;
  }

  return g_buffer[idx];
}
