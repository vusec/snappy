#include "stdint.h"

extern __thread uint32_t __angora_prev_loc;
extern __thread uint32_t __angora_context;

void __angora_reset_context() {
  __angora_prev_loc = 0;
  __angora_context = 0;
}
