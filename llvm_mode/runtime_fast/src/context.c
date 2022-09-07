#include <stdint.h>

extern __thread uint32_t __angora_prev_loc;
extern __thread uint32_t __angora_context;

uint32_t __angora_get_context() { return __angora_context; }

uint32_t __angora_get_prev_loc() { return __angora_prev_loc; }