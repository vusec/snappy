#ifndef FFDS_H
#define FFDS_H

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t __angora_io_find_fd(int fd);
uint32_t __angora_io_find_pfile(FILE *f);
void __angora_io_add_fd(int fd);
void __angora_io_add_pfile(FILE *f);
void __angora_io_remove_fd(int fd);
void __angora_io_remove_pfile(FILE *f);

#ifdef __cplusplus
}
#endif

#endif
