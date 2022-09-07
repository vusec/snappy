#ifndef RUNTIME_FAST_H
#define RUNTIME_FAST_H

const char *const runtime_fast_wrapped_symbols[] = {
    "open",      "fopen",          "fopen64", "freopen",
    "freopen64", "close",          "fclose",  "mmap",
    "read",      "pread",          "fread",   "fread_unlocked",
    "fgetc",     "fgetc_unlocked", "getc",    "getc_unlocked",
    "fgets",     "fgets_unlocked", "getline", "getdelim",
    "vfscanf",   "fscanf",         "stat",    "fstat",
    "lstat",     "ftell",          "fseek",   "__xstat",
    "__lxstat",  "__fxstat"};

#endif
