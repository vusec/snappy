/*
  The code is modified from AFL's LLVM mode.
  Angora did some minor modification on it, including:
  - add taint tracking arguments.
  - use angora's llvm passs.

   ------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#define ANGORA_MAIN

#include "alloc_inl.h"
#include "defs.h"
#include "debug.h"

#if defined(TEST_BUILD)
#include "build_locations.h"
#else
#include "install_locations.h"
#endif

#include <argp.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define ARRAY_SIZE(x) sizeof(x) / sizeof(x[0])

struct config {
  u8 clang_type;
  bool is_cxx;
};

static void verify_installation(void) {
  if (!access(ANGORA_PASS_PATH, R_OK)) {
    return;
  }
  FATAL("Unable to find 'AngoraPass.so'");
}

static struct config parse_config(char *name) {
  struct config config = {
    .clang_type = CLANG_FAST_TYPE,
    .is_cxx = false,
  };

  char* use_fast = getenv("USE_FAST");
  char* use_dfsan = getenv("USE_DFSAN");
  char* use_track = getenv("USE_TRACK");
  char* use_pin = getenv("USE_PIN");

  if (use_fast) {
    config.clang_type = CLANG_FAST_TYPE;
  } else if (use_dfsan) {
    config.clang_type = CLANG_DFSAN_TYPE;
  } else if (use_track) {
    config.clang_type = CLANG_TRACK_TYPE;
  } else if (use_pin) {
    config.clang_type = CLANG_PIN_TYPE;
  }

  if (!strcmp(name, "angora-clang++")) {
    config.is_cxx = true;
  }

  return config;
}

static u8 check_if_assembler(u32 argc, char **argv) {
  /* Check if a file with an assembler extension ("s" or "S") appears in argv */

  while (--argc) {
    char* cur = *(++argv);

    const char* ext = strrchr(cur, '.');
    if (ext && (!strcmp(ext + 1, "s") || !strcmp(ext + 1, "S"))) {
      return 1;
    }
  }

  return 0;
}

static void add_angora_pass(size_t* cc_par_cnt, char* cc_params[*cc_par_cnt], struct config* config) {
  if (config->clang_type != CLANG_DFSAN_TYPE) {
    cc_params[(*cc_par_cnt)++] = "-Xclang";
    cc_params[(*cc_par_cnt)++] = "-load";
    cc_params[(*cc_par_cnt)++] = "-Xclang";
    cc_params[(*cc_par_cnt)++] = UNFOLD_BRANCH_PASS_PATH;
  }

  cc_params[(*cc_par_cnt)++] = "-Xclang";
  cc_params[(*cc_par_cnt)++] = "-load";
  cc_params[(*cc_par_cnt)++] = "-Xclang";
  cc_params[(*cc_par_cnt)++] = ANGORA_PASS_PATH;

  cc_params[(*cc_par_cnt)++] = "-fno-builtin-bcmp"; // Incompatible with DFSan

  if (config->clang_type == CLANG_DFSAN_TYPE) {
    cc_params[(*cc_par_cnt)++] = "-mllvm";
    cc_params[(*cc_par_cnt)++] = "-DFSanMode";
  } else if (config->clang_type == CLANG_TRACK_TYPE || config->clang_type == CLANG_PIN_TYPE) {
    cc_params[(*cc_par_cnt)++] = "-mllvm";
    cc_params[(*cc_par_cnt)++] = "-TrackMode";
  }

  for (size_t idx = 0; idx < ARRAY_SIZE(angora_abilists); ++idx) {
    cc_params[(*cc_par_cnt)++] = "-mllvm";
    if (!strstr(angora_abilists[idx], "exploitation")) {
      cc_params[(*cc_par_cnt)++] =
              alloc_printf("-angora-dfsan-abilist=%s", angora_abilists[idx]);
    } else {
      cc_params[(*cc_par_cnt)++] =
          alloc_printf("-angora-exploitation-list=%s", angora_abilists[idx]);
    }
  }

  char *rule_list = getenv(TAINT_RULE_LIST_VAR);
  if (rule_list) {
    cc_params[(*cc_par_cnt)++] = "-mllvm";
    cc_params[(*cc_par_cnt)++] =
        alloc_printf("-angora-dfsan-abilist=%s", rule_list);
  }
}

static void add_angora_runtime(size_t *cc_par_cnt, char *cc_params[*cc_par_cnt],
                               struct config *config) {
  if (config->clang_type == CLANG_FAST_TYPE) {
    cc_params[(*cc_par_cnt)++] = alloc_printf("%s", FAST_RTLIB_PATH);
    cc_params[(*cc_par_cnt)++] = "-lpthread";
    cc_params[(*cc_par_cnt)++] = "-ldl";
    cc_params[(*cc_par_cnt)++] = "-lm";
  } else if (config->clang_type == CLANG_TRACK_TYPE ||
             config->clang_type == CLANG_DFSAN_TYPE) {
    cc_params[(*cc_par_cnt)++] = alloc_printf("%s", TRACK_RTLIB_PATH);
    cc_params[(*cc_par_cnt)++] = "-lpthread";
    cc_params[(*cc_par_cnt)++] = "-ldl";
  } else if (config->clang_type == CLANG_PIN_TYPE) {
    cc_params[(*cc_par_cnt)++] = alloc_printf("%s/pin_stub.o", RUNLIBS_INSTALL_DIR);
  }
}

static void add_dfsan_pass(size_t *cc_par_cnt, char *cc_params[*cc_par_cnt],
                           struct config *config) {
  if (config->clang_type == CLANG_TRACK_TYPE ||
      config->clang_type == CLANG_DFSAN_TYPE) {
    cc_params[(*cc_par_cnt)++] = "-Xclang";
    cc_params[(*cc_par_cnt)++] = "-load";
    cc_params[(*cc_par_cnt)++] = "-Xclang";
    cc_params[(*cc_par_cnt)++] = DFSAN_PASS_PATH;

    for (size_t idx = 0; idx < ARRAY_SIZE(angora_abilists); ++idx) {
      if (!strstr(angora_abilists[idx], "exploitation")) {
        cc_params[(*cc_par_cnt)++] = "-mllvm";
        cc_params[(*cc_par_cnt)++] =
            alloc_printf("-angora-dfsan-abilist2=%s", angora_abilists[idx]);
      }
    }

    char *rule_list = getenv(TAINT_RULE_LIST_VAR);
    if (rule_list) {
      cc_params[(*cc_par_cnt)++] = "-mllvm";
      cc_params[(*cc_par_cnt)++] =
          alloc_printf("-angora-dfsan-abilist2=%s", rule_list);
    }
  }
}

static void add_dfsan_runtime(size_t *cc_par_cnt, char *cc_params[*cc_par_cnt],
                              struct config *config) {
  if (config->clang_type == CLANG_TRACK_TYPE ||
      config->clang_type == CLANG_DFSAN_TYPE) {
    cc_params[(*cc_par_cnt)++] = alloc_printf(
        "-Wl,--whole-archive,%s,--no-whole-archive", DFSAN_RTLIB_PATH);
    cc_params[(*cc_par_cnt)++] =
        alloc_printf("-Wl,--dynamic-list=%s", DFSAN_RTLIB_SYMS_PATH);

    cc_params[(*cc_par_cnt)++] = alloc_printf(
        "-Wl,--whole-archive,%s,--no-whole-archive", EXTRA_RTLIB_PATH);
    char *rule_obj = getenv(TAINT_CUSTOM_RULE_VAR);
    if (rule_obj) {
      cc_params[(*cc_par_cnt)++] = rule_obj;
    }

    // Taken from tools::linkSanitizerRuntimeDeps
    cc_params[(*cc_par_cnt)++] = "-Wl,--no-as-needed";
    cc_params[(*cc_par_cnt)++] = "-lpthread";
    cc_params[(*cc_par_cnt)++] = "-lrt";
    cc_params[(*cc_par_cnt)++] = "-lm";
    cc_params[(*cc_par_cnt)++] = "-ldl";
  }
}

static char** edit_params(u32 argc, char **argv) {

  u8 fortify_set = 0, x_set = 0, maybe_linking = 1, bit_mode = 0;
  u8 maybe_assembler = 0;

  char** cc_params = ck_alloc((argc + 128) * sizeof(char*));
  size_t cc_par_cnt = 0;

  char* name = strrchr(argv[0], '/');
  if (!name)
    name = argv[0];
  else
    name++;

  struct config config = parse_config(name);

  if (config.is_cxx) {
    char* alt_cxx = getenv("ANGORA_CXX");
    cc_params[0] = alt_cxx ? alt_cxx : "clang++";
  } else {
    char* alt_cc = getenv("ANGORA_CC");
    cc_params[0] = alt_cc ? alt_cc : "clang";
  }
  cc_par_cnt++;

  maybe_assembler = check_if_assembler(argc, argv);

  /* Detect stray -v calls from ./configure scripts. */
  if (argc == 1 && !strcmp(argv[1], "-v"))
    maybe_linking = 0;

  bool sanitizers_disabled = false;
  if (getenv("ANGORA_DISABLE_SANITIZERS")) {
    sanitizers_disabled = true;
  }

  bool asan_set = false;

  while (--argc) {
    char* cur = *(++argv);
    // FIXME
    if (!strcmp(cur, "-O1") || !strcmp(cur, "-O2") || !strcmp(cur, "-O3")) {
      continue;
    }
    if (!strcmp(cur, "-m32"))
      bit_mode = 32;
    if (!strcmp(cur, "-m64"))
      bit_mode = 64;

    if (!strcmp(cur, "-x"))
      x_set = 1;

    if (!strcmp(cur, "-c") || !strcmp(cur, "-S") || !strcmp(cur, "-E"))
      maybe_linking = 0;

    if (!strncmp(cur, "-fsanitize=", strlen("-fsanitize="))) {
      if (config.clang_type == CLANG_TRACK_TYPE ||
          config.clang_type == CLANG_DFSAN_TYPE || sanitizers_disabled) {
        // Always disable sanitizers when using DFSan because they are not
        // compatible.
        char *fsanitize_arg = strchr(cur, '=');
        assert(fsanitize_arg);
        fsanitize_arg++;
        printf("warning: ignoring incompatible sanitizers: %s\n", fsanitize_arg);
        continue;
      }

      asan_set = true;
    }

    if (strstr(cur, "FORTIFY_SOURCE"))
      fortify_set = 1;

    if (!strcmp(cur, "-shared"))
      maybe_linking = 0;

    if (!strcmp(cur, "-Wl,-z,defs") || !strcmp(cur, "-Wl,--no-undefined"))
      continue;

    cc_params[cc_par_cnt++] = cur;
  }

  if (!maybe_assembler) {
    add_angora_pass(&cc_par_cnt, cc_params, &config);
    add_dfsan_pass(&cc_par_cnt, cc_params, &config);
  }

  cc_params[cc_par_cnt++] = "-pie";
  cc_params[cc_par_cnt++] = "-fpic";
  cc_params[cc_par_cnt++] = "-Qunused-arguments";
  /*
  cc_params[cc_par_cnt++] = "-mno-mmx";
  cc_params[cc_par_cnt++] = "-mno-sse";
  cc_params[cc_par_cnt++] = "-mno-sse2";
  cc_params[cc_par_cnt++] = "-mno-avx";
  cc_params[cc_par_cnt++] = "-mno-sse3";
  cc_params[cc_par_cnt++] = "-mno-sse4.1";
  cc_params[cc_par_cnt++] = "-mno-sse4.2";
  cc_params[cc_par_cnt++] = "-mno-ssse3";
  */

  if (getenv("ANGORA_HARDEN")) {
    cc_params[cc_par_cnt++] = "-fstack-protector-all";

    if (!fortify_set)
      cc_params[cc_par_cnt++] = "-D_FORTIFY_SOURCE=2";
  }

  if (!asan_set && config.clang_type == CLANG_FAST_TYPE) {
    // We did not test Angora on asan and msan..
    if (getenv("ANGORA_USE_ASAN")) {

      if (getenv("ANGORA_USE_MSAN"))
        FATAL("ASAN and MSAN are mutually exclusive");

      if (getenv("ANGORA_HARDEN"))
        FATAL("ASAN and ANGORA_HARDEN are mutually exclusive");

      cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
      cc_params[cc_par_cnt++] = "-fsanitize=address";

    } else if (getenv("ANGORA_USE_MSAN")) {

      if (getenv("ANGORA_USE_ASAN"))
        FATAL("ASAN and MSAN are mutually exclusive");

      if (getenv("ANGORA_HARDEN"))
        FATAL("MSAN and ANGORA_HARDEN are mutually exclusive");

      cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
      cc_params[cc_par_cnt++] = "-fsanitize=memory";
    }
  }

  if (!getenv("ANGORA_DONT_OPTIMIZE")) {
    cc_params[cc_par_cnt++] = "-g";
    cc_params[cc_par_cnt++] = "-O3";
    cc_params[cc_par_cnt++] = "-funroll-loops";
  }

  /*
    cc_params[cc_par_cnt++] = "-D__ANGORA_HAVE_MANUAL_CONTROL=1";
    cc_params[cc_par_cnt++] = "-D__ANGORA_COMPILER=1";
    cc_params[cc_par_cnt++] = "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1";
  */
  /* When the user tries to use persistent or deferred forkserver modes by
     appending a single line to the program, we want to reliably inject a
     signature into the binary (to be picked up by angora-fuzz) and we want
     to call a function from the runtime .o file. This is unnecessarily
     painful for three reasons:

     1) We need to convince the compiler not to optimize out the signature.
        This is done with __attribute__((used)).

     2) We need to convince the linker, when called with -Wl,--gc-sections,
        not to do the same. This is done by forcing an assignment to a
        'volatile' pointer.

     3) We need to declare __angora_persistent_loop() in the global namespace,
        but doing this within a method in a class is hard - :: and extern "C"
        are forbidden and __attribute__((alias(...))) doesn't work. Hence the
        __asm__ aliasing trick.

   */

  /*
  cc_params[cc_par_cnt++] = "-D__ANGORA_LOOP(_A)="
    "({ static volatile char *_B __attribute__((used)); "
    " _B = (char*)\"" PERSIST_SIG "\"; "
#ifdef __APPLE__
    "__attribute__((visibility(\"default\"))) "
    "int _L(unsigned int) __asm__(\"___angora_persistent_loop\"); "
#else
    "__attribute__((visibility(\"default\"))) "
    "int _L(unsigned int) __asm__(\"__angora_persistent_loop\"); "
#endif
    "_L(_A); })";

  cc_params[cc_par_cnt++] = "-D__ANGORA_INIT()="
    "do { static volatile char *_A __attribute__((used)); "
    " _A = (char*)\"" DEFER_SIG "\"; "
#ifdef __APPLE__
    "__attribute__((visibility(\"default\"))) "
    "void _I(void) __asm__(\"___angora_manual_init\"); "
#else
    "__attribute__((visibility(\"default\"))) "
    "void _I(void) __asm__(\"__angora_manual_init\"); "
#endif
    "_I(); } while (0)";
  */

  char* libcxx_prefix = NULL;
  if (config.is_cxx) {
    if (config.clang_type == CLANG_FAST_TYPE) {
      libcxx_prefix = getenv("ANGORA_LIBCXX_FAST_PREFIX");
      if (!libcxx_prefix) {
        FATAL("ANGORA_LIBCXX_FAST_PREFIX is not set");
      }
    } else if (config.clang_type == CLANG_TRACK_TYPE) {
      libcxx_prefix = getenv("ANGORA_LIBCXX_TRACK_PREFIX");
      if (!libcxx_prefix) {
        FATAL("ANGORA_LIBCXX_TRACK_PREFIX is not set");
      }
    }
    assert(libcxx_prefix != NULL);

    cc_params[cc_par_cnt++] = "-stdlib=libc++";
    cc_params[cc_par_cnt++] = "-nostdinc++";
    cc_params[cc_par_cnt++] = alloc_printf("-I%s/include/c++/v1", libcxx_prefix);
  }

  if (maybe_linking) {

    if (x_set) {
      cc_params[cc_par_cnt++] = "-x";
      cc_params[cc_par_cnt++] = "none";
    }

    add_dfsan_runtime(&cc_par_cnt, cc_params, &config);

    if (config.is_cxx) {
      // libc++ should be linked before the runtime because it relies on the
      // wrappers for the allocator, which are in the runtime.
      assert(libcxx_prefix != NULL);
      cc_params[cc_par_cnt++] = "-nostdlib++";
      cc_params[cc_par_cnt++] = alloc_printf("%s/lib/libc++.a", libcxx_prefix);
      cc_params[cc_par_cnt++] = alloc_printf("%s/lib/libc++abi.a", libcxx_prefix);
    }

    add_angora_runtime(&cc_par_cnt, cc_params, &config);

    switch (bit_mode) {
    case 0:
      break;
    case 32:
      /* if (access(cc_params[cc_par_cnt - 1], R_OK)) */
      // FATAL("-m32 is not supported by your compiler");
      break;

    case 64:
      /* if (access(cc_params[cc_par_cnt - 1], R_OK)) */
      // FATAL("-m64 is not supported by your compiler");
      break;
    }
  }

  cc_params[cc_par_cnt] = NULL;

  return cc_params;
}

enum flags_mode {
  FLAGS_MODE_UNKNOWN,
  FLAGS_MODE_COMPILER,
  FLAGS_MODE_LINKER,
};

struct arguments {
  enum flags_mode mode;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
  struct arguments *arguments = state->input;

  switch (key) {
  case 'l':
    if (arguments->mode == FLAGS_MODE_UNKNOWN) {
      arguments->mode = FLAGS_MODE_LINKER;
    } else {
      argp_error(state, "Only one between --compiler and --linker is allowed");
    }
    break;

  case 'c':
    if (arguments->mode == FLAGS_MODE_UNKNOWN) {
      arguments->mode = FLAGS_MODE_COMPILER;
    } else {
      argp_error(state, "Only one between --compiler and --linker is allowed");
    }
    break;

  case ARGP_KEY_END:
    if (arguments->mode == FLAGS_MODE_UNKNOWN) {
      argp_error(state, "One between --compiler and --linker is required");
    }
    break;

  default:
    return ARGP_ERR_UNKNOWN;
  }

  return 0;
}

int flags_main(int argc, char *argv[argc + 1]) {
  static struct argp_option options[] = {
      {"compiler", 'c', 0, 0, "Show compiler flags"},
      {"linker", 'l', 0, 0, "Show linker flags"},
      {0}};

  static struct argp argp = {options, parse_opt, 0, 0};

  struct arguments arguments = {
      .mode = FLAGS_MODE_UNKNOWN,
  };

  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  char *name = strrchr(argv[0], '/');
  if (!name) {
    name = argv[0];
  } else {
    name++;
  }
  struct config config = parse_config(name);

  char **cc_params = ck_alloc((argc + 128) * sizeof(char *));
  size_t cc_par_cnt = 0;

  switch (arguments.mode) {
  case FLAGS_MODE_COMPILER:
    add_angora_pass(&cc_par_cnt, cc_params, &config);
    add_dfsan_pass(&cc_par_cnt, cc_params, &config);
    break;
  case FLAGS_MODE_LINKER:
    add_angora_runtime(&cc_par_cnt, cc_params, &config);
    break;
  default:
    __builtin_unreachable();
  }

  for (size_t idx = 0; idx < cc_par_cnt; idx++) {
    printf("%s ", cc_params[idx]);
  }
  printf("\n");

  return 0;
}

/* Main entry point */

int main(int argc, char **argv) {

  if (argc < 2) {

    SAYF("\n"
         "This is a helper application for angora-fuzz. It serves as a drop-in "
         "replacement\n"
         "for clang, letting you recompile third-party code with the required "
         "runtime\n"
         "instrumentation. A common use pattern would be one of the "
         "following:\n\n"

         "  CC=%s/angora-clang ./configure\n"
         "  CXX=%s/angora-clang++ ./configure\n\n"

         "In contrast to the traditional angora-clang tool, this version is "
         "implemented as\n"
         "an LLVM pass and tends to offer improved performance with slow "
         "programs.\n\n"

         "You can specify custom next-stage toolchain via ANGORA_CC and "
         "ANGORA_CXX. Setting\n"
         "ANGORA_HARDEN enables hardening optimizations in the compiled "
         "code.\n\n",
         "xx", "xx");

    exit(1);
  }

  verify_installation();

  if (getenv("FLAGS_MODE")) {
    return flags_main(argc, argv);
  }

  char **cc_params = edit_params(argc, argv);

  pid_t pid = fork();
  if (pid == -1) {
    perror("could not fork compiler process");
    exit(EXIT_FAILURE);
  } else if (pid == 0) {
    execvp(cc_params[0], cc_params);
    FATAL("Oops, failed to execute '%s' - check your PATH", cc_params[0]);
  } else {
    int status;
    pid_t waited_pid = wait(&status);
    if (waited_pid == -1) {
      perror("could not wait compiler process");
      exit(EXIT_FAILURE);
    }

    if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
      printf("Compilation failed, real cmdline was: ");
      for (char **iter = cc_params; *iter; ++iter) {
        printf("%s ", *iter);
      }
      printf("\n");

      exit(EXIT_FAILURE);
    }
  }

  return 0;
}
