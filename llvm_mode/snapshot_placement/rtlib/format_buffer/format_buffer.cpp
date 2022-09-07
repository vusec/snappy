#include "format_buffer.h"

#include <cstdint>
#include <cstdio>
#include <cinttypes>
#include <cassert>

// The following code was all taken from LLVM 11

// This function is located at:
// compiler-rt/lib/sanitizer-common/sanitizer_libc.cpp
// `uptr` was substituted with `size_t` and the function was made static

static void *internal_memcpy(void *dest, const void *src, size_t n) {
  char *d = (char*)dest;
  const char *s = (const char *)src;
  for (size_t i = 0; i < n; ++i)
    d[i] = s[i];
  return dest;
}

// This constant is located at:
// compiler-rt/lib/dfsan/dfsan_platform.h
// `uptr` was substituted with `uintptr_t`

static const uintptr_t kShadowMask = ~0x700000000000;

// This function is located at:
// compiler-rt/lib/sanitizer-common/dfsan.h
// `uptr` was substituted with `uintptr_t`
// The function was made static and the shadow mask resolution was simplified

static inline dfsan_label *shadow_for(void *ptr) {
  return (dfsan_label *) ((((uintptr_t) ptr) & kShadowMask) << 1);
}

// The following code is located at:
// compiler-rt/lib/dfsan/dfsan_custom.cpp
// The `format_buffer function was made globally visible

// Formats a chunk either a constant string or a single format directive (e.g.,
// '%.3f').
struct Formatter {
  Formatter(char *str_, const char *fmt_, size_t size_)
      : str(str_), str_off(0), size(size_), fmt_start(fmt_), fmt_cur(fmt_),
        width(-1) {}

  int format() {
    char *tmp_fmt = build_format_string();
    int retval =
        snprintf(str + str_off, str_off < size ? size - str_off : 0, tmp_fmt,
                 0 /* used only to avoid warnings */);
    free(tmp_fmt);
    return retval;
  }

  template <typename T> int format(T arg) {
    char *tmp_fmt = build_format_string();
    int retval;
    if (width >= 0) {
      retval = snprintf(str + str_off, str_off < size ? size - str_off : 0,
                        tmp_fmt, width, arg);
    } else {
      retval = snprintf(str + str_off, str_off < size ? size - str_off : 0,
                        tmp_fmt, arg);
    }
    free(tmp_fmt);
    return retval;
  }

  char *build_format_string() {
    size_t fmt_size = fmt_cur - fmt_start + 1;
    char *new_fmt = (char *)malloc(fmt_size + 1);
    assert(new_fmt);
    internal_memcpy(new_fmt, fmt_start, fmt_size);
    new_fmt[fmt_size] = '\0';
    return new_fmt;
  }

  char *str_cur() { return str + str_off; }

  size_t num_written_bytes(int retval) {
    if (retval < 0) {
      return 0;
    }

    size_t num_avail = str_off < size ? size - str_off : 0;
    if (num_avail == 0) {
      return 0;
    }

    size_t num_written = retval;
    // A return value of {v,}snprintf of size or more means that the output was
    // truncated.
    if (num_written >= num_avail) {
      num_written -= num_avail;
    }

    return num_written;
  }

  char *str;
  size_t str_off;
  size_t size;
  const char *fmt_start;
  const char *fmt_cur;
  int width;
};

// Formats the input and propagates the input labels to the output. The output
// is stored in 'str'. 'size' bounds the number of output bytes. 'format' and
// 'ap' are the format string and the list of arguments for formatting. Returns
// the return value vsnprintf would return.
//
// The function tokenizes the format string in chunks representing either a
// constant string or a single format directive (e.g., '%.3f') and formats each
// chunk independently into the output string. This approach allows to figure
// out which bytes of the output string depends on which argument and thus to
// propagate labels more precisely.
//
// WARNING: This implementation does not support conversion specifiers with
// positional arguments.
extern "C" int format_buffer(char *str, size_t size, const char *fmt,
                             dfsan_label *va_labels, dfsan_label *ret_label,
                             va_list ap) {
  Formatter formatter(str, fmt, size);

  while (*formatter.fmt_cur) {
    formatter.fmt_start = formatter.fmt_cur;
    formatter.width = -1;
    int retval = 0;

    if (*formatter.fmt_cur != '%') {
      // Ordinary character. Consume all the characters until a '%' or the end
      // of the string.
      for (; *(formatter.fmt_cur + 1) && *(formatter.fmt_cur + 1) != '%';
           ++formatter.fmt_cur) {}
      retval = formatter.format();
      dfsan_set_label(0, formatter.str_cur(),
                      formatter.num_written_bytes(retval));
    } else {
      // Conversion directive. Consume all the characters until a conversion
      // specifier or the end of the string.
      bool end_fmt = false;
      for (; *formatter.fmt_cur && !end_fmt; ) {
        switch (*++formatter.fmt_cur) {
        case 'd':
        case 'i':
        case 'o':
        case 'u':
        case 'x':
        case 'X':
          switch (*(formatter.fmt_cur - 1)) {
          case 'h':
            // Also covers the 'hh' case (since the size of the arg is still
            // an int).
            retval = formatter.format(va_arg(ap, int));
            break;
          case 'l':
            if (formatter.fmt_cur - formatter.fmt_start >= 2 &&
                *(formatter.fmt_cur - 2) == 'l') {
              retval = formatter.format(va_arg(ap, long long int));
            } else {
              retval = formatter.format(va_arg(ap, long int));
            }
            break;
          case 'q':
            retval = formatter.format(va_arg(ap, long long int));
            break;
          case 'j':
            retval = formatter.format(va_arg(ap, intmax_t));
            break;
          case 'z':
          case 't':
            retval = formatter.format(va_arg(ap, size_t));
            break;
          default:
            retval = formatter.format(va_arg(ap, int));
          }
          dfsan_set_label(*va_labels++, formatter.str_cur(),
                          formatter.num_written_bytes(retval));
          end_fmt = true;
          break;

        case 'a':
        case 'A':
        case 'e':
        case 'E':
        case 'f':
        case 'F':
        case 'g':
        case 'G':
          if (*(formatter.fmt_cur - 1) == 'L') {
            retval = formatter.format(va_arg(ap, long double));
          } else {
            retval = formatter.format(va_arg(ap, double));
          }
          dfsan_set_label(*va_labels++, formatter.str_cur(),
                          formatter.num_written_bytes(retval));
          end_fmt = true;
          break;

        case 'c':
          retval = formatter.format(va_arg(ap, int));
          dfsan_set_label(*va_labels++, formatter.str_cur(),
                          formatter.num_written_bytes(retval));
          end_fmt = true;
          break;

        case 's': {
          char *arg = va_arg(ap, char *);
          retval = formatter.format(arg);
          va_labels++;
          internal_memcpy(shadow_for(formatter.str_cur()), shadow_for(arg),
                          sizeof(dfsan_label) *
                              formatter.num_written_bytes(retval));
          end_fmt = true;
          break;
        }

        case 'p':
          retval = formatter.format(va_arg(ap, void *));
          dfsan_set_label(*va_labels++, formatter.str_cur(),
                          formatter.num_written_bytes(retval));
          end_fmt = true;
          break;

        case 'n': {
          int *ptr = va_arg(ap, int *);
          *ptr = (int)formatter.str_off;
          va_labels++;
          dfsan_set_label(0, ptr, sizeof(ptr));
          end_fmt = true;
          break;
        }

        case '%':
          retval = formatter.format();
          dfsan_set_label(0, formatter.str_cur(),
                          formatter.num_written_bytes(retval));
          end_fmt = true;
          break;

        case '*':
          formatter.width = va_arg(ap, int);
          va_labels++;
          break;

        default:
          break;
        }
      }
    }

    if (retval < 0) {
      return retval;
    }

    formatter.fmt_cur++;
    formatter.str_off += retval;
  }

  *ret_label = 0;

  // Number of bytes written in total.
  return formatter.str_off;
}
