#ifndef FORMAT_BUFFER_H
#define FORMAT_BUFFER_H

#include <cstdarg>
#include <cstdlib>
#include <sanitizer/dfsan_interface.h>

extern "C" int format_buffer(char *str, size_t size, const char *fmt,
                             dfsan_label *va_labels, dfsan_label *ret_label,
                             va_list ap);

#endif // FORMAT_BUFFER_H
