//===-- dfsan_interface.h -------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DataFlowSanitizer.
//
// Public interface header.
//===----------------------------------------------------------------------===//
#ifndef DFSAN_INTERFACE_H
#define DFSAN_INTERFACE_H

#include <stddef.h>
#include <stdint.h>
#include <sanitizer/common_interface_defs.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t dfsan_label;

/// Signature of the callback argument to dfsan_set_write_callback().
typedef void (*dfsan_write_callback_t)(int fd, const void *buf, size_t count);

/// Computes the union of \c l1 and \c l2, possibly creating a union label in
/// the process.
dfsan_label dfsan_union(dfsan_label l1, dfsan_label l2);

/// Creates and returns a base label with the given description and user data.
dfsan_label dfsan_create_label(int pos);
  
/// Sets the label for each address in [addr,addr+size) to \c label.
void dfsan_set_label(dfsan_label label, void *addr, size_t size);

/// Sets the label for each address in [addr,addr+size) to the union of the
/// current label for that address and \c label.
void dfsan_add_label(dfsan_label label, void *addr, size_t size);

/// Retrieves the label associated with the given data.
///
/// The type of 'data' is arbitrary.  The function accepts a value of any type,
/// which can be truncated or extended (implicitly or explicitly) as necessary.
/// The truncation/extension operations will preserve the label of the original
/// value.
dfsan_label dfsan_get_label(long data);

/// Retrieves the label associated with the data at the given address.
dfsan_label dfsan_read_label(const void *addr, size_t size);

/// Retrieves the starting address for the shadow memory of the given address
dfsan_label * dfsan_shadow_for(void * addr);

/// Sets a callback to be invoked on calls to write().  The callback is invoked
/// before the write is done.  The write is not guaranteed to succeed when the
/// callback executes.  Pass in NULL to remove any callback.
void dfsan_set_write_callback(dfsan_write_callback_t labeled_write_callback);

/// Interceptor hooks.
/// Whenever a dfsan's custom function is called the corresponding
/// hook is called it non-zero. The hooks should be defined by the user.
/// The primary use case is taint-guided fuzzing, where the fuzzer
/// needs to see the parameters of the function and the labels.
/// FIXME: implement more hooks.
void dfsan_weak_hook_memcmp(void *caller_pc, const void *s1, const void *s2,
                            size_t n, dfsan_label s1_label,
                            dfsan_label s2_label, dfsan_label n_label);
void dfsan_weak_hook_strncmp(void *caller_pc, const char *s1, const char *s2,
                             size_t n, dfsan_label s1_label,
                             dfsan_label s2_label, dfsan_label n_label);
#ifdef __cplusplus
}  // extern "C"

template <typename T>
void dfsan_set_label(dfsan_label label, T &data) {  // NOLINT
  dfsan_set_label(label, (void *)&data, sizeof(T));
}

#include <vector>
const std::vector<tag_seg> dfsan_get_label_offsets(dfsan_label l);

#endif

#endif  // DFSAN_INTERFACE_H
