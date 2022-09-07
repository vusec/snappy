; RUN: rm -f %t.ll
; RUN: %opt_stackmapper -stack-mapper -print-after=stack-mapper %s -S -o %t.ll
; RUN: FileCheck -input-file=%t.ll %s

define void @allocate_locals() {
; CHECK-LABEL: entry
entry:
  %i32_alloca = alloca i32, align 4
  %string_alloca = alloca [10 x i8], align 1
; CHECK: call void (i64, i32, ...) @llvm.experimental.stackmap(i64 {{-?[0-9]+}}, i32 0, i32* %i32_alloca, i64 4, [10 x i8]* %string_alloca, i64 10)
; CHECK-NEXT: ret void
  ret void
}
