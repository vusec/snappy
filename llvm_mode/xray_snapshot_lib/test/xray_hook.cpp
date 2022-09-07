// RUN: %clang_cpp_xray_snapshot %s -o %t
// RUN: rm -f %t.map %t.stats %t.target.json
// RUN: llvm-xray extract --symbolize %t > %t.map
// RUN: %generate_snapshot_target \
// RUN:         %t.map 'MessagePrinter::printMessage()' \
// RUN:         --hit_count 2 > %t.target.json
// RUN: RUST_LOG=trace \
// RUN:         %ld_library_path \
// RUN:         TRACER_ENABLED=true \
// RUN:         TRACER_OUTPUT_FILE=%t.stats \
// RUN:         XRAY_SNAPSHOT_TAINTS=%S/empty.json \
// RUN:         TRACER_SNAPSHOT_TARGET=%t.target.json \
// RUN:         TRACER_STATS_ONLY=true \
// RUN:         %t 2>&1 | FileCheck --dump-input=fail %s
// REQUIRES: cpp_stdlib

#include <iostream>
#include <string>

class MessagePrinter {
  std::string message_;

public:
  MessagePrinter(std::string message) : message_(message) {}
  void printMessage() { std::cout << message_ << std::endl; }
};

int main() {
  MessagePrinter printer("Hello!");

  printer.printMessage();

  // CHECK: Before
  std::cout << "Before" << std::endl;

  // CHECK: Custom handler called
  printer.printMessage();

  // CHECK-NOT: Custom handler called
  printer.printMessage();

  return 0;
}
