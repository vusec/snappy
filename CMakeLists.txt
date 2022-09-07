cmake_minimum_required(VERSION 3.13)

project(AngoraSnapshot VERSION 0.0.1)

set(Rust_TOOLCHAIN "nightly")
find_package(Corrosion REQUIRED)

add_subdirectory(llvm_mode)
add_subdirectory(fuzzer)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  add_subdirectory(packaging)
endif()

if(BUILD_BENCHMARKING)
  find_package(Python3 REQUIRED)
  add_subdirectory(benchmarks)
endif()
