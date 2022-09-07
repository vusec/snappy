cmake_minimum_required(VERSION 3.13)

project(SnapshotPlacement)

if(NOT Corrosion_FOUND)
  # Rust nightly is needed to support c_variadic
  set(Rust_TOOLCHAIN "nightly")
  find_package(Corrosion REQUIRED)
else()
  if(NOT Rust_TOOLCHAIN MATCHES "nightly[0-9-]*")
    message(FATAL_ERROR "Nightly Rust required")
  endif()
endif()

include(GNUInstallDirs)

# LLVM is needed to retrieve the DFSan ABI list
if(NOT LLVM_FOUND)
  find_package(LLVM REQUIRED CONFIG)
  message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
  message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
  list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
  include(AddLLVM)
endif()

set(MINIMUM_REQUIRED_LLVM_VERSION 11)
if(${LLVM_VERSION_MAJOR} LESS ${MINIMUM_REQUIRED_LLVM_VERSION})
  message(
    FATAL_ERROR
      "Minimum required LLVM version: ${MINIMUM_REQUIRED_LLVM_VERSION}")
endif()

# LLVM_VERSION may include a `git` suffix
set(LLVM_VERSION_CLEAN
    "${LLVM_VERSION_MAJOR}.${LLVM_VERSION_MINOR}.${LLVM_VERSION_PATCH}")
set(LIBCLANG_PREFIX "${LLVM_LIBRARY_DIRS}/clang/${LLVM_VERSION_CLEAN}")
if(NOT EXISTS ${LIBCLANG_PREFIX})
  message(FATAL_ERROR "Could not find libclang prefix: ${LIBCLANG_PREFIX}")
endif()

find_package(Python3 REQUIRED)

set(RTLIB_NAME "${PROJECT_NAME}RT")

add_subdirectory(rtlib)
add_subdirectory(scripts)

if(BUILD_TESTING)
  find_program(LIT_PROGRAM lit REQUIRED)
  add_subdirectory(test)
endif()
