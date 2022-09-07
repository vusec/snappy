cmake_minimum_required(VERSION 3.13)

project(XRaySnapshot)

if(NOT Corrosion_FOUND)
  find_package(Corrosion REQUIRED)
endif()

include(GNUInstallDirs)

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

set(PASS_NAME "LLVM${PROJECT_NAME}")
set(RTLIB_NAME "${PROJECT_NAME}RT")

add_subdirectory(src)
add_subdirectory(rtlib)
add_subdirectory(scripts)

if(BUILD_TESTING)
  find_package(Python3 REQUIRED)
  find_program(LIT_PROGRAM lit)
  add_subdirectory(test)
endif()
