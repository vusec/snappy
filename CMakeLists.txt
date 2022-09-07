cmake_minimum_required(VERSION 3.13)

project(Angora VERSION 1.2.2)

if(NOT Corrosion_FOUND)
  find_package(Corrosion REQUIRED)
endif()

add_subdirectory(llvm_mode)
add_subdirectory(fuzzer)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  add_subdirectory(packaging)
endif()
