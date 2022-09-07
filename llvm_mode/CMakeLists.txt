cmake_minimum_required(VERSION 3.13)

project(angora_llvm_mode VERSION 1.2.2)

include(GNUInstallDirs)

if(NOT Corrosion_FOUND)
  find_package(Corrosion REQUIRED)
endif()

if(NOT LLVM_FOUND)
  find_package(LLVM 11.1 REQUIRED CONFIG)
  message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
  message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
  list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
  include(AddLLVM)
endif()

set(COMPILER_RT_STANDALONE_BUILD TRUE)
add_subdirectory(dfsan_rt)

set(TMP_ANGORA_ABILISTS_BUILD
    "${CMAKE_CURRENT_BINARY_DIR}/dfsan_rt/share/dfsan_abilist.txt")
set(TMP_ANGORA_ABILISTS_INSTALL
    "${CMAKE_INSTALL_PREFIX}/share/dfsan_abilist.txt")
add_subdirectory(rules)
set(ANGORA_ABILISTS_BUILD
    ${TMP_ANGORA_ABILISTS_BUILD}
    CACHE INTERNAL "List of all Angora ABI lists in build tree")
set(ANGORA_ABILISTS_INSTALL
    ${TMP_ANGORA_ABILISTS_INSTALL}
    CACHE INTERNAL "List of all Angora ABI lists in installation")

add_subdirectory(compiler)
add_subdirectory(pass)
add_subdirectory(external_lib)
add_subdirectory(runtime)
add_subdirectory(runtime_fast)