set(PASS_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}/lib${LLVM_LIBDIR_SUFFIX}")
set(STACK_MAPPER_PASS_PATH
    "${PASS_INSTALL_PREFIX}/$<TARGET_FILE_NAME:${PASS_NAME}>")

set(ABILIST_PATH "${ABILIST_INSTALL_PATH}")
set(RTLIB_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
set(RTLIB_PATH
    "${RTLIB_INSTALL_PREFIX}/$<TARGET_FILE_NAME:${RTLIB_NAME}-static>")
set(XRAY_NO_COMMON_PATH "${XRAY_NO_COMMON_INSTALL_PATH}")

set(DFSAN_RTLIB_OVERRIDE "${${PROJECT_NAME}_DFSAN_RT_OVERRIDE}")

configure_file(clang_dfsan_snapshot.in clang_dfsan_snapshot.gen @ONLY)
file(
  GENERATE
  OUTPUT clang_dfsan_snapshot
  INPUT "${CMAKE_CURRENT_BINARY_DIR}/clang_dfsan_snapshot.gen")
install(PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/clang_dfsan_snapshot" TYPE BIN)
install(
  PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/clang_dfsan_snapshot"
  TYPE BIN
  RENAME clang_dfsan_snapshot++)

if(BUILD_TESTING)
  # If testing is enabled, build a version of the wrapper that refers to the
  # artifacts in the build directory. This version of the wrapper can be used
  # directly in tests, without requiring to install the project.

  set(STACK_MAPPER_PASS_PATH $<TARGET_FILE:${PASS_NAME}>)

  set(ABILIST_PATH "${${PROJECT_NAME}_ABILIST_PATH}")
  # The `-static` suffix is needed because this is how Corruption defines the
  # target.
  set(RTLIB_PATH "$<TARGET_FILE:${RTLIB_NAME}-static>")
  set(XRAY_NO_COMMON_PATH ${${PROJECT_NAME}_XRAY_NO_COMMON_PATH})

  configure_file(clang_dfsan_snapshot.in clang_dfsan_snapshot_test.gen @ONLY)
  file(
    GENERATE
    OUTPUT clang_dfsan_snapshot_test
    INPUT "${CMAKE_CURRENT_BINARY_DIR}/clang_dfsan_snapshot_test.gen")

  set(${PROJECT_NAME}_WRAPPER_PATH
      "${CMAKE_CURRENT_BINARY_DIR}/clang_dfsan_snapshot_test"
      CACHE INTERNAL "")
endif()
