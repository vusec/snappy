set(PASS_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}/lib${LLVM_LIBDIR_SUFFIX}")
set(STACK_MAPPER_PASS_PATH
    "${PASS_INSTALL_PREFIX}/$<TARGET_FILE_NAME:${PASS_NAME}>")

if(TARGET AngoraPass)
  set(ANGORA_PASS_PATH "${PASS_INSTALL_PREFIX}/$<TARGET_FILE_NAME:AngoraPass>")
  set(ANGORA_ABILISTS "${ANGORA_ABILISTS_INSTALL}")
endif()

set(RTLIB_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
set(RTLIB_PATH
    "${RTLIB_INSTALL_PREFIX}/$<TARGET_FILE_NAME:${RTLIB_NAME}-static>")

configure_file(clang_xray_snapshot.in clang_xray_snapshot.gen @ONLY)
file(
  GENERATE
  OUTPUT clang_xray_snapshot
  INPUT "${CMAKE_CURRENT_BINARY_DIR}/clang_xray_snapshot.gen")
install(PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/clang_xray_snapshot" TYPE BIN)
install(
  PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/clang_xray_snapshot"
  TYPE BIN
  RENAME clang_xray_snapshot++)

if(BUILD_TESTING)
  # If testing is enabled, build a version of the wrapper that refers to the
  # artifacts in the build directory. This version of the wrapper can be used
  # directly in tests, without requiring to install the project.

  set(STACK_MAPPER_PASS_PATH $<TARGET_FILE:${PASS_NAME}>)

  if(TARGET AngoraPass)
    set(ANGORA_PASS_PATH "$<TARGET_FILE:AngoraPass>")
    set(ANGORA_ABILISTS "${ANGORA_ABILISTS_BUILD}")
  endif()

  # The `-static` suffix is needed because this is how Corruption defines the
  # target.
  set(RTLIB_PATH "$<TARGET_FILE:${RTLIB_NAME}-static>")

  configure_file(clang_xray_snapshot.in clang_xray_snapshot_test.gen @ONLY)
  file(
    GENERATE
    OUTPUT clang_xray_snapshot_test
    INPUT "${CMAKE_CURRENT_BINARY_DIR}/clang_xray_snapshot_test.gen")
  file(
    GENERATE
    OUTPUT clang_xray_snapshot_test++
    INPUT "${CMAKE_CURRENT_BINARY_DIR}/clang_xray_snapshot_test.gen")

  set(${PROJECT_NAME}_WRAPPER_PATH
      "${CMAKE_CURRENT_BINARY_DIR}/clang_xray_snapshot_test"
      CACHE INTERNAL "")
endif()
