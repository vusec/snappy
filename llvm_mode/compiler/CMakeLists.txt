set(PASS_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}/lib${LLVM_LIBDIR_SUFFIX}")
set(ANGORA_PASS_PATH "${PASS_INSTALL_PREFIX}/$<TARGET_FILE_NAME:AngoraPass>")
set(UNFOLD_BRANCH_PASS_PATH
    "${PASS_INSTALL_PREFIX}/$<TARGET_FILE_NAME:UnfoldBranchPass>")
set(DFSAN_PASS_PATH "${PASS_INSTALL_PREFIX}/$<TARGET_FILE_NAME:DFSanPass>")

set(ANGORA_ABILISTS_ARRAY_BODY)
foreach(ABILIST ${ANGORA_ABILISTS_INSTALL})
  set(ANGORA_ABILISTS_ARRAY_BODY
      "${ANGORA_ABILISTS_ARRAY_BODY}  \"${ABILIST}\",\n")
endforeach()

set(ANGORA_ABILISTS ${ANGORA_ABILISTS_INSTALL})

set(RTLIB_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
set(FAST_RTLIB_PATH
    "${RTLIB_INSTALL_PREFIX}/$<TARGET_FILE_NAME:runtime_fast-static>")
set(TRACK_RTLIB_PATH
    "${RTLIB_INSTALL_PREFIX}/$<TARGET_FILE_NAME:runtime-static>")
set(EXTRA_RTLIB_PATH "${RTLIB_INSTALL_PREFIX}/$<TARGET_FILE_NAME:DFSanIO>")
set(DFSAN_RTLIB_PATH
    "${CMAKE_INSTALL_PREFIX}/lib/linux/libclang_rt.dfsan-x86_64.a")
set(DFSAN_RTLIB_SYMS_PATH
    "${CMAKE_INSTALL_PREFIX}/lib/linux/libclang_rt.dfsan-x86_64.a.syms")

configure_file(install_locations.h.in install_locations.h.gen @ONLY)
file(
  GENERATE
  OUTPUT install_locations.h
  INPUT "${CMAKE_CURRENT_BINARY_DIR}/install_locations.h.gen")

add_executable(AngoraClang angora_clang.c)
target_include_directories(AngoraClang PRIVATE ${PROJECT_SOURCE_DIR}/include
                                               ${CMAKE_CURRENT_BINARY_DIR})
set_target_properties(AngoraClang PROPERTIES OUTPUT_NAME "angora-clang")

add_custom_command(
  TARGET AngoraClang
  POST_BUILD
  COMMAND ln -sf "angora-clang" "angora-clang++")
install(TARGETS AngoraClang DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/angora-clang++
        DESTINATION ${CMAKE_INSTALL_BINDIR})

if(BUILD_TESTING)
  # If testing is enabled, build a version of the wrapper that refers to the
  # artifacts in the build directory. This version of the wrapper can be used
  # directly in tests, without requiring to install the project.

  set(ANGORA_PASS_PATH $<TARGET_FILE:AngoraPass>)
  set(UNFOLD_BRANCH_PASS_PATH $<TARGET_FILE:UnfoldBranchPass>)
  set(DFSAN_PASS_PATH $<TARGET_FILE:DFSanPass>)

  set(ANGORA_ABILISTS_ARRAY_BODY)
  foreach(ABILIST ${ANGORA_ABILISTS_BUILD})
    set(ANGORA_ABILISTS_ARRAY_BODY
        "${ANGORA_ABILISTS_ARRAY_BODY}  \"${ABILIST}\",\n")
  endforeach()

  set(FAST_RTLIB_PATH "$<TARGET_FILE:runtime_fast-static>")
  set(TRACK_RTLIB_PATH "$<TARGET_FILE:runtime-static>")
  set(EXTRA_RTLIB_PATH "$<TARGET_FILE:DFSanIO>")
  set(DFSAN_RTLIB_PATH
      "${PROJECT_BINARY_DIR}/dfsan_rt/lib/linux/libclang_rt.dfsan-x86_64.a")
  set(DFSAN_RTLIB_SYMS_PATH
      "${PROJECT_BINARY_DIR}/dfsan_rt/lib/linux/libclang_rt.dfsan-x86_64.a.syms"
  )

  configure_file(install_locations.h.in build_locations.h.gen @ONLY)
  file(
    GENERATE
    OUTPUT build_locations.h
    INPUT "${CMAKE_CURRENT_BINARY_DIR}/build_locations.h.gen")

  add_executable(AngoraClangTest angora_clang.c)
  target_compile_definitions(AngoraClangTest PRIVATE TEST_BUILD)
  target_include_directories(
    AngoraClangTest PRIVATE ${PROJECT_SOURCE_DIR}/include
                            ${CMAKE_CURRENT_BINARY_DIR})
  set_target_properties(AngoraClangTest PROPERTIES OUTPUT_NAME
                                                   "angora-clang-test")

  set(Angora_WRAPPER_PATH
      "${CMAKE_CURRENT_BINARY_DIR}/angora-clang-test"
      CACHE INTERNAL "")
endif()
