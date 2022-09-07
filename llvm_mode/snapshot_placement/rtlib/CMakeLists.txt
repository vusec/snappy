corrosion_import_crate(MANIFEST_PATH Cargo.toml)

# Corrosion does not currently support installing libraries through CMake, so it
# is necessary to install this one manually. See:
# https://github.com/AndrewGaspar/corrosion/issues/64
install(PROGRAMS $<TARGET_FILE:${RTLIB_NAME}-static> TYPE LIB)

# Create custom ABI list
if(NOT DFSAN_ORIGINAL_ABILIST)
  set(DFSAN_ORIGINAL_ABILIST "${LIBCLANG_PREFIX}/share/dfsan_abilist.txt")

  if(NOT EXISTS ${DFSAN_ORIGINAL_ABILIST})
    message(FATAL_ERROR "Could not find abilist in: ${DFSAN_ORIGINAL_ABILIST}")
  endif()

  message(STATUS "Original DFSan ABI list: ${DFSAN_ORIGINAL_ABILIST}")
endif()

set(CUSTOM_ABILIST_NAME snapshot_placement_abilist.txt)
add_custom_command(
  OUTPUT ${CUSTOM_ABILIST_NAME}
  COMMAND
    Python3::Interpreter
    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_abilist.py"
    ${DFSAN_ORIGINAL_ABILIST} "${CMAKE_CURRENT_SOURCE_DIR}/project_abilist.txt"
    -o ${CUSTOM_ABILIST_NAME}
  COMMENT "Generating custom ABI list"
  DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/project_abilist.txt")

add_custom_target(${PROJECT_NAME}_abilist ALL DEPENDS ${CUSTOM_ABILIST_NAME})

set(${PROJECT_NAME}_ABILIST_PATH
    "${CMAKE_CURRENT_BINARY_DIR}/${CUSTOM_ABILIST_NAME}"
    CACHE INTERNAL "")

install(FILES ${${PROJECT_NAME}_ABILIST_PATH}
        DESTINATION ${CMAKE_INSTALL_DATADIR})
set(ABILIST_INSTALL_PATH
    "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}/${CUSTOM_ABILIST_NAME}"
    PARENT_SCOPE)

# These symbols have to be wrapped using ld because they are present in
# compiler-rt as well
set(${PROJECT_NAME}_DFSAN_RT_OVERRIDE
    "__dfsw_fgets"
    "__dfsw_read"
    "__dfsw_pread"
    "__dfsw_strchr"
    "__dfsw_memcmp"
    "__dfsw_strcmp"
    "__dfsw_strcasecmp"
    "__dfsw_strncmp"
    "__dfsw_strncasecmp"
    "__dfsw_strlen"
    "__dfsw_memchr"
    "__dfsw_strrchr"
    "__dfsw_strstr"
    "__dfsw_strtol"
    "__dfsw_strtod"
    "__dfsw_strtoll"
    "__dfsw_strtoul"
    "__dfsw_strtoull"
    CACHE INTERNAL "")

add_subdirectory(xray_no_common)
set(XRAY_NO_COMMON_INSTALL_PATH
    ${XRAY_NO_COMMON_INSTALL_PATH}
    PARENT_SCOPE)
