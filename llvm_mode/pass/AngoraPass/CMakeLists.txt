execute_process(
  COMMAND cat ${PROJECT_SOURCE_DIR}/../common/src/config.rs
  COMMAND grep "pub const MAP_SIZE_POW2"
  COMMAND cut -f2 -d "="
  COMMAND grep -o "[[:digit:]]*"
  COMMAND tr -d "\n"
  OUTPUT_VARIABLE MAP_SIZE_POW2)
message(STATUS "MAP_SIZE_POW2: ${MAP_SIZE_POW2}")

add_llvm_library(AngoraPass MODULE AngoraPass.cpp)
target_compile_definitions(AngoraPass PRIVATE ${LLVM_DEFINITIONS})
target_include_directories(AngoraPass PRIVATE ${LLVM_INCLUDE_DIRS}
                                              ${PROJECT_SOURCE_DIR}/include)
target_compile_definitions(AngoraPass PRIVATE "MAP_SIZE_POW2=${MAP_SIZE_POW2}")

if(WARNINGS_ENABLED)
  target_compile_options(AngoraPass PRIVATE ${WARNINGS_ENABLED})
endif()
