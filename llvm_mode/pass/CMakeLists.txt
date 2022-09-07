if(${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang" OR ${CMAKE_CXX_COMPILER_ID}
                                                STREQUAL "GNU")
  set(WARNINGS_ENABLED "-Wall" "-Wextra" "-Wno-unused-parameter")
endif()

add_subdirectory(AngoraPass)
add_subdirectory(DFSanPass)
add_subdirectory(UnfoldBranchPass)
