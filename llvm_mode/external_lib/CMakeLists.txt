# default taint models for IO and memory allocation.
add_library(DFSanIO STATIC io_func.c stdalloc.c)
set_target_properties(DFSanIO PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(
  DFSanIO
  PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/dfsan_rt/include)
target_link_libraries(DFSanIO PUBLIC runtime)
install(TARGETS DFSanIO DESTINATION ${CMAKE_INSTALL_LIBDIR})

# custom model
add_library(ZlibRt STATIC zlib_func.c)
set_target_properties(ZlibRt PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(
  ZlibRt
  PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/dfsan_rt/include)
target_link_libraries(ZlibRt PUBLIC runtime)
install(TARGETS ZlibRt DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(FILES "zlib_abilist.txt" DESTINATION share)
