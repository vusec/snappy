add_llvm_library(DFSanPass MODULE DFSanPass.cpp)
target_compile_definitions(DFSanPass PRIVATE ${LLVM_DEFINITIONS})
target_include_directories(DFSanPass PRIVATE ${LLVM_INCLUDE_DIRS})

if(WARNINGS_ENABLED)
  target_compile_options(DFSanPass PRIVATE ${WARNINGS_ENABLED})
endif()
