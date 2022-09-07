add_llvm_library(UnfoldBranchPass MODULE UnfoldBranchPass.cpp)
target_compile_definitions(UnfoldBranchPass PRIVATE ${LLVM_DEFINITIONS})
target_include_directories(UnfoldBranchPass PRIVATE ${LLVM_INCLUDE_DIRS})

if(WARNINGS_ENABLED)
  target_compile_options(UnfoldBranchPass PRIVATE ${WARNINGS_ENABLED})
endif()
