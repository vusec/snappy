corrosion_import_crate(MANIFEST_PATH Cargo.toml)
target_include_directories(runtime INTERFACE include)

# Corrosion does not currently support installing libraries through CMake, so it
# is necessary to install this one manually. See:
# https://github.com/AndrewGaspar/corrosion/issues/64
install(FILES $<TARGET_FILE:runtime-static> TYPE LIB)