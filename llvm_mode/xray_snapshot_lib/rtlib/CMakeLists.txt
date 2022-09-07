corrosion_import_crate(MANIFEST_PATH Cargo.toml)

# Corrosion does not currently support installing libraries through CMake, so it
# is necessary to install this one manually. See:
# https://github.com/AndrewGaspar/corrosion/issues/64
install(FILES $<TARGET_FILE:${RTLIB_NAME}-static> TYPE LIB)
