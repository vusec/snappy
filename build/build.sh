#!/bin/bash
set -euxo pipefail

BIN_PATH="$(readlink -f "$0")"
ROOT_DIR="$(dirname "$(dirname "$BIN_PATH")")"

BUILD_DIR="${ROOT_DIR}/angora_build"
INSTALL_PREFIX="${PREFIX:-${ROOT_DIR}/angora_prefix/}"

cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX}" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=TRUE
cmake --build "${BUILD_DIR}" -- -j
cmake --install "${BUILD_DIR}"
