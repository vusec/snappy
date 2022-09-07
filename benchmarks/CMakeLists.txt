configure_file(build_benchmark.sh.in build_benchmark.sh @ONLY)

function(add_benchmark benchmarkName cargoModule perfTargets)
  add_custom_command(
    OUTPUT ${benchmarkName}_angora_fast ${benchmarkName}_angora_track
           ${benchmarkName}_snapshot_placement ${benchmarkName}_dfsan_snapshot
           ${benchmarkName}_xray_snapshot
    COMMAND "${CMAKE_CURRENT_BINARY_DIR}/build_benchmark.sh" ${benchmarkName} -g
            ${ARGN}
    DEPENDS build_benchmark.sh
            AngoraPass
            runtime_fast-static
            DFSanPass
            runtime-static
            SnapshotPlacementRT-static
            LLVMDFSanSnapshot
            DFSanSnapshotRT-static
            LLVMXRaySnapshot
            XRaySnapshotRT-static
            ${ARGN})

  add_custom_target(
    bench-${benchmarkName}-${cargoModule}
    COMMAND
      ${CMAKE_COMMAND} -E env
      BENCH_ANGORA_FAST=${CMAKE_CURRENT_BINARY_DIR}/${benchmarkName}_angora_fast
      BENCH_ANGORA_TRACK=${CMAKE_CURRENT_BINARY_DIR}/${benchmarkName}_angora_track
      BENCH_SNAPSHOT_PLACEMENT=${CMAKE_CURRENT_BINARY_DIR}/${benchmarkName}_snapshot_placement
      BENCH_DFSAN_SNAPSHOT=${CMAKE_CURRENT_BINARY_DIR}/${benchmarkName}_dfsan_snapshot
      BENCH_XRAY_SNAPSHOT=${CMAKE_CURRENT_BINARY_DIR}/${benchmarkName}_xray_snapshot
      cargo criterion --bench ${cargoModule} --manifest-path
      ${PROJECT_SOURCE_DIR}/fuzzer/Cargo.toml -- --measurement-time 30
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${benchmarkName}_angora_fast
            ${CMAKE_CURRENT_BINARY_DIR}/${benchmarkName}_angora_track
            ${CMAKE_CURRENT_BINARY_DIR}/${benchmarkName}_snapshot_placement
            ${CMAKE_CURRENT_BINARY_DIR}/${benchmarkName}_dfsan_snapshot
            ${CMAKE_CURRENT_BINARY_DIR}/${benchmarkName}_xray_snapshot)

  foreach(perfTarget ${perfTargets})
    string(REPLACE "/" "_" perfTargetNoSlash ${perfTarget})

    add_custom_target(
      perf-bench-${benchmarkName}-${cargoModule}-${perfTargetNoSlash}
      COMMAND
        ${CMAKE_COMMAND} -E env
        BENCH_ANGORA_FAST=${CMAKE_CURRENT_BINARY_DIR}/${benchmarkName}_angora_fast
        BENCH_ANGORA_TRACK=${CMAKE_CURRENT_BINARY_DIR}/${benchmarkName}_angora_track
        BENCH_SNAPSHOT_PLACEMENT=${CMAKE_CURRENT_BINARY_DIR}/${benchmarkName}_snapshot_placement
        BENCH_DFSAN_SNAPSHOT=${CMAKE_CURRENT_BINARY_DIR}/${benchmarkName}_dfsan_snapshot
        BENCH_XRAY_SNAPSHOT=${CMAKE_CURRENT_BINARY_DIR}/${benchmarkName}_xray_snapshot
        perf record --call-graph dwarf,16384 -F 997 -e cycles -o
        ${benchmarkName}_${cargoModule}_${perfTargetNoSlash}.data -- cargo
        criterion --bench ${cargoModule} --manifest-path
        ${PROJECT_SOURCE_DIR}/fuzzer/Cargo.toml -- ${perfTarget} --profile-time
        30
      BYPRODUCTS ${benchmarkName}_${cargoModule}_${perfTargetNoSlash}.data
                 ${benchmarkName}_${cargoModule}_${perfTargetNoSlash}.data.old
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${benchmarkName}_angora_fast
              ${CMAKE_CURRENT_BINARY_DIR}/${benchmarkName}_angora_track
              ${CMAKE_CURRENT_BINARY_DIR}/${benchmarkName}_snapshot_placement
              ${CMAKE_CURRENT_BINARY_DIR}/${benchmarkName}_dfsan_snapshot
              ${CMAKE_CURRENT_BINARY_DIR}/${benchmarkName}_xray_snapshot)
  endforeach()
endfunction()

set(perfTargets forkservers/plain forkservers/delayed
                delayed_forksrv_setup_teardown)
add_benchmark(echo delayed_forksrv "${perfTargets}"
              ${CMAKE_CURRENT_SOURCE_DIR}/echo.c)
