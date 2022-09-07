#!/bin/sh
set -eux

BUILD_TYPE="debug"
# BUILD_TYPE="release"
num_jobs=1
#sync_afl="--sync_afl"
sync_afl=""
LOG_TYPE=angora
MODE="pin"
MODE="llvm"
#LOG_TYPE=info

if [ ! -z ${RELEASE+x} ]; then
    BUILD_TYPE="release"
fi

if [ ! -z ${LLVM_MODE+x} ]; then
    MODE="llvm"
fi
if [ ! -z ${PIN_MODE+x} ]; then
    MODE="pin"
fi


envs="BUILD_TYPE=${BUILD_TYPE} LOG_TYPE=${LOG_TYPE}"
fuzzer="../angora_fuzzer"
input="./input"
output="./output"

if [ "$#" -ne 1 ] || ! [ -d "$1" ]; then
    echo "Usage: $0 DIRECTORY" >&2
    exit 1
fi

rm -rf $output
name=$1

echo "Compile..."

target=${name}/${name}

rm -f ${target}.fast ${target}.cmp ${target}.taint 

# export ANGORA_CUSTOM_FN_CONTEXT=0

angora_prefix='../angora_prefix'
USE_FAST=1 \
    "${angora_prefix}/bin/angora-clang" ${target}.c -lz -o ${target}.fast
USE_TRACK=1 \
    "${angora_prefix}/bin/angora-clang" ${target}.c -lz -o ${target}.taint
"${angora_prefix}/bin/clang_snapshot_placement" \
    ${target}.c -o ${target}.placement
"${angora_prefix}/bin/clang_dfsan_snapshot" \
    ${target}.c -o ${target}.dfsan_snapshot
"${angora_prefix}/bin/clang_xray_snapshot" \
    ${target}.c -o ${target}.xray_snapshot

# USE_PIN=1 ${bin_dir}/angora-clang ${target}.c -lz -o ${target}.pin
#LLVM_COMPILER=clang wllvm -O0 -g ${target}.c -lz -o ${target}
#extract-bc ${target}
#opt -load ../bin/unfold-branch-pass.so -unfold_branch_pass < ${target}.bc > ${target}2.bc
#opt -load ../bin/angora-llvm-pass.so -angora_llvm_pass < ${target}2.bc > ${target}3.bc
#opt -load ../bin/angora-llvm-pass.so -angora_llvm_pass -TrackMode < ${target}2.bc > ${target}4.bc
#USE_FAST=1 ${bin_dir}/angora-clang ${target}.bc -lz -o ${target}.fast
#USE_TRACK=1 ${bin_dir}/angora-clang ${target}.bc -lz -o ${target}.taint
echo "Compile Done.."

args_file="./${name}/args"
if [ ! -f ${args_file} ]; then
    echo "Can't find args file in ${name}!"
    exit 1
fi

args=`cat ${args_file}`

cmd="$envs $fuzzer -M 0 -A -i $input -o $output -j $num_jobs"
if [ $MODE = "llvm" ]; then
    cmd="$cmd -m llvm
        --deterministic-seed 42
        -t ${target}.taint
        --snapshot-placement ${target}.placement
        --dfsan-snapshot ${target}.dfsan_snapshot
        --xray-snapshot ${target}.xray_snapshot
        ${sync_afl} -- ${target}.fast ${args}"
elif [ $MODE = "pin" ]; then
    cmd="$cmd -m pin -t ${target}.pin ${sync_afl} -- ${target}.fast ${args}"
fi;

echo "run: ${cmd}"
eval $cmd
