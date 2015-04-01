#!/bin/bash

## Set up Android NDK Cross Compile toolchain path
TOOLCHAIN=/usr/local/android-ndk-r10d/arm-linux-androideabi-clang3.5/bin

if [ ! -d "$TOOLCHAIN" ]; then
    echo "Set up your Android NDK Cross Compile toolchain path correctly and try again."
    exit -1
fi

## Add Android NDK Cross Compile toolchain to path
export PATH=$TOOLCHAIN:$PATH

## Set up variables to point to Cross-Compile tools
export CCBIN="$TOOLCHAIN"
export CCTOOL="$CCBIN/arm-linux-androideabi-"

## Export ARM/Android NDK Cross-Compile tools
export CC="${CCTOOL}gcc"
export RANLIB="${CCTOOL}ranlib"
export AR="${CCTOOL}ar"

## Configure the library
#ac_cv_func_malloc_0_nonnull=yes ac_cv_func_realloc_0_nonnull=yes ./configure --host=arm-linux-androideabi --enable-static --disable-shared $@

## Make the library
#make

pushd IDE/android

## Make the jar
ant build

## Clean the wrapper
ndk-build clean

## Make the wrapper
ndk-build

popd