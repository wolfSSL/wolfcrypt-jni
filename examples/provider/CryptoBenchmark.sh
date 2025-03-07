#!/bin/bash

# Flag to track if we downloaded BC during this session
BC_DOWNLOADED=false

# Function to download Bouncy Castle JARs
download_bc_jars() {
  local bc_version="1.79"
  local lib_dir="../../../lib"
  local bc_url="https://downloads.bouncycastle.org/java"

  echo -n "Downloading Bouncy Castle JARs... "

  # Create lib directory if it doesn't exist
  mkdir -p "$lib_dir" 2>/dev/null

  # Download both required JARs
  if command -v wget >/dev/null; then
    wget -q -P "$lib_dir" "$bc_url/bcprov-jdk18on-$bc_version.jar" 2>/dev/null &&
      wget -q -P "$lib_dir" "$bc_url/bctls-jdk18on-$bc_version.jar" 2>/dev/null || return 1
  elif command -v curl >/dev/null; then
    curl -s -L -o "$lib_dir/bcprov-jdk18on-$bc_version.jar" "$bc_url/bcprov-jdk18on-$bc_version.jar" 2>/dev/null &&
      curl -s -L -o "$lib_dir/bctls-jdk18on-$bc_version.jar" "$bc_url/bctls-jdk18on-$bc_version.jar" 2>/dev/null || return 1
  else
    echo "failed"
    echo "Error: Neither wget nor curl is available. Please install either wget or curl."
    return 1
  fi

  # Verify downloads were successful
  if [ -f "$lib_dir/bcprov-jdk18on-$bc_version.jar" ] && [ -f "$lib_dir/bctls-jdk18on-$bc_version.jar" ]; then
    echo "done"
    BC_DOWNLOADED=true
    return 0
  else
    echo "failed"
    return 1
  fi
}

# Function to cleanup BC JARs
cleanup_bc_jars() {
  local lib_dir="../../../lib"
  echo -n "Removing Bouncy Castle JARs... "
  rm -f "$lib_dir/bcprov-jdk18on-1.79.jar" "$lib_dir/bctls-jdk18on-1.79.jar" 2>/dev/null
  if [ $? -eq 0 ]; then
    echo "done"
    return 0
  else
    echo "failed"
    return 1
  fi
}

cd ./examples/build/provider

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:../../../lib/:/usr/local/lib

CLASSPATH="../../../lib/wolfcrypt-jni.jar:."

if [ -f "../../../lib/bcprov-jdk18on-1.79.jar" ] && [ -f "../../../lib/bctls-jdk18on-1.79.jar" ]; then
  echo "Running crypto benchmark with Bouncy Castle"
  CLASSPATH="$CLASSPATH:../../../lib/bcprov-jdk18on-1.79.jar:../../../lib/bctls-jdk18on-1.79.jar"
else
  echo "Bouncy Castle JARs not found in lib directory"
  read -p "Would you like to download Bouncy Castle JARs? (y/n) " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    if download_bc_jars; then
      echo "Running crypto benchmark with Bouncy Castle"
      CLASSPATH="$CLASSPATH:../../../lib/bcprov-jdk18on-1.79.jar:../../../lib/bctls-jdk18on-1.79.jar"
    else
      echo "Running crypto benchmark without Bouncy Castle due to download failure"
    fi
  else
    echo "Running crypto benchmark without Bouncy Castle"
  fi
fi

# Run the benchmark
java -XX:-TieredCompilation -XX:ReservedCodeCacheSize=1024m -classpath $CLASSPATH -Dsun.boot.library.path=../../../lib/ CryptoBenchmark $@

# Always prompt for cleanup after benchmark completion if Bouncy Castle files exist
if [ -f "../../../lib/bcprov-jdk18on-1.79.jar" ] && [ -f "../../../lib/bctls-jdk18on-1.79.jar" ]; then
  echo
  read -p "Would you like to remove the Bouncy Castle JARs? (y/n) " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    cleanup_bc_jars
  else
    echo "Keeping Bouncy Castle JARs for future use"
  fi
fi
