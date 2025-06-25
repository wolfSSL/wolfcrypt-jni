#!/bin/bash

# Flag to track if we downloaded BC during this session
BC_DOWNLOADED=false

# Function to get the latest Bouncy Castle version from Maven Central
get_latest_version() {
  local metadata_url="https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/maven-metadata.xml"
  if command -v curl >/dev/null; then
    curl -s "$metadata_url" | grep '<latest>' | sed -e 's/.*<latest>\(.*\)<\/latest>.*/\1/'
  elif command -v wget >/dev/null; then
    wget -q -O - "$metadata_url" | grep '<latest>' | sed -e 's/.*<latest>\(.*\)<\/latest>.*/\1/'
  else
    echo "Error: Neither curl nor wget is installed. Please install one to fetch the latest version."
    exit 1
  fi
}

# Function to download Bouncy Castle JARs with the latest version
download_bc_jars() {
  local bc_version=$(get_latest_version)
  local lib_dir="../../../lib"
  local bc_url="https://repo1.maven.org/maven2/org/bouncycastle"

  if [ -z "$bc_version" ]; then
    echo "failed (could not determine latest version)"
    return 1
  fi

  echo -n "Downloading Bouncy Castle JARs (version $bc_version)... "
  mkdir -p "$lib_dir" || {
    echo "failed (cannot create $lib_dir)"
    return 1
  }

  if command -v wget >/dev/null; then
    wget -P "$lib_dir" "$bc_url/bcprov-jdk18on/$bc_version/bcprov-jdk18on-$bc_version.jar" &&
      wget -P "$lib_dir" "$bc_url/bctls-jdk18on/$bc_version/bctls-jdk18on-$bc_version.jar" || {
      echo "failed (wget error: check URL or network)"
      return 1
    }
  elif command -v curl >/dev/null; then
    curl -L -o "$lib_dir/bcprov-jdk18on-$bc_version.jar" "$bc_url/bcprov-jdk18on/$bc_version/bcprov-jdk18on-$bc_version.jar" &&
      curl -L -o "$lib_dir/bctls-jdk18on-$bc_version.jar" "$bc_url/bctls-jdk18on/$bc_version/bctls-jdk18on-$bc_version.jar" || {
      echo "failed (curl error: check URL or network)"
      return 1
    }
  else
    echo "failed (neither wget nor curl installed)"
    echo "Please install wget or curl."
    return 1
  fi

  if [ -f "$lib_dir/bcprov-jdk18on-$bc_version.jar" ] && [ -f "$lib_dir/bctls-jdk18on-$bc_version.jar" ]; then
    echo "done"
    BC_DOWNLOADED=true
    return 0
  else
    echo "failed (downloaded files not found)"
    return 1
  fi
}

# Function to cleanup BC JARs
cleanup_bc_jars() {
  local lib_dir="../../../lib"
  echo -n "Removing Bouncy Castle JARs... "
  rm -f "$lib_dir/bcprov-jdk18on-"*".jar" "$lib_dir/bctls-jdk18on-"*".jar" && echo "done" || echo "failed"
}

cd ./examples/build/provider || {
  echo "Error: Cannot change to ./examples/build/provider"
  exit 1
}

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:../../../lib:/usr/local/lib
CLASSPATH="../../../lib/wolfcrypt-jni.jar:."

# Check for existing Bouncy Castle JARs (any version)
if ls "../../../lib/bcprov-jdk18on-"*".jar" "../../../lib/bctls-jdk18on-"*".jar" 2>/dev/null; then
  latest_bc_jar=$(ls -t "../../../lib/bcprov-jdk18on-"*".jar" | head -n 1)
  bc_version=$(basename "$latest_bc_jar" | sed -e 's/bcprov-jdk18on-//' -e 's/.jar$//')
  echo "Running crypto benchmark with Bouncy Castle (version $bc_version)"
  CLASSPATH="$CLASSPATH:$latest_bc_jar:../../../lib/bctls-jdk18on-$bc_version.jar"
else
  echo "Bouncy Castle JARs not found in lib directory"
  read -p "Would you like to download Bouncy Castle JARs? (y/n) " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    if download_bc_jars; then
      bc_version=$(get_latest_version)
      echo "Running crypto benchmark with Bouncy Castle (version $bc_version)"
      CLASSPATH="$CLASSPATH:../../../lib/bcprov-jdk18on-$bc_version.jar:../../../lib/bctls-jdk18on-$bc_version.jar"
    else
      echo "Running crypto benchmark without Bouncy Castle due to download failure"
    fi
  else
    echo "Running crypto benchmark without Bouncy Castle"
  fi
fi

# Use interpreter mode to completely avoid CodeCache issues
# This will be slower but eliminates CodeCache fragmentation problems
echo "Running in interpreter mode to avoid CodeCache issues..."
java -Xint \
     -Xmx8g \
     -Xms4g \
     -XX:+UseG1GC \
     -XX:MaxGCPauseMillis=100 \
     -classpath "$CLASSPATH" \
     -Dsun.boot.library.path=../../../lib/ \
     CryptoBenchmark "$@"

if [ "$BC_DOWNLOADED" = true ]; then
  echo
  read -p "Would you like to remove the Bouncy Castle JARs? (y/n) " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    cleanup_bc_jars
  else
    echo "Keeping Bouncy Castle JARs for future use"
  fi
fi