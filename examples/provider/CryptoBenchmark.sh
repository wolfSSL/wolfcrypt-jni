#!/bin/bash

# Flag to track if we downloaded BC during this session
BC_DOWNLOADED=false

# Pinned Bouncy Castle version and SHA-256 hashes for verification.
# Update these when upgrading to a new Bouncy Castle release.
BC_VERSION="1.78.1"
BC_PROV_SHA256="add5915e6acfc6ab5836e1fd8a5e21c6488536a8c1f21f386eeb3bf280b702d7"
BC_TLS_SHA256="483bd1582d3957adfe100747f22c6da0ff9532d6464f9c454181f99bfa44e52b"

# Function to verify SHA-256 hash of a downloaded file
verify_sha256() {
  local file="$1"
  local expected="$2"
  local actual=""

  if command -v sha256sum >/dev/null; then
    actual=$(sha256sum "$file" | awk '{print $1}')
  elif command -v shasum >/dev/null; then
    actual=$(shasum -a 256 "$file" | awk '{print $1}')
  else
    echo "Warning: no sha256sum or shasum available, skipping hash verification"
    return 0
  fi

  if [ "$actual" != "$expected" ]; then
    echo "SHA-256 mismatch for $file"
    echo "  expected: $expected"
    echo "  actual:   $actual"
    rm -f "$file"
    return 1
  fi
  return 0
}

# Function to download Bouncy Castle JARs with pinned version
download_bc_jars() {
  local bc_version="$BC_VERSION"
  local lib_dir="../../../lib"
  local bc_url="https://repo1.maven.org/maven2/org/bouncycastle"

  echo -n "Downloading Bouncy Castle JARs (version $bc_version)... "
  mkdir -p "$lib_dir" || {
    echo "failed (cannot create $lib_dir)"
    return 1
  }

  if command -v wget >/dev/null; then
    wget -q -P "$lib_dir" "$bc_url/bcprov-jdk18on/$bc_version/bcprov-jdk18on-$bc_version.jar" &&
      wget -q -P "$lib_dir" "$bc_url/bctls-jdk18on/$bc_version/bctls-jdk18on-$bc_version.jar" || {
      echo "failed (wget error: check URL or network)"
      return 1
    }
  elif command -v curl >/dev/null; then
    curl -sL -o "$lib_dir/bcprov-jdk18on-$bc_version.jar" "$bc_url/bcprov-jdk18on/$bc_version/bcprov-jdk18on-$bc_version.jar" &&
      curl -sL -o "$lib_dir/bctls-jdk18on-$bc_version.jar" "$bc_url/bctls-jdk18on/$bc_version/bctls-jdk18on-$bc_version.jar" || {
      echo "failed (curl error: check URL or network)"
      return 1
    }
  else
    echo "failed (neither wget nor curl installed)"
    echo "Please install wget or curl."
    return 1
  fi

  # Verify SHA-256 hashes
  verify_sha256 "$lib_dir/bcprov-jdk18on-$bc_version.jar" "$BC_PROV_SHA256" || {
    echo "failed (bcprov hash verification)"
    return 1
  }
  verify_sha256 "$lib_dir/bctls-jdk18on-$bc_version.jar" "$BC_TLS_SHA256" || {
    echo "failed (bctls hash verification)"
    return 1
  }

  echo "done"
  BC_DOWNLOADED=true
  return 0
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
      echo "Running crypto benchmark with Bouncy Castle (version $BC_VERSION)"
      CLASSPATH="$CLASSPATH:../../../lib/bcprov-jdk18on-$BC_VERSION.jar:../../../lib/bctls-jdk18on-$BC_VERSION.jar"
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