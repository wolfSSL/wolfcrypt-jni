#!/bin/bash

# Paths anchored to this script location, runs from any directory
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
LIB_DIR="$SCRIPT_DIR/../../lib"

cd "$SCRIPT_DIR/../build/provider" || exit 1
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}$LIB_DIR:/usr/local/lib"
java -classpath "$LIB_DIR/wolfcrypt-jni.jar:./" -Dsun.boot.library.path="$LIB_DIR/" -Dwolfjce.debug=true ProviderTest "$@"
