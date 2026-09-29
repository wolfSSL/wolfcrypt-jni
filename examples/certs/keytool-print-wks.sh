#!/bin/bash
# Script to print out WKS keystores using keytool -list
#
# Primarily used as a sanity check that keytool can successfully process
# WKS KeyStore files using the -list command
#
# Paths anchored to this script location, runs from any directory
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
LIB_DIR="$SCRIPT_DIR/../../lib"

# Export library paths for Linux and Mac to find shared JNI library
export LD_LIBRARY_PATH="$LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export DYLD_LIBRARY_PATH="$LIB_DIR${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"

# ARGS: <keystore file name in this directory> <password>
print_wks() {
    printf "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
    printf "KEYSTORE: %s\n" "$1"
    keytool -list -provider com.wolfssl.provider.jce.WolfCryptProvider \
        --providerpath "$LIB_DIR/wolfcrypt-jni.jar" -storetype WKS \
        -storepass "$2" -keystore "$SCRIPT_DIR/$1"
    if [ $? -ne 0 ]; then
        printf "fail"
        exit 1
    fi
}

print_wks "client.wks" "wolfsslpassword"
print_wks "client-rsa-1024.wks" "wolfsslpassword"
print_wks "client-rsa.wks" "wolfsslpassword"
print_wks "client-ecc.wks" "wolfsslpassword"
print_wks "server.wks" "wolfsslpassword"
print_wks "server-rsa-1024.wks" "wolfsslpassword"
print_wks "server-rsa.wks" "wolfsslpassword"
print_wks "server-ecc.wks" "wolfsslpassword"
print_wks "cacerts.wks" "wolfsslpassword"
print_wks "ca-client.wks" "wolfsslpassword"
print_wks "ca-server.wks" "wolfsslpassword"
print_wks "ca-server-rsa-2048.wks" "wolfsslpassword"
print_wks "ca-server-ecc-256.wks" "wolfsslpassword"

printf "\nSUCCESS printing all KeyStore files\n"
