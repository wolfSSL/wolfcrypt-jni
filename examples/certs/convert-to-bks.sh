#!/bin/bash

# Convert JKS KeyStore files to BKS format for Android use.
# Android does not support JKS KeyStores, so BKS format is needed.
#
# Requires a Bouncy Castle provider JAR (bcprov). Download from:
#   https://www.bouncycastle.org/download/bouncy-castle-java/
#
# Usage:
#   cd examples/certs
#   ./convert-to-bks.sh <path/to/bcprov.jar>
#
# Example:
#   ./convert-to-bks.sh ~/Downloads/bcprov-jdk18on-1.78.1.jar

if [ -z "$1" ]; then
    echo "Expected path to Bouncy Castle provider JAR."
    echo "Usage: ./convert-to-bks.sh <path/to/bcprov.jar>"
    echo ""
    echo "Example:"
    echo "  ./convert-to-bks.sh ~/Downloads/bcprov-jdk18on-1.78.1.jar"
    exit 1
fi

PROVIDER="$1"

if [ ! -f "$PROVIDER" ]; then
    echo "Error: Provider JAR not found: $PROVIDER"
    exit 1
fi

convert () {
    if [ ! -f "${1}.jks" ]; then
        echo "Warning: ${1}.jks not found, skipping"
        return
    fi

    rm -f "${1}.bks" 2>/dev/null
    keytool -importkeystore \
        -srckeystore "${1}.jks" \
        -destkeystore "${1}.bks" \
        -srcstoretype JKS \
        -deststoretype BKS \
        -srcstorepass "wolfsslpassword" \
        -deststorepass "wolfsslpassword" \
        -provider org.bouncycastle.jce.provider.BouncyCastleProvider \
        -providerpath "$PROVIDER"

    if [ $? -eq 0 ]; then
        echo "Converted: ${1}.jks -> ${1}.bks"
    else
        echo "Error converting: ${1}.jks"
        FAIL=1
    fi
}

FAIL=0

echo "Converting JKS KeyStore files to BKS format..."
echo ""

convert "ca-server-rsa-2048"
convert "ca-server-ecc-256"

echo ""
if [ $FAIL -ne 0 ]; then
    echo "One or more conversions failed."
    exit 1
fi
echo "Done."

