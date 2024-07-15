#!/bin/bash
#
# Script to convert system CA certs KeyStore file from JKS to WKS format
#
# This script tries to detect OS variant and Java version to find correct
# CA certificate KeyStore for this system.
#
# The following search order is used for trying to find either cacerts,
# jssecacerts, or both:
#
# cacerts
#   1. $JAVA_HOME/lib/security/cacerts         (JDK 9+)
#   2. $JAVA_HOME/jre/lib/security/cacerts     (JDK <= 8)
#
# jssecacerts:
#
#   1. $JAVA_HOME/lib/security/jssecacerts     (JDK 9+)
#   2. $JAVA_HOME/jre/lib/security/jssecacerts (JDK <= 8)
#
# The default cacerts.jks password is 'changeit'. Since wolfCrypt FIPS
# requires a minimum HMAC key size of 14 bytes, we expand the password
# to 'changeitchangeit' here to get past the 14 byte limitation when using
# WKS type.
#

# Export library paths for Linux and Mac to find shared JNI library
export LD_LIBRARY_PATH=../../../lib:$LD_LIBRARY_PATH
export DYLD_LIBRARY_PATH=../../../lib:$DYLD_LIBRARY_PATH

OUTDIR=`pwd`

# ARGS: <input-keystore-name> <output-keystore-name> <in-password> <out-password>
jks_to_wks() {
    keytool -importkeystore -srckeystore ${1} -destkeystore ${2}.wks -srcstoretype JKS -deststoretype WKS -srcstorepass "$3" -deststorepass "$3" -deststorepass "$4" -provider com.wolfssl.provider.jce.WolfCryptProvider --providerpath ../../../lib/wolfcrypt-jni.jar &> /dev/null
    if [ $? -ne 0 ]; then
        printf "Failed to convert JKS to WKS!"
        exit 1
    fi

}

OS=`uname`
ARCH=`uname -a`

CACERTS_JDK9="lib/security/cacerts"
CACERTS_JDK8="jre/lib/security/cacerts"
JSSECACERTS_JDK9="lib/security/jssecacerts"
JSSECACERTS_JDK8="jre/lib/security/jssecacerts"

echo "-----------------------------------------------------------------------"
echo "System CA KeyStore to WKS Conversion Script"
echo "-----------------------------------------------------------------------"

if [ -z "$JAVA_HOME" ]; then
    echo "JAVA_HOME empty, trying to detect"
else
    echo "JAVA_HOME already set = $JAVA_HOME"
    javaHome="$JAVA_HOME"
fi

# Set up Java include and library paths for OS X and Linux
# NOTE: you may need to modify these if your platform uses different locations
if [ "$OS" == "Darwin" ]; then
    echo "Detected Darwin/OSX host OS"
    if [ -z $javaHome ]; then
        # this is broken since Big Sur, set JAVA_HOME environment var instead
        # OSX JAVA_HOME is typically similar to:
        #    /Library/Java/JavaVirtualMachines/jdk1.8.0_261.jdk/Contents/Home
        javaHome=`/usr/libexec/java_home`
    fi
elif [ "$OS" == "Linux" ] ; then
    echo "Detected Linux host OS"
    if [ -z $javaHome ]; then
        javaHome=`echo $(dirname $(dirname $(readlink -f $(which java))))`
    fi
    if [ ! -d "$javaHome/include" ]
    then
        javaHome=`echo $(dirname $javaHome)`
    fi
else
    echo 'Unknown host OS!'
    exit
fi
echo "    $OS $ARCH"
echo "Java Home = $javaHome"
echo ""

if [ ! -d $OUTDIR ]; then
    mkdir $OUTDIR
fi

if [ -f "$javaHome/$CACERTS_JDK9" ]; then
    echo "System cacerts found, converting from JKS to WKS:"
    echo "    FROM: $javaHome/$CACERTS_JDK9"
    echo "    TO:   $OUTDIR/cacerts.wks"
    echo "    IN PASS (default): changeit"
    echo "    OUT PASS: changeitchangeit"
    if [ -f $OUTDIR/cacerts.wks ]; then
        rm $OUTDIR/cacerts.wks
    fi
    jks_to_wks "$javaHome/$CACERTS_JDK9" "$OUTDIR/cacerts" "changeit" "changeitchangeit"
fi

if [ -f "$javaHome/$CACERTS_JDK8" ]; then
    echo "System cacerts found, converting from JKS to WKS:"
    echo "    FROM: $javaHome/$CACERTS_JDK8"
    echo "    TO:   $OUTDIR/cacerts.wks"
    echo "    IN PASS (default): changeit"
    echo "    OUT PASS: changeitchangeit"
    if [ -f $OUTDIR/cacerts.wks ]; then
        rm $OUTDIR/cacerts.wks
    fi
    jks_to_wks "$javaHome/$CACERTS_JDK8" "$OUTDIR/cacerts" "changeit" "changeitchangeit"
fi

if [ -f "$javaHome/$JSSECERTS_JDK9" ]; then
    echo "System jssecacerts found, converting from JKS to WKS:"
    echo "    FROM: $javaHome/$JSSECACERTS_JDK9"
    echo "    TO:   $OUTDIR/jssecacerts.wks"
    echo "    IN PASS (default): changeit"
    echo "    OUT PASS: changeitchangeit"
    if [ -f $OUTDIR/jssecacerts.wks ]; then
        rm $OUTDIR/jssecacerts.wks
    fi
    jks_to_wks "$javaHome/$JSSECACERTS_JDK9" "$OUTDIR/jssecacerts" "changeit" "changeitchangeit"
fi

if [ -f "$javaHome/$JSSECERTS_JDK8" ]; then
    echo "System jssecacerts found, converting from JKS to WKS:"
    echo "    FROM: $javaHome/$JSSECACERTS_JDK8"
    echo "    TO:   $OUTDIR/jssecacerts.wks"
    echo "    IN PASS (default): changeit"
    echo "    OUT PASS: changeitchangeit"
    if [ -f $OUTDIR/jssecacerts.wks ]; then
        rm $OUTDIR/jssecacerts.wks
    fi
    jks_to_wks "$javaHome/$JSSECACERTS_JDK8" "$OUTDIR/jssecacerts" "changeit" "changeitchangeit"
fi

echo ""
echo "Successfully converted JKS to WKS"

