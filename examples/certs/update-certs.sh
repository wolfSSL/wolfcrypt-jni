#!/bin/bash

# Example Certificate and Key Update Script
#
# This script is used to update all example certificates and keys by copying
# them over from a specified wolfSSL library directory.
#
# Script should be run from the <wolfcryptjni>/examples/certs directory.
# One argument should be provided, the path to a wolfSSL directory's "cert"
# directory.
#
# Script behavior:
#
#   1. Copy certs from wolfSSL certs directory to this certs directory.
#   2. Convert certs from PEM to DER where needed.
#   3. Remove text info from intermediate certs (for Android use)
#

printf "Removing and updating example certificates and keys\n"
if [ -z "$1" ]; then
    printf "\tNo directory to certs provided\n"
    printf "\tExample use ./update-certs.sh ~/wolfssl/certs\n"
    exit 1;
fi
CERT_LOCATION=$1

# Copy cert files from wolfssl/certs to local examples/certs
certList=(
    "ca-cert.pem"
    "ca-cert.der"
    "ca-ecc-cert.pem"
    "ca-ecc-cert.der"
    "ca-ecc-key.pem"
    "ca-key.pem"
    "ca-key.der"
    "client-cert.der"
    "client-cert.pem"
    "client-ecc-cert.pem"
    "client-ecc-cert.der"
    "client-key.pem"
    "client-key.der"
    "client-keyPub.der"
    "dh2048.pem"
    "ecc-client-key.der"
    "ecc-client-key.pem"
    "ecc-key.pem"
    "ecc-keyPkcs8.der"
    "server-cert.pem"
    "server-cert.der"
    "server-ecc.pem"
    "server-ecc.der"
    "server-key.pem"
    "server-key.der"
    "server-keyPkcs8.der"
    "crl/cliCrl.pem"
    "crl/crl.pem"
    "crl/crl.der"
    "crl/crl.revoked"
    "crl/eccCliCRL.pem"
    "crl/eccSrvCRL.pem"
    "intermediate/ca-int2-cert.pem"
    "intermediate/ca-int2-cert.der"
    "intermediate/ca-int2-ecc-cert.pem"
    "intermediate/ca-int2-ecc-cert.der"
    "intermediate/ca-int-cert.pem"
    "intermediate/ca-int-cert.der"
    "intermediate/ca-int-ecc-cert.pem"
    "intermediate/ca-int-ecc-cert.der"
    "intermediate/server-int-cert.pem"
    "intermediate/server-int-cert.der"
    "intermediate/server-int-ecc-cert.pem"
    "intermediate/server-int-ecc-cert.der"
    "rsapss/server-rsapss.der"
    "rsapss/server-rsapss-priv.der"
)

# ML-DSA certs/keys are newer than the latest wolfSSL release, copy them only
# when present so this script keeps working against released wolfSSL cert
# directories (warn-and-skip instead of abort).
mldsaCertList=(
    "mldsa/mldsa44-cert.pem"
    "mldsa/mldsa44-cert.der"
    "mldsa/mldsa44-key.pem"
    "mldsa/mldsa44_pub-spki.der"
    "mldsa/mldsa65-cert.pem"
    "mldsa/mldsa65-cert.der"
    "mldsa/mldsa65-key.pem"
    "mldsa/mldsa65_pub-spki.der"
    "mldsa/mldsa87-cert.pem"
    "mldsa/mldsa87-cert.der"
    "mldsa/mldsa87-key.pem"
    "mldsa/mldsa87_pub-spki.der"
)

# XMSS/XMSS^MT (RFC 8391) verify-only test cert.
# See examples/certs/xmss/README for how it was generated.
xmssCertList=(
    "xmss/xmss_root_cert.der"
)

for i in ${!certList[@]};
do
    printf "Updating: ${certList[$i]}\n"
    cp $CERT_LOCATION/${certList[$i]} ./${certList[$i]}
    if [ $? -ne 0 ]; then
        printf "Failed to copy cert: ${certList[$i]}\n"
        exit 1
    fi
done

if [ -d "$CERT_LOCATION/mldsa" ]; then
    for i in ${!mldsaCertList[@]};
    do
        printf "Updating: ${mldsaCertList[$i]}\n"
        cp $CERT_LOCATION/${mldsaCertList[$i]} ./${mldsaCertList[$i]}
        if [ $? -ne 0 ]; then
            printf "Warning: skipped missing ML-DSA cert: "
            printf "${mldsaCertList[$i]}\n"
        fi
    done
else
    printf "Notice: $CERT_LOCATION/mldsa not found, skipping ML-DSA\n"
    printf "certs (provided wolfSSL predates them), keeping existing\n"
    printf "local copies\n"
fi

if [ -d "$CERT_LOCATION/xmss" ]; then
    for i in ${!xmssCertList[@]};
    do
        printf "Updating: ${xmssCertList[$i]}\n"
        cp $CERT_LOCATION/${xmssCertList[$i]} ./${xmssCertList[$i]}
        if [ $? -ne 0 ]; then
            printf "Warning: skipped missing XMSS cert: "
            printf "${xmssCertList[$i]}\n"
        fi
    done
else
    printf "Notice: $CERT_LOCATION/xmss not found, skipping XMSS\n"
    printf "certs (provided wolfSSL predates them), keeping existing\n"
    printf "local copies\n"
fi

# Generate ca-keyPkcs8.der, used by examples/X509CertificateGeneration.java
openssl pkcs8 -topk8 -inform DER -outform DER -in ca-key.der -out ca-keyPkcs8.der -nocrypt
if [ $? -ne 0 ]; then
    printf "Failed to generate ca-keyPkcs8.der"
    exit 1
fi
printf "Generated ca-keyPkcs8.der\n"

# Remove text info from intermediate certs, causes issues on Android (WRONG TAG)
printf "Removing text info from intermediate certs\n"
sed -i.bak -n '/-----BEGIN CERTIFICATE-----/,$p' intermediate/ca-int2-cert.pem
sed -i.bak -n '/-----BEGIN CERTIFICATE-----/,$p' intermediate/ca-int2-ecc-cert.pem
sed -i.bak -n '/-----BEGIN CERTIFICATE-----/,$p' intermediate/ca-int-cert.pem
sed -i.bak -n '/-----BEGIN CERTIFICATE-----/,$p' intermediate/ca-int-ecc-cert.pem
sed -i.bak -n '/-----BEGIN CERTIFICATE-----/,$p' intermediate/server-int-cert.pem
sed -i.bak -n '/-----BEGIN CERTIFICATE-----/,$p' intermediate/server-int-ecc-cert.pem

# Remove sed .bak files
rm intermediate/ca-int2-cert.pem.bak
rm intermediate/ca-int2-ecc-cert.pem.bak
rm intermediate/ca-int-cert.pem.bak
rm intermediate/ca-int-ecc-cert.pem.bak
rm intermediate/server-int-cert.pem.bak
rm intermediate/server-int-ecc-cert.pem.bak

printf "Finished successfully\n"

