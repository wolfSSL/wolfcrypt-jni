#!/bin/bash

# Simple script to run Facebook Infer over java files included in this package.
#
# This is set up to run entire infer over Java classes in this package. To
# only run the RacerD thread safety analysis tool, change the command
# invocation below from "run" to "--racerd-only", ie:
#
# infer --racerd-only -- javac \
#
# Run from wolfssljni root:
#
#    $ cd wolfcryptjni
#    $ ./scripts/infer.sh
#
# By default the generated output and logs from Infer will be deleted. To keep
# them, pass 'keep' to the script:
#
#    $ ./scripts/infer.sh keep
#
# wolfSSL Inc, April 2024


# These variables may be overridden on the command line.
KEEP="${KEEP:-no}"

while [ "$1" ]; do
  if [ "$1" = 'keep' ]; then
      KEEP='yes';
  fi
  shift
done

infer --fail-on-issue run -- javac \
    src/main/java/com/wolfssl/wolfcrypt/Aes.java \
    src/main/java/com/wolfssl/wolfcrypt/AesGcm.java \
    src/main/java/com/wolfssl/wolfcrypt/Asn.java \
    src/main/java/com/wolfssl/wolfcrypt/BlockCipher.java \
    src/main/java/com/wolfssl/wolfcrypt/Chacha.java \
    src/main/java/com/wolfssl/wolfcrypt/Curve25519.java \
    src/main/java/com/wolfssl/wolfcrypt/Des3.java \
    src/main/java/com/wolfssl/wolfcrypt/Dh.java \
    src/main/java/com/wolfssl/wolfcrypt/Ecc.java \
    src/main/java/com/wolfssl/wolfcrypt/Ed25519.java \
    src/main/java/com/wolfssl/wolfcrypt/FeatureDetect.java \
    src/main/java/com/wolfssl/wolfcrypt/Fips.java \
    src/main/java/com/wolfssl/wolfcrypt/Hmac.java \
    src/main/java/com/wolfssl/wolfcrypt/Logging.java \
    src/main/java/com/wolfssl/wolfcrypt/Md5.java \
    src/main/java/com/wolfssl/wolfcrypt/MessageDigest.java \
    src/main/java/com/wolfssl/wolfcrypt/NativeStruct.java \
    src/main/java/com/wolfssl/wolfcrypt/Pwdbased.java \
    src/main/java/com/wolfssl/wolfcrypt/Rng.java \
    src/main/java/com/wolfssl/wolfcrypt/Rsa.java \
    src/main/java/com/wolfssl/wolfcrypt/Sha.java \
    src/main/java/com/wolfssl/wolfcrypt/Sha256.java \
    src/main/java/com/wolfssl/wolfcrypt/Sha384.java \
    src/main/java/com/wolfssl/wolfcrypt/Sha512.java \
    src/main/java/com/wolfssl/wolfcrypt/WolfCrypt.java \
    src/main/java/com/wolfssl/wolfcrypt/WolfCryptError.java \
    src/main/java/com/wolfssl/wolfcrypt/WolfCryptException.java \
    src/main/java/com/wolfssl/wolfcrypt/WolfCryptState.java \
    src/main/java/com/wolfssl/wolfcrypt/WolfObject.java \
    src/main/java/com/wolfssl/wolfcrypt/WolfSSLCertManager.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptCipher.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptDebug.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptKeyAgreement.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptKeyPairGenerator.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptMac.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptMessageDigestMd5.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptMessageDigestSha.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptMessageDigestSha256.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptMessageDigestSha384.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptMessageDigestSha512.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptPBEKey.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptPKIXCertPathValidator.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptProvider.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptRandom.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptSecretKeyFactory.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptSignature.java \
    src/main/java/com/wolfssl/provider/jce/WolfSSLKeyStore.java

RETVAL=$?

# remove compiled class files
rm -r ./com

# remove infer out directory (comment this out to inspect logs if needed)
if [ "$RETVAL" == '0' ] && [ "$KEEP" == 'no' ]; then
    rm -r ./infer-out
fi

if [ "$RETVAL" == '2' ]; then
    # GitHub Actions expects return of 1 to mark step as failure
    exit 1
fi

