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

# javax.crypto.KEMSpi (used by WolfCryptMlKemKem.java) requires JDK 21+.
# build.xml and pom.xml exclude that source below JDK 21. Mirror that here so
# this script still runs on Java 8-20. KEM_SRC stays empty on older JDKs (and
# must remain unquoted below so an empty value expands to zero arguments).
JAVA_MAJOR=$(javac -version 2>&1 | sed -E 's/^javac ([0-9]+).*/\1/')
KEM_SRC=""
if [ "$JAVA_MAJOR" -ge 21 ] 2>/dev/null; then
    KEM_SRC="src/main/java/com/wolfssl/provider/jce/WolfCryptMlKemKem.java"
fi

infer --fail-on-issue run -- javac \
    src/main/java/com/wolfssl/wolfcrypt/Aes.java \
    src/main/java/com/wolfssl/wolfcrypt/AesCcm.java \
    src/main/java/com/wolfssl/wolfcrypt/AesCmac.java \
    src/main/java/com/wolfssl/wolfcrypt/AesCts.java \
    src/main/java/com/wolfssl/wolfcrypt/AesCtr.java \
    src/main/java/com/wolfssl/wolfcrypt/AesEcb.java \
    src/main/java/com/wolfssl/wolfcrypt/AesGcm.java \
    src/main/java/com/wolfssl/wolfcrypt/AesGmac.java \
    src/main/java/com/wolfssl/wolfcrypt/AesOfb.java \
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
    src/main/java/com/wolfssl/wolfcrypt/Lms.java \
    src/main/java/com/wolfssl/wolfcrypt/Logging.java \
    src/main/java/com/wolfssl/wolfcrypt/Md5.java \
    src/main/java/com/wolfssl/wolfcrypt/MessageDigest.java \
    src/main/java/com/wolfssl/wolfcrypt/MlDsa.java \
    src/main/java/com/wolfssl/wolfcrypt/MlKem.java \
    src/main/java/com/wolfssl/wolfcrypt/NativeStruct.java \
    src/main/java/com/wolfssl/wolfcrypt/Pwdbased.java \
    src/main/java/com/wolfssl/wolfcrypt/Rng.java \
    src/main/java/com/wolfssl/wolfcrypt/Rsa.java \
    src/main/java/com/wolfssl/wolfcrypt/Sha.java \
    src/main/java/com/wolfssl/wolfcrypt/Sha224.java \
    src/main/java/com/wolfssl/wolfcrypt/Sha256.java \
    src/main/java/com/wolfssl/wolfcrypt/Sha384.java \
    src/main/java/com/wolfssl/wolfcrypt/Sha512.java \
    src/main/java/com/wolfssl/wolfcrypt/Sha3.java \
    src/main/java/com/wolfssl/wolfcrypt/WolfCrypt.java \
    src/main/java/com/wolfssl/wolfcrypt/WolfCryptError.java \
    src/main/java/com/wolfssl/wolfcrypt/WolfCryptException.java \
    src/main/java/com/wolfssl/wolfcrypt/WolfCryptState.java \
    src/main/java/com/wolfssl/wolfcrypt/WolfObject.java \
    src/main/java/com/wolfssl/wolfcrypt/WolfSSLCertManager.java \
    src/main/java/com/wolfssl/wolfcrypt/WolfSSLCertManagerVerifyCallback.java \
    src/main/java/com/wolfssl/wolfcrypt/WolfSSLX509StoreCtx.java \
    src/main/java/com/wolfssl/wolfcrypt/Xmss.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptAesParameters.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptASN1Util.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptCipher.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptDebug.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptDhParameterGenerator.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptDhParameters.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptDHKeyFactory.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptDHPrivateKey.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptDHPublicKey.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptECKeyFactory.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptECParameterSpec.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptECPrivateKey.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptECPublicKey.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptRSAKeyFactory.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptRSAPrivateCrtKey.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptRSAPrivateKey.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptRSAPublicKey.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptGcmParameters.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptKeyAgreement.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptKeyGenerator.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptKeyPairGenerator.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptLmsKeyFactory.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptLmsPublicKey.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptLmsSignature.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptLmsUtil.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptMac.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptMlDsaKeyFactory.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptMlDsaPrivateKey.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptMlDsaPublicKey.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptMlDsaSignature.java \
    $KEM_SRC \
    src/main/java/com/wolfssl/provider/jce/WolfCryptMlKemKeyFactory.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptMlKemPrivateKey.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptMlKemPublicKey.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptMlKemUtil.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptMessageDigestMd5.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptMessageDigestSha.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptMessageDigestSha224.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptMessageDigestSha256.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptMessageDigestSha384.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptMessageDigestSha512.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptPBEKey.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptPKIXCertPathBuilder.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptPKIXCertPathValidator.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptPKIXRevocationChecker.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptProvider.java \
    src/main/java/com/wolfssl/provider/jce/WolfPQCJdkCompat.java \
    src/main/java/com/wolfssl/provider/jce/WolfPQCParameterSpec.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptPssParameters.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptRandom.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptSecretKey.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptSecretKeyFactory.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptSignature.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptUtil.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptXmssKeyFactory.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptXmssPublicKey.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptXmssSignature.java \
    src/main/java/com/wolfssl/provider/jce/WolfCryptXmssUtil.java \
    src/main/java/com/wolfssl/provider/jce/WolfSSLKeyStore.java \
    examples/filtered-providers/src/com/wolfssl/security/providers/FilteredSun.java \
    examples/filtered-providers/src/com/wolfssl/security/providers/FilteredSunEC.java \
    examples/filtered-providers/src/com/wolfssl/security/providers/FilteredSunRsaSign.java \
    examples/filtered-providers/src/com/wolfssl/security/providers/ProviderServiceCopier.java

RETVAL=$?

# remove compiled class files
rm -r ./com

# remove infer out directory (comment this out to inspect logs if needed)
if [ "$RETVAL" == '0' ] && [ "$KEEP" == 'no' ]; then
    rm -r ./infer-out
fi

if [ "$RETVAL" == '1' ] || [ "$RETVAL" == '2' ]; then
    # GitHub Actions expects return of 1 to mark step as failure
    exit 1
fi

exit 0

