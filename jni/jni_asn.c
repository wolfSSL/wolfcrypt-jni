/* jni_asn.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#elif !defined(__ANDROID__)
    #include <wolfssl/options.h>
#endif
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <com_wolfssl_wolfcrypt_Asn.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getDSAk
  (JNIEnv* env, jclass class)
{
    return DSAk;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getRSAk
  (JNIEnv* env, jclass class)
{
    return RSAk;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getRSAPSSk
  (JNIEnv* env, jclass class)
{
    return RSAPSSk;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getRSAESOAEPk
  (JNIEnv* env, jclass class)
{
    return RSAESOAEPk;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getECDSAk
  (JNIEnv* env, jclass class)
{
    return ECDSAk;
}

/* ML-DSA Key_Sum enum values:
 *   - Not present in native wolfSSL before 5.7.4, return 0 to indicate
 *     not available (Java callers treat 0 as unsupported).
 *   - wolfSSL 5.7.4 - 5.9.1 releases define ML_DSA_LEVEL2k/3k/5k as
 *     enum constants.
 *   - Newer wolfSSL renames these to ML_DSA_44k/65k/87k and keeps
 *     ML_DSA_LEVELxk only as legacy macro aliases, disabled by
 *     WOLFSSL_NO_DILITHIUM_LEGACY_NAMES and slated for removal. */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getML_1DSA_1LEVEL2k
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
#if (LIBWOLFSSL_VERSION_HEX < 0x05007004)
    return 0;
#elif defined(ML_DSA_LEVEL2k)
    /* legacy macro alias for ML_DSA_44k */
    return ML_DSA_LEVEL2k;
#elif defined(WOLFSSL_NO_DILITHIUM_LEGACY_NAMES) || \
      (LIBWOLFSSL_VERSION_HEX > 0x05009001)
    /* legacy names disabled or removed, use final FIPS 204 name */
    return ML_DSA_44k;
#else
    /* wolfSSL 5.7.4 - 5.9.1 enum constant */
    return ML_DSA_LEVEL2k;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getML_1DSA_1LEVEL3k
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
#if (LIBWOLFSSL_VERSION_HEX < 0x05007004)
    return 0;
#elif defined(ML_DSA_LEVEL3k)
    /* legacy macro alias for ML_DSA_65k */
    return ML_DSA_LEVEL3k;
#elif defined(WOLFSSL_NO_DILITHIUM_LEGACY_NAMES) || \
      (LIBWOLFSSL_VERSION_HEX > 0x05009001)
    /* legacy names disabled or removed, use final FIPS 204 name */
    return ML_DSA_65k;
#else
    /* wolfSSL 5.7.4 - 5.9.1 enum constant */
    return ML_DSA_LEVEL3k;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getML_1DSA_1LEVEL5k
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
#if (LIBWOLFSSL_VERSION_HEX < 0x05007004)
    return 0;
#elif defined(ML_DSA_LEVEL5k)
    /* legacy macro alias for ML_DSA_87k */
    return ML_DSA_LEVEL5k;
#elif defined(WOLFSSL_NO_DILITHIUM_LEGACY_NAMES) || \
      (LIBWOLFSSL_VERSION_HEX > 0x05009001)
    /* legacy names disabled or removed, use final FIPS 204 name */
    return ML_DSA_87k;
#else
    /* wolfSSL 5.7.4 - 5.9.1 enum constant */
    return ML_DSA_LEVEL5k;
#endif
}

/* SLH-DSA (FIPS 205) Key_Sum enum values from oid_sum.h, present when native
 * wolfSSL is built with SLH-DSA support. Return 0 (treated as unsupported by
 * Java callers) when SLH-DSA is not compiled in. */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getSLH_1DSA_1SHA2_1128Sk
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
#ifdef WOLFSSL_HAVE_SLHDSA
    return (jint)SLH_DSA_SHA2_128Sk;
#else
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getSLH_1DSA_1SHA2_1128Fk
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
#ifdef WOLFSSL_HAVE_SLHDSA
    return (jint)SLH_DSA_SHA2_128Fk;
#else
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getSLH_1DSA_1SHA2_1192Sk
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
#ifdef WOLFSSL_HAVE_SLHDSA
    return (jint)SLH_DSA_SHA2_192Sk;
#else
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getSLH_1DSA_1SHA2_1192Fk
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
#ifdef WOLFSSL_HAVE_SLHDSA
    return (jint)SLH_DSA_SHA2_192Fk;
#else
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getSLH_1DSA_1SHA2_1256Sk
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
#ifdef WOLFSSL_HAVE_SLHDSA
    return (jint)SLH_DSA_SHA2_256Sk;
#else
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getSLH_1DSA_1SHA2_1256Fk
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
#ifdef WOLFSSL_HAVE_SLHDSA
    return (jint)SLH_DSA_SHA2_256Fk;
#else
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getSLH_1DSA_1SHAKE_1128Sk
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
#ifdef WOLFSSL_HAVE_SLHDSA
    return (jint)SLH_DSA_SHAKE_128Sk;
#else
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getSLH_1DSA_1SHAKE_1128Fk
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
#ifdef WOLFSSL_HAVE_SLHDSA
    return (jint)SLH_DSA_SHAKE_128Fk;
#else
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getSLH_1DSA_1SHAKE_1192Sk
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
#ifdef WOLFSSL_HAVE_SLHDSA
    return (jint)SLH_DSA_SHAKE_192Sk;
#else
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getSLH_1DSA_1SHAKE_1192Fk
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
#ifdef WOLFSSL_HAVE_SLHDSA
    return (jint)SLH_DSA_SHAKE_192Fk;
#else
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getSLH_1DSA_1SHAKE_1256Sk
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
#ifdef WOLFSSL_HAVE_SLHDSA
    return (jint)SLH_DSA_SHAKE_256Sk;
#else
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getSLH_1DSA_1SHAKE_1256Fk
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
#ifdef WOLFSSL_HAVE_SLHDSA
    return (jint)SLH_DSA_SHAKE_256Fk;
#else
    return 0;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Asn_encodeSignature__Ljava_nio_ByteBuffer_2Ljava_nio_ByteBuffer_2JI(
    JNIEnv* env, jclass class, jobject encoded_object, jobject hash_object,
    jlong hashSize, jint hashOID)
{
    byte* encoded = getDirectBufferAddress(env, encoded_object);
    byte* hash = getDirectBufferAddress(env, hash_object);

    if (encoded == NULL || hash == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
    }
    else {
        setDirectBufferLimit(env, encoded_object,
            wc_EncodeSignature(encoded, hash, (word32)hashSize, hashOID));
    }
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Asn_encodeSignature___3B_3BJI(
    JNIEnv* env, jclass class, jbyteArray encoded_object,
    jbyteArray hash_object, jlong hashSize, jint hashOID)
{
    byte* encoded = getByteArray(env, encoded_object);
    byte* hash = getByteArray(env, hash_object);
    jlong ret = 0;

    if (encoded == NULL || hash == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_EncodeSignature(encoded, hash, (word32)hashSize, hashOID);
    }

    releaseByteArray(env, encoded_object, encoded, ret < 0);
    releaseByteArray(env, hash_object, hash, ret < 0);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getCTC_1HashOID(
    JNIEnv* env, jclass class, jint type)
{
    return wc_GetCTC_HashOID(type);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getPkcs8AlgoID
  (JNIEnv* env, jclass class, jbyteArray pkcs8Der)
{
#if !defined(NO_ASN) && !defined(NO_PWDBASED) && defined(HAVE_PKCS8)
    int ret = 0;
    word32 algoId = 0;
    byte* p8 = NULL;
    byte* p8Copy = NULL;
    word32 p8Len = 0;

    if (pkcs8Der != NULL) {
        p8 = (byte*)(*env)->GetByteArrayElements(env, pkcs8Der, NULL);
        p8Len = (*env)->GetArrayLength(env, pkcs8Der);
    }

    if (p8 == NULL || p8Len == 0) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        p8Copy = (byte*)XMALLOC(p8Len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (p8Copy == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        /* Copy array since ToTraditional modifies source buffer */
        XMEMSET(p8Copy, 0, p8Len);
        XMEMCPY(p8Copy, p8, p8Len);

        ret = ToTraditional_ex(p8Copy, p8Len, &algoId);
        if (ret > 0) {
            /* returns length of header, but not needed here */
            ret = 0;
        }
    }

    if (p8Copy != NULL) {
    #if (LIBWOLFSSL_VERSION_HEX >= 0x05008004) && \
        !defined(WOLFSSL_NO_FORCE_ZERO)
        wc_ForceZero(p8Copy, p8Len);
    #else
        XMEMSET(p8Copy, 0, p8Len);
    #endif
        XFREE(p8Copy, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (pkcs8Der != NULL) {
        (*env)->ReleaseByteArrayElements(env, pkcs8Der, (jbyte*)p8, JNI_ABORT);
    }

    if (ret == 0) {
        ret = (int)algoId;
    }
    else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    return (jint)ret;

#else
    (void)env;
    (void)class;
    (void)pkcs8Der;
    throwNotCompiledInException(env);
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getMD5h
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
    return MD5h;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getSHAh
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
    return SHAh;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getSHA224h
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
    return SHA224h;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getSHA256h
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
    return SHA256h;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getSHA384h
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
    return SHA384h;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getSHA512h
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
    return SHA512h;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getSHA3_1224h
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
    return SHA3_224h;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getSHA3_1256h
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
    return SHA3_256h;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getSHA3_1384h
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
    return SHA3_384h;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getSHA3_1512h
  (JNIEnv* env, jclass class)
{
    (void)env;
    (void)class;
    return SHA3_512h;
}

