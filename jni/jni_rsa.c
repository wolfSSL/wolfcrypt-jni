/* jni_rsa.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#include <stdint.h>

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#elif !defined(__ANDROID__)
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/misc.h>
#include <wolfssl/wolfcrypt/hash.h>

#include <com_wolfssl_wolfcrypt_Rsa.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

#if !defined(WC_NO_RNG) && defined(NO_OLD_RNGNAME)
    #define RNG WC_RNG
#endif

JNIEXPORT jlong JNICALL
Java_com_wolfssl_wolfcrypt_Rsa_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
#ifndef NO_RSA
    RsaKey* rsa = NULL;

    rsa = (RsaKey*)XMALLOC(sizeof(RsaKey), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (rsa == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate Rsa object");
    }
    else {
        XMEMSET(rsa, 0, sizeof(RsaKey));
    }

    LogStr("new Rsa() = %p\n", rsa);

    return (jlong)(uintptr_t)rsa;
#else
    throwNotCompiledInException(env);

    return (jlong)0;
#endif
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Rsa_getDefaultRsaExponent
  (JNIEnv *env, jclass jcl)
{
    (void)env;
    (void)jcl;

#ifndef NO_RSA
    return WC_RSA_EXPONENT;
#else
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Rsa_rsaMinSize
  (JNIEnv *env, jclass jcl)
{
    (void)env;
    (void)jcl;

    return (jint)RSA_MIN_SIZE;
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Rsa_MakeRsaKey(
    JNIEnv *env, jobject this, jint size, jlong e, jobject rng_object)
{
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    int ret = 0;
    RsaKey* key = NULL;
    RNG*    rng = NULL;

    key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    rng = (RNG*) getNativeStruct(env, rng_object);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    if (key == NULL || rng == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_MakeRsaKey(key, size, (long)e, rng);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MakeRsaKey(%d, %lu) = %d\n", size, e, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaPublicKeyDecodeRaw__Ljava_nio_ByteBuffer_2JLjava_nio_ByteBuffer_2J(
    JNIEnv* env, jobject this, jobject n_object, jlong nSize,
    jobject e_object, jlong eSize)
{
#ifndef NO_RSA
    int ret = 0;
    RsaKey* key = NULL;
    byte* n = NULL;
    byte* e = NULL;

    key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    n = getDirectBufferAddress(env, n_object);
    e = getDirectBufferAddress(env, e_object);

    if (key == NULL || n == NULL || e == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_RsaPublicKeyDecodeRaw(n, (long)nSize, e, (long)eSize, key);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_RsaPublicKeyDecodeRaw(n, nSz, e, eSz) = %d\n", ret);
    LogStr("n[%u]: [%p]\n", (word32)nSize, n);
    LogHex((byte*) n, 0, nSize);
    LogStr("e[%u]: [%p]\n", (word32)eSize, e);
    LogHex((byte*) e, 0, eSize);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaPublicKeyDecodeRaw___3BJ_3BJ(
    JNIEnv* env, jobject this, jbyteArray n_object, jlong nSize,
    jbyteArray e_object, jlong eSize)
{
#ifndef NO_RSA
    int ret  = 0;
    RsaKey* key = NULL;
    byte* n = NULL;
    byte* e = NULL;

    key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    n = getByteArray(env, n_object);
    e = getByteArray(env, e_object);

    if (key == NULL || n == NULL || e == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_RsaPublicKeyDecodeRaw(n, (long)nSize, e, (long)eSize, key);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_RsaPublicKeyDecodeRaw(n, nSz, e, eSz) = %d\n", ret);
    LogStr("n[%u]: [%p]\n", (word32)nSize, n);
    LogHex((byte*) n, 0, nSize);
    LogStr("e[%u]: [%p]\n", (word32)eSize, e);
    LogHex((byte*) e, 0, eSize);

    releaseByteArray(env, n_object, n, JNI_ABORT);
    releaseByteArray(env, e_object, e, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Rsa_RsaFlattenPublicKey__Ljava_nio_ByteBuffer_2Ljava_nio_ByteBuffer_2(
    JNIEnv* env, jobject this, jobject n_object, jobject e_object)
{
#ifndef NO_RSA
    int ret = 0;
    RsaKey* key = NULL;
    byte* n = NULL;
    byte* e = NULL;
    word32 nSize = 0, eSize = 0;

    key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    n = getDirectBufferAddress(env, n_object);
    e = getDirectBufferAddress(env, e_object);
    nSize = n ? getDirectBufferLimit(env, n_object) : 0;
    eSize = e ? getDirectBufferLimit(env, e_object) : 0;

    if (key == NULL || n == NULL || e == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_RsaFlattenPublicKey(key, e, &eSize, n, &nSize);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    } else {

        setDirectBufferLimit(env, n_object, nSize);
        if ((*env)->ExceptionOccurred(env)) {
            return;
        }

        setDirectBufferLimit(env, e_object, eSize);
        if ((*env)->ExceptionOccurred(env)) {
            return;
        }
    }

    LogStr("wc_RsaFlattenPublicKey(key, e, eSz, n, nSz) = %d\n", ret);
    LogStr("n[%u]: [%p]\n", (word32)nSize, n);
    LogHex((byte*) n, 0, nSize);
    LogStr("e[%u]: [%p]\n", (word32)eSize, e);
    LogHex((byte*) e, 0, eSize);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Rsa_RsaFlattenPublicKey___3B_3J_3B_3J(
    JNIEnv* env, jobject this, jbyteArray n_object, jlongArray nSize,
    jbyteArray e_object, jlongArray eSize)
{
#ifndef NO_RSA
    int ret = 0;
    RsaKey* key = NULL;
    byte* n = NULL;
    byte* e = NULL;
    jlong nSz;
    jlong eSz;

    key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    n = getByteArray(env, n_object);
    e = getByteArray(env, e_object);

    (*env)->GetLongArrayRegion(env, nSize, 0, 1, &nSz);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    (*env)->GetLongArrayRegion(env, eSize, 0, 1, &eSz);
    if ((*env)->ExceptionOccurred(env)) {
        releaseByteArray(env, n_object, n, ret);
        return;
    }

    if (key == NULL || n == NULL || e == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_RsaFlattenPublicKey(key, e, (word32*) &eSz, n, (word32*) &nSz);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    } else {

        (*env)->SetLongArrayRegion(env, nSize, 0, 1, &nSz);
        if ((*env)->ExceptionOccurred(env)) {
            releaseByteArray(env, n_object, n, ret);
            releaseByteArray(env, e_object, e, ret);
            return;
        }

        (*env)->SetLongArrayRegion(env, eSize, 0, 1, &eSz);
        if ((*env)->ExceptionOccurred(env)) {
            releaseByteArray(env, n_object, n, ret);
            releaseByteArray(env, e_object, e, ret);
            return;
        }
    }

    LogStr("RsaFlattenPublicKey(key, e, eSz, n, nSz) = %d\n", ret);
    LogStr("n[%u]: [%p]\n", (word32)nSz, n);
    LogHex((byte*) n, 0, nSz);
    LogStr("e[%u]: [%p]\n", (word32)eSz, e);
    LogHex((byte*) e, 0, eSz);

    releaseByteArray(env, n_object, n, ret);
    releaseByteArray(env, e_object, e, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaKeyToDer
  (JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;
#if !defined(NO_RSA) && (defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA))
    int ret = 0;
    RsaKey* key = NULL;
    byte* output = NULL;
    word32 outputSz = 0;
    word32 outputBufSz = 0;

    key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0 && key == NULL) {
        ret = BAD_FUNC_ARG;
    }

    /* Get length of DER encoded RSA private key */
    if (ret == 0) {
        ret = wc_RsaKeyToDer(key, NULL, 0);
        if (ret > 0) {
            outputSz = ret;
            outputBufSz = outputSz;
            ret = 0;
        }
    }

    /* Allocate temp buffer to hold DER encoded key */
    if (ret == 0) {
        output = (byte*)XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (output == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        XMEMSET(output, 0, outputSz);

        ret = wc_RsaKeyToDer(key, output, outputSz);
        if (ret > 0) {
            outputSz = ret;
            ret = 0;
        }
    }

    if (ret == 0) {
        result = (*env)->NewByteArray(env, outputSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, outputSz,
                                       (const jbyte*) output);
        } else {
            throwWolfCryptException(env, "Failed NewByteArray() for DER key");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_RsaKeyToDer() = %d\n", ret);
    LogStr("output[%u]: [%p]\n", outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    if (output != NULL) {
        XMEMSET(output, 0, outputBufSz);
        XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaKeyToPublicDer
  (JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;
#ifndef NO_RSA
    int ret = 0;
    RsaKey* key = NULL;
    byte* output = NULL;
    word32 outputSz = 0;
    word32 outputBufSz = 0;

    key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0 && key == NULL) {
        ret = BAD_FUNC_ARG;
    }

    /* Get length of DER encoded RSA private key */
    if (ret == 0) {
        ret = wc_RsaKeyToPublicDer(key, NULL, 0);
        if (ret > 0) {
            outputSz = ret;
            outputBufSz = outputSz;
            ret = 0;
        }
    }

    /* Allocate temp buffer to hold DER encoded key */
    if (ret == 0) {
        output = (byte*)XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (output == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        XMEMSET(output, 0, outputSz);

        ret = wc_RsaKeyToPublicDer(key, output, outputSz);
        if (ret > 0) {
            outputSz = ret;
            ret = 0;
        }
    }

    if (ret == 0) {
        result = (*env)->NewByteArray(env, outputSz);
        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, outputSz,
                                       (const jbyte*) output);
        } else {
            throwWolfCryptException(env,
                "Failed NewByteArray() for DER public key");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_RsaKeyToPublicDer() = %d\n", ret);
    LogStr("output[%u]: [%p]\n", outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    if (output != NULL) {
        XMEMSET(output, 0, outputBufSz);
        XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaPrivateKeyToPkcs8
  (JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;
#ifndef NO_RSA
    int ret = 0;
    RsaKey* key  = NULL;
    byte* derKey = NULL;
    byte* pkcs8  = NULL;
    word32 derKeySz = 0;
    word32 pkcs8Sz = 0;

    /* Keep track of malloc sizes for memset cleanup */
    word32 derKeyBufSz = 0;
    word32 pkcs8BufSz = 0;

    int algoID = RSAk;
    word32 oidSz = 0;
    const byte* curveOID = NULL;

    key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0 && key == NULL) {
        ret = BAD_FUNC_ARG;
    }

    /* Get length of DER encoded RSA private key */
    if (ret == 0) {
        ret = wc_RsaKeyToDer(key, NULL, 0);
        if (ret > 0) {
            derKeySz = ret;
            ret = 0;
        }
    }

    /* Get PKCS#8 output size, into pkcs8Sz */
    if (ret == 0) {
        ret = wc_CreatePKCS8Key(NULL, &pkcs8Sz, derKey, derKeySz, algoID,
                                curveOID, oidSz);
        if (ret == LENGTH_ONLY_E) {
            pkcs8 = (byte*)XMALLOC(pkcs8Sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (pkcs8 == NULL) {
                ret = MEMORY_E;
            }
            else {
                XMEMSET(pkcs8, 0, pkcs8Sz);
                pkcs8BufSz = pkcs8Sz;
                ret = 0;
            }
        }
    }

    if (ret == 0) {
        /* Allocate temp buffer to hold DER encoded key */
        derKey = (byte*)XMALLOC(derKeySz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (derKey == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(derKey, 0, derKeySz);
            derKeyBufSz = derKeySz;
        }
    }

    /* Get DER encoded RSA private key */
    if (ret == 0) {
        ret = wc_RsaKeyToDer(key, derKey, derKeySz);
        if (ret > 0) {
            derKeySz = ret;
            ret = 0;
        }
    }

    /* Create PKCS#8 from DER key */
    if (ret == 0) {
        ret = wc_CreatePKCS8Key(pkcs8, &pkcs8Sz, derKey, derKeySz,
                                algoID, curveOID, oidSz);
        if (ret > 0) {
            pkcs8Sz = ret;
            ret = 0;
        }
    }

    /* Create new Java byte[] and return */
    if (ret == 0) {
        result = (*env)->NewByteArray(env, pkcs8Sz);
        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, pkcs8Sz,
                                       (const jbyte*) pkcs8);
        }
    }

    if (derKey != NULL) {
        XMEMSET(derKey, 0, derKeyBufSz);
        XFREE(derKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (pkcs8 != NULL) {
        XMEMSET(pkcs8, 0, pkcs8BufSz);
        XFREE(pkcs8,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (ret < 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }
#else
    throwNotCompiledInException(env);
#endif /* !NO_RSA */
    return result;
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Rsa_wc_1InitRsaKey(
    JNIEnv* env, jobject this)
{
#ifndef NO_RSA
    int ret = 0;
    RsaKey* key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_InitRsaKey(key, NULL);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_InitRsaKey(key) = %d\n", ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Rsa_wc_1FreeRsaKey(
    JNIEnv* env, jobject this)
{
#ifndef NO_RSA
    int ret = 0;
    RsaKey* key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_FreeRsaKey(key);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_FreeRsaKey(key) = %d\n", ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jboolean JNICALL
Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaSetRNG(
    JNIEnv* env, jobject this, jobject rng_object)
{
#ifndef NO_RSA

#ifdef WC_RSA_BLINDING
    int ret = 0;
    RsaKey* key = NULL;
    RNG*    rng = NULL;

    key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return JNI_FALSE;
    }

    rng = (RNG*) getNativeStruct(env, rng_object);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return JNI_FALSE;
    }

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_RsaSetRNG(key, rng);
    }

    LogStr("wc_RsaSetRNG(key, rng) = %d\n", ret);

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }
    else {
        return JNI_TRUE;
    }
#endif

#else
    throwNotCompiledInException(env);
#endif

    return JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaPrivateKeyDecode(
    JNIEnv* env, jobject this, jbyteArray key_object)
{
#ifndef NO_RSA
    int ret = 0;
    RsaKey* key = NULL;
    byte* k = NULL;
    word32 kSz = 0, index = 0;

    key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    k   = getByteArray(env, key_object);
    kSz = getByteArrayLength(env, key_object);

    if (key == NULL || k == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_RsaPrivateKeyDecode(k, &index, key, kSz);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    releaseByteArray(env, key_object, k, JNI_ABORT);

    LogStr("wc_RsaPrivateKeyDecode(k, kSize, key) = %d\n", ret);
    LogStr("key[%u]: [%p]\n", (word32)kSz, k);
    LogHex((byte*) k, 0, kSz);

#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaPrivateKeyDecodePKCS8
  (JNIEnv* env, jobject this, jbyteArray key_object)
{
#ifndef NO_RSA
    int ret = 0;
    int length = 0;
    RsaKey* key = NULL;
    byte* k = NULL;
    word32 kSz = 0, offset = 0;

    key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    k   = getByteArray(env, key_object);
    kSz = getByteArrayLength(env, key_object);

    if (key == NULL || k == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        length = wc_GetPkcs8TraditionalOffset(k, &offset, kSz);
        if (length < 0) {
            ret = length;
        }
    }

    if (ret == 0) {
        ret = wc_RsaPrivateKeyDecode(k, &offset, key, kSz);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_RsaPrivateKeyDecodePKCS8(k, kSize, key) = %d\n", ret);
    LogStr("key[%u]: [%p]\n", (word32)kSz, k);
    LogHex((byte*) k, 0, kSz);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaPublicKeyDecode
  (JNIEnv* env, jobject this, jbyteArray key_object)
{
#ifndef NO_RSA
    int ret = 0;
    RsaKey* key = NULL;
    byte* k = NULL;
    word32 kSz = 0, index = 0;

    key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    k   = getByteArray(env, key_object);
    kSz = getByteArrayLength(env, key_object);

    if (key == NULL || k == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_RsaPublicKeyDecode(k, &index, key, kSz);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_RsaPublicKeyDecode(k, kSize, key) = %d\n", ret);
    LogStr("key[%u]: [%p]\n", (word32)kSz, k);
    LogHex((byte*) k, 0, kSz);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaEncryptSize
  (JNIEnv* env, jobject this)
{
    jint ret = 0;

#ifndef NO_RSA
    RsaKey* key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return 0;
    }

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_RsaEncryptSize(key);
    }

    if (ret < 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_RsaEncryptSize(key=%p) = %d\n", key, ret);
#else
    throwNotCompiledInException(env);
#endif

    return ret;
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaPublicEncrypt(
    JNIEnv* env, jobject this, jbyteArray plaintext_object, jobject rng_object)
{
    jbyteArray result = NULL;

#ifndef NO_RSA
    int ret = 0;
    RsaKey* key = NULL;
    RNG*    rng = NULL;
    byte* plaintext = NULL;
    byte* output = NULL;
    word32 size = 0, outputSz = 0;

    key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    rng = (RNG*) getNativeStruct(env, rng_object);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    plaintext = getByteArray(env, plaintext_object);
    size = getByteArrayLength(env, plaintext_object);

    if (key == NULL || rng == NULL || plaintext == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        outputSz = wc_RsaEncryptSize(key);
        if (outputSz < 0) {
            ret = outputSz;
        }
    }

    if (ret == 0) {
        output = (byte*)XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (output == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        XMEMSET(output, 0, outputSz);

        ret = wc_RsaPublicEncrypt(plaintext, size, output, outputSz, key, rng);
        if (ret > 0) {
            outputSz = ret;
            ret = 0;
        }
    }

    if (ret == 0) {
        result = (*env)->NewByteArray(env, outputSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, outputSz,
                                       (const jbyte*) output);
        } else {
            throwWolfCryptException(env, "Failed to create ciphertext array");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_RsaPublicEncrypt(in, inSz, out, outSz, key=, rng) = %d\n", ret);
    LogStr("output[%u]: [%p]\n", outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    if (output != NULL) {
        XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    releaseByteArray(env, plaintext_object, plaintext, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaPrivateDecrypt(
    JNIEnv* env, jobject this, jbyteArray ciphertext_object)
{
    jbyteArray result = NULL;

#ifndef NO_RSA
    int ret = 0;
    RsaKey* key = NULL;
    byte* ciphertext = NULL;
    byte* output = NULL;
    word32 size = 0, outputSz = 0;

    key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    ciphertext = getByteArray(env, ciphertext_object);
    size = getByteArrayLength(env, ciphertext_object);

    if (key == NULL || ciphertext == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        outputSz = wc_RsaEncryptSize(key);
        if (outputSz < 0) {
            ret = outputSz;
        }
    }

    if (ret == 0) {
        output = (byte*)XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (output == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        XMEMSET(output, 0, outputSz);

        ret = wc_RsaPrivateDecrypt(ciphertext, size, output, outputSz, key);
        if (ret > 0) {
            outputSz = ret;
            ret = 0;
        }
    }

    if (ret == 0) {
        result = (*env)->NewByteArray(env, outputSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, outputSz,
                                       (const jbyte*) output);
        } else {
            throwWolfCryptException(env, "Failed to create plaintext array");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_RsaPrivateDecrypt(in, inSz, out, outSz, key) = %d\n", ret);
    LogStr("output[%u]: [%p]\n", outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    if (output != NULL) {
        XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    releaseByteArray(env, ciphertext_object, ciphertext, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaSSL_1Sign(
    JNIEnv* env, jobject this, jbyteArray data_object, jobject rng_object)
{
    jbyteArray result = NULL;

#ifndef NO_RSA
    int ret = 0;
    RsaKey* key  = NULL;
    RNG*  rng    = NULL;
    byte* data   = NULL;
    byte* output = NULL;
    word32 size = 0, outputSz = 0;

    key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    rng = (RNG*) getNativeStruct(env, rng_object);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    data = getByteArray(env, data_object);
    size = getByteArrayLength(env, data_object);

    if (key == NULL || rng == NULL || data == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        outputSz = wc_RsaEncryptSize(key);
        if (outputSz < 0) {
            ret = outputSz;
        }
    }

    if (ret == 0) {
        output = (byte*)XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (output == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        XMEMSET(output, 0, outputSz);

        ret = wc_RsaSSL_Sign(data, size, output, outputSz, key, rng);
        if (ret > 0) {
            outputSz = ret;
            ret = 0;
        }
    }

    if (ret == 0) {
        result = (*env)->NewByteArray(env, outputSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, outputSz,
                                       (const jbyte*) output);
        } else {
            throwWolfCryptException(env,
                "Failed to create new signature array");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_RsaSSL_Sign(in, inSz, out, outSz, key, rng) = %d\n", ret);
    LogStr("output[%u]: [%p]\n", outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    if (output != NULL) {
        XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    releaseByteArray(env, data_object, data, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaSSL_1Verify(
    JNIEnv* env, jobject this, jbyteArray signature_object)
{
    jbyteArray result = NULL;
#ifndef NO_RSA
    int ret = 0;
    RsaKey* key     = NULL;
    byte* signature = NULL;
    byte* output    = NULL;
    word32 size = 0, outputSz = 0;

    key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    signature = getByteArray(env, signature_object);
    size = getByteArrayLength(env, signature_object);

    if (key == NULL || signature == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        outputSz = wc_RsaEncryptSize(key);
        if (outputSz < 0) {
            ret = outputSz;
        }
    }

    if (ret == 0) {
        output = (byte*)XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (output == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        XMEMSET(output, 0, outputSz);

        ret = wc_RsaSSL_Verify(signature, size, output, outputSz, key);
        if (ret > 0) {
            outputSz = ret;
            ret = 0;
        }
    }

    if (ret == 0) {
        result = (*env)->NewByteArray(env, outputSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, outputSz,
                                       (const jbyte*) output);
        } else {
            throwWolfCryptException(env, "Failed to create new verify array");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_RsaSSL_Verify(in, inSz, out, outSz, key) = %d\n", ret);
    LogStr("output[%u]: [%p]\n", outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    if (output != NULL) {
        XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    releaseByteArray(env, signature_object, signature, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaPSS_1Sign(
    JNIEnv* env, jobject this, jbyteArray data_object, jlong hashType,
    jint mgf, jint saltLen, jobject rng_object)
{
#if !defined(NO_RSA) && defined(WC_RSA_PSS)
    int ret = 0;
    RsaKey* key = NULL;
    RNG*    rng = NULL;
    byte*   data = NULL;
    byte*   signature = NULL;
    word32  dataSz = 0;
    word32  signatureSz = 0;
    jbyteArray result = NULL;

    /* get RsaKey pointer from Java object */
    key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    /* get RNG pointer from Java object */
    rng = (RNG*) getNativeStruct(env, rng_object);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    /* get data to sign */
    data = getByteArray(env, data_object);
    dataSz = getByteArrayLength(env, data_object);

    /* validate parameters */
    if (key == NULL || rng == NULL || data == NULL || dataSz == 0) {
        LogStr("Parameter validation failed: key=%p, rng=%p, data=%p, "
               "dataSz=%d\n", key, rng, data, dataSz);
        ret = BAD_FUNC_ARG;
    }

    /* get signature size */
    if (ret == 0) {
        signatureSz = wc_RsaEncryptSize(key);
        if (signatureSz <= 0) {
            ret = signatureSz;
        }
    }

    if (ret == 0) {
        signature = (byte*)XMALLOC(signatureSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (signature == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        XMEMSET(signature, 0, signatureSz);

        LogStr("About to call wc_RsaPSS_Sign_ex: data=%p, dataSz=%d, "
                "signature=%p, signatureSz=%d, hashType=%ld, mgf=%d, "
                "saltLen=%d, key=%p, rng=%p\n", data, dataSz, signature,
                signatureSz, hashType, mgf, saltLen, key, rng);

        ret = wc_RsaPSS_Sign_ex(data, dataSz, signature, signatureSz,
            (enum wc_HashType)hashType, mgf, saltLen, key, rng);
        if (ret > 0) {
            signatureSz = ret;
            ret = 0;
        }
    }

    if (ret == 0) {
        result = (*env)->NewByteArray(env, signatureSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, signatureSz,
                                       (const jbyte*) signature);
        } else {
            throwWolfCryptException(env,
                "Failed to create new signature array");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_RsaPSS_Sign_ex(data, dataSz, sig, sigSz, hash, mgf=%d, "
           "saltLen, key, rng) = %d\n", mgf, ret);

    if (signature != NULL) {
        XFREE(signature, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (data != NULL) {
        releaseByteArray(env, data_object, data, JNI_ABORT);
    }
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jboolean JNICALL
Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaPSS_1Verify(
    JNIEnv* env, jobject this, jbyteArray signature_object,
    jbyteArray data_object, jlong hashType, jint mgf, jint saltLen)
{
#if !defined(NO_RSA) && defined(WC_RSA_PSS)
    int ret = 0;
    RsaKey* key = NULL;
    byte*   signature = NULL;
    byte*   data = NULL;
    byte*   output = NULL;
    word32  signatureSz = 0;
    word32  dataSz = 0;
    word32  outputSz = 0;
    jboolean result = JNI_FALSE;

    /* get RsaKey pointer from Java object */
    key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return JNI_FALSE;
    }

    /* get signature and data */
    signature = getByteArray(env, signature_object);
    signatureSz = getByteArrayLength(env, signature_object);
    data = getByteArray(env, data_object);
    dataSz = getByteArrayLength(env, data_object);

    /* validate parameters */
    if (key == NULL || signature == NULL || signatureSz == 0 ||
        data == NULL || dataSz == 0) {
        ret = BAD_FUNC_ARG;
    }

    /* get output buffer size */
    if (ret == 0) {
        outputSz = wc_RsaEncryptSize(key);
        if (outputSz <= 0) {
            ret = outputSz;
        }
    }

    if (ret == 0) {
        output = (byte*)XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (output == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        XMEMSET(output, 0, outputSz);

        ret = wc_RsaPSS_Verify_ex(signature, signatureSz, output, outputSz,
                                  (enum wc_HashType)hashType, mgf,
                                  saltLen, key);
        if (ret > 0) {
            /* Now verify the PSS padding with the provided data */
            ret = wc_RsaPSS_CheckPadding_ex(data, dataSz, output, ret,
                                            (enum wc_HashType)hashType,
                                            saltLen, 0);
            if (ret == 0) {
                result = JNI_TRUE;
            }
        } else if (ret < 0) {
            throwWolfCryptExceptionFromError(env, ret);
        }
    }

    if (ret != 0 && ret != RSA_BUFFER_E) {
        LogStr("wc_RsaPSS_Verify_ex failed with error: %d\n", ret);
    }

    LogStr("wc_RsaPSS_Verify_ex(sig, sigSz, out, outSz, hash, mgf, "
           "saltLen, key) = %d\n", ret);

    if (output != NULL) {
        XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (signature != NULL) {
        releaseByteArray(env, signature_object, signature, JNI_ABORT);
    }
    if (data != NULL) {
        releaseByteArray(env, data_object, data, JNI_ABORT);
    }
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jboolean JNICALL
Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaPSS_1VerifyInline(
    JNIEnv* env, jobject this, jbyteArray signatureAndData_object,
    jlong hashType, jint mgf, jint saltLen)
{
#if !defined(NO_RSA) && defined(WC_RSA_PSS)
    int ret = 0;
    RsaKey* key = NULL;
    byte*   signatureAndData = NULL;
    byte*   output = NULL;
    word32  signatureAndDataSz = 0;
    jboolean result = JNI_FALSE;

    /* get RsaKey pointer from Java object */
    key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return JNI_FALSE;
    }

    /* get signature and data */
    signatureAndData = getByteArray(env, signatureAndData_object);
    signatureAndDataSz = getByteArrayLength(env, signatureAndData_object);

    /* validate parameters */
    if (key == NULL || signatureAndData == NULL || signatureAndDataSz == 0) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = wc_RsaPSS_VerifyInline_ex(signatureAndData, signatureAndDataSz,
            &output, (enum wc_HashType)hashType, mgf, saltLen, key);
    }
    if (ret > 0) {
        result = JNI_TRUE;
    }

    LogStr("wc_RsaPSS_VerifyInline_ex(sig, sigSz, out, hash, mgf, "
           "saltLen, key) = %d\n", ret);

    if (signatureAndData != NULL) {
        releaseByteArray(env, signatureAndData_object, signatureAndData,
                         JNI_ABORT);
    }
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jboolean JNICALL
Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaPSS_1VerifyCheck(
    JNIEnv* env, jobject this, jbyteArray signature_object,
    jbyteArray data_object, jbyteArray digest_object, jlong hashType,
    jint mgf, jint saltLen)
{
#if !defined(NO_RSA) && defined(WC_RSA_PSS)
    int ret = 0;
    RsaKey* key = NULL;
    byte*   signature = NULL;
    byte*   data = NULL;
    byte*   digest = NULL;
    word32  signatureSz = 0;
    word32  dataSz = 0;
    word32  digestSz = 0;
    jboolean result = JNI_FALSE;

    /* get RsaKey pointer from Java object */
    key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return JNI_FALSE;
    }

    /* get signature, data, and digest */
    signature = getByteArray(env, signature_object);
    signatureSz = getByteArrayLength(env, signature_object);
    data = getByteArray(env, data_object);
    dataSz = getByteArrayLength(env, data_object);
    digest = getByteArray(env, digest_object);
    digestSz = getByteArrayLength(env, digest_object);

    /* validate parameters */
    if (key == NULL || signature == NULL || signatureSz == 0 ||
        data == NULL || dataSz == 0 || digest == NULL || digestSz == 0) {
        ret = BAD_FUNC_ARG;
    }

    /* get output buffer for decrypted signature */
    byte* output = NULL;
    word32 outputSz = 0;

    if (ret == 0) {
        outputSz = wc_RsaEncryptSize(key);
        if (outputSz <= 0) {
            ret = outputSz;
        }
    }

    if (ret == 0) {
        output = (byte*)XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (output == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        XMEMSET(output, 0, outputSz);

        ret = wc_RsaPSS_VerifyCheck(signature, signatureSz, output, outputSz,
            digest, digestSz, (enum wc_HashType)hashType, mgf, key);
    }
    if (ret > 0) {
        result = JNI_TRUE;
    }

    LogStr("wc_RsaPSS_VerifyCheck(sig, sigSz, out, outSz, digest, "
           "digestSz, hash, mgf, key) = %d\n", ret);

    if (output != NULL) {
        XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (signature != NULL) {
        releaseByteArray(env, signature_object, signature, JNI_ABORT);
    }
    if (data != NULL) {
        releaseByteArray(env, data_object, data, JNI_ABORT);
    }
    if (digest != NULL) {
        releaseByteArray(env, digest_object, digest, JNI_ABORT);
    }
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jboolean JNICALL
Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaPSS_1CheckPadding(
    JNIEnv* env, jobject this, jbyteArray signature_object,
    jbyteArray digest_object, jint hashType, jint mgf, jint saltLen)
{
#if !defined(NO_RSA) && defined(WC_RSA_PSS)
    int ret = 0;
    RsaKey* key = NULL;
    byte*   signature = NULL;
    byte*   digest = NULL;
    byte*   pssData = NULL;
    word32  signatureSz = 0;
    word32  digestSz = 0;
    word32  pssDataSz = 0;
    jboolean result = JNI_FALSE;

    /* get RsaKey pointer from Java object */
    key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return JNI_FALSE;
    }

    /* get signature and digest */
    signature = getByteArray(env, signature_object);
    signatureSz = getByteArrayLength(env, signature_object);
    digest = getByteArray(env, digest_object);
    digestSz = getByteArrayLength(env, digest_object);

    /* validate parameters */
    if (key == NULL || signature == NULL || signatureSz == 0 ||
        digest == NULL || digestSz == 0) {
        ret = BAD_FUNC_ARG;
    }

    /* get PSS data buffer size */
    if (ret == 0) {
        pssDataSz = wc_RsaEncryptSize(key);
        if (pssDataSz <= 0) {
            ret = pssDataSz;
        }
    }

    if (ret == 0) {
        pssData = (byte*)XMALLOC(pssDataSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (pssData == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        XMEMSET(pssData, 0, pssDataSz);

        /* First decrypt the signature to get PSS padded data */
        ret = wc_RsaPSS_Verify_ex(signature, signatureSz, pssData, pssDataSz,
            (enum wc_HashType)hashType, mgf, saltLen, key);

        if (ret > 0) {
            pssDataSz = ret;
            /* Now check the PSS padding against the digest */
            ret = wc_RsaPSS_CheckPadding_ex(digest, digestSz, pssData,
                pssDataSz, (enum wc_HashType)hashType, saltLen, 0);
        }
    }
    if (ret == 0) {
        result = JNI_TRUE;
    }

    LogStr("wc_RsaPSS_CheckPadding_ex(digest, digestSz, pss, pssSz, "
           "hash, saltLen, bits) = %d\n", ret);

    if (pssData != NULL) {
        XFREE(pssData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (signature != NULL) {
        releaseByteArray(env, signature_object, signature, JNI_ABORT);
    }
    if (digest != NULL) {
        releaseByteArray(env, digest_object, digest, JNI_ABORT);
    }
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaExportCrtKey(
    JNIEnv* env, jobject this, jbyteArray n_object, jlongArray nSize,
    jbyteArray e_object, jlongArray eSize, jbyteArray d_object,
    jlongArray dSize, jbyteArray p_object, jlongArray pSize,
    jbyteArray q_object, jlongArray qSize, jbyteArray dP_object,
    jlongArray dPSize, jbyteArray dQ_object, jlongArray dQSize,
    jbyteArray u_object, jlongArray uSize)
{
#if !defined(NO_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY) && \
    (defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || \
     !defined(RSA_LOW_MEM))
    int ret = 0;
    RsaKey* key = NULL;
    byte* n = NULL;
    byte* e = NULL;
    byte* d = NULL;
    byte* p = NULL;
    byte* q = NULL;
    byte* dP = NULL;
    byte* dQ = NULL;
    byte* u = NULL;
    jlong nSz = 0, eSz = 0, dSz = 0, pSz = 0;
    jlong qSz = 0, dPSz = 0, dQSz = 0, uSz = 0;

    key = (RsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    /* Get size array values */
    n = getByteArray(env, n_object);
    (*env)->GetLongArrayRegion(env, nSize, 0, 1, &nSz);
    if ((*env)->ExceptionOccurred(env)) {
        releaseByteArray(env, n_object, n, ret);
        return;
    }

    e = getByteArray(env, e_object);
    (*env)->GetLongArrayRegion(env, eSize, 0, 1, &eSz);
    if ((*env)->ExceptionOccurred(env)) {
        releaseByteArray(env, n_object, n, ret);
        releaseByteArray(env, e_object, e, ret);
        return;
    }

    d = getByteArray(env, d_object);
    (*env)->GetLongArrayRegion(env, dSize, 0, 1, &dSz);
    if ((*env)->ExceptionOccurred(env)) {
        releaseByteArray(env, n_object, n, ret);
        releaseByteArray(env, e_object, e, ret);
        releaseByteArray(env, d_object, d, ret);
        return;
    }

    p = getByteArray(env, p_object);
    (*env)->GetLongArrayRegion(env, pSize, 0, 1, &pSz);
    if ((*env)->ExceptionOccurred(env)) {
        releaseByteArray(env, n_object, n, ret);
        releaseByteArray(env, e_object, e, ret);
        releaseByteArray(env, d_object, d, ret);
        releaseByteArray(env, p_object, p, ret);
        return;
    }

    q = getByteArray(env, q_object);
    (*env)->GetLongArrayRegion(env, qSize, 0, 1, &qSz);
    if ((*env)->ExceptionOccurred(env)) {
        releaseByteArray(env, n_object, n, ret);
        releaseByteArray(env, e_object, e, ret);
        releaseByteArray(env, d_object, d, ret);
        releaseByteArray(env, p_object, p, ret);
        releaseByteArray(env, q_object, q, ret);
        return;
    }

    dP = getByteArray(env, dP_object);
    (*env)->GetLongArrayRegion(env, dPSize, 0, 1, &dPSz);
    if ((*env)->ExceptionOccurred(env)) {
        releaseByteArray(env, n_object, n, ret);
        releaseByteArray(env, e_object, e, ret);
        releaseByteArray(env, d_object, d, ret);
        releaseByteArray(env, p_object, p, ret);
        releaseByteArray(env, q_object, q, ret);
        releaseByteArray(env, dP_object, dP, ret);
        return;
    }

    dQ = getByteArray(env, dQ_object);
    (*env)->GetLongArrayRegion(env, dQSize, 0, 1, &dQSz);
    if ((*env)->ExceptionOccurred(env)) {
        releaseByteArray(env, n_object, n, ret);
        releaseByteArray(env, e_object, e, ret);
        releaseByteArray(env, d_object, d, ret);
        releaseByteArray(env, p_object, p, ret);
        releaseByteArray(env, q_object, q, ret);
        releaseByteArray(env, dP_object, dP, ret);
        releaseByteArray(env, dQ_object, dQ, ret);
        return;
    }

    u = getByteArray(env, u_object);
    (*env)->GetLongArrayRegion(env, uSize, 0, 1, &uSz);
    if ((*env)->ExceptionOccurred(env)) {
        releaseByteArray(env, n_object, n, ret);
        releaseByteArray(env, e_object, e, ret);
        releaseByteArray(env, d_object, d, ret);
        releaseByteArray(env, p_object, p, ret);
        releaseByteArray(env, q_object, q, ret);
        releaseByteArray(env, dP_object, dP, ret);
        releaseByteArray(env, dQ_object, dQ, ret);
        releaseByteArray(env, u_object, u, ret);
        return;
    }

    /* Validate inputs */
    if (key == NULL || n == NULL || e == NULL || d == NULL || p == NULL ||
        q == NULL || dP == NULL || dQ == NULL || u == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Export e, n, d, p, q using wc_RsaExportKey() */
        PRIVATE_KEY_UNLOCK();
        ret = wc_RsaExportKey(key, e, (word32*)&eSz, n, (word32*)&nSz,
            d, (word32*)&dSz, p, (word32*)&pSz, q, (word32*)&qSz);

        /* Export CRT parameters dP, dQ, u */
#ifdef WOLFSSL_PUBLIC_MP
        if (ret == 0) {
            dPSz = (jlong)mp_unsigned_bin_size(&key->dP);
            if ((dPSz > 0) &&
                (dPSz <= (jlong)(*env)->GetArrayLength(env, dP_object))) {
                ret = mp_to_unsigned_bin(&key->dP, dP);
            }
            else {
                ret = RSA_BUFFER_E;
            }
        }
        if (ret == 0) {
            dQSz = (jlong)mp_unsigned_bin_size(&key->dQ);
            if ((dQSz > 0) &&
                (dQSz <= (jlong)(*env)->GetArrayLength(env, dQ_object))) {
                ret = mp_to_unsigned_bin(&key->dQ, dQ);
            }
            else {
                ret = RSA_BUFFER_E;
            }
        }
        if (ret == 0) {
            uSz = (jlong)mp_unsigned_bin_size(&key->u);
            if ((uSz > 0) &&
                (uSz <= (jlong)(*env)->GetArrayLength(env, u_object))) {
                ret = mp_to_unsigned_bin(&key->u, u);
            }
            else {
                ret = RSA_BUFFER_E;
            }
        }
#else
        (void)dP;
        (void)dQ;
        (void)u;
        (void)dP_object;
        (void)dQ_object;
        (void)u_object;
        if (ret == 0) {
            ret = NOT_COMPILED_IN;
        }
#endif
        PRIVATE_KEY_LOCK();
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }
    else {
        /* Set updated size values. If any SetLongArrayRegion call fails,
         * continue to next call anyway since we need to release all arrays. */
        (*env)->SetLongArrayRegion(env, nSize, 0, 1, &nSz);
        (*env)->SetLongArrayRegion(env, eSize, 0, 1, &eSz);
        (*env)->SetLongArrayRegion(env, dSize, 0, 1, &dSz);
        (*env)->SetLongArrayRegion(env, pSize, 0, 1, &pSz);
        (*env)->SetLongArrayRegion(env, qSize, 0, 1, &qSz);
        (*env)->SetLongArrayRegion(env, dPSize, 0, 1, &dPSz);
        (*env)->SetLongArrayRegion(env, dQSize, 0, 1, &dQSz);
        (*env)->SetLongArrayRegion(env, uSize, 0, 1, &uSz);

        /* Only log if no exception occurred */
        if (!(*env)->ExceptionOccurred(env)) {
            LogStr("wc_RsaExportCrtKey() = %d\n", ret);
            LogStr("n[%u]: [%p]\n", (word32)nSz, n);
            LogHex((byte*) n, 0, nSz);
            LogStr("e[%u]: [%p]\n", (word32)eSz, e);
            LogHex((byte*) e, 0, eSz);
            LogStr("p[%u]: [%p]\n", (word32)pSz, p);
            LogStr("q[%u]: [%p]\n", (word32)qSz, q);
            LogStr("dP[%u]: [%p]\n", (word32)dPSz, dP);
            LogStr("dQ[%u]: [%p]\n", (word32)dQSz, dQ);
            LogStr("u[%u]: [%p]\n", (word32)uSz, u);
        }
    }

    /* Release all byte arrays */
    releaseByteArray(env, n_object, n, ret);
    releaseByteArray(env, e_object, e, ret);
    releaseByteArray(env, d_object, d, ret);
    releaseByteArray(env, p_object, p, ret);
    releaseByteArray(env, q_object, q, ret);
    releaseByteArray(env, dP_object, dP, ret);
    releaseByteArray(env, dQ_object, dQ, ret);
    releaseByteArray(env, u_object, u, ret);
#else
    (void)env;
    (void)this;
    (void)n_object;
    (void)nSize;
    (void)e_object;
    (void)eSize;
    (void)d_object;
    (void)dSize;
    (void)p_object;
    (void)pSize;
    (void)q_object;
    (void)qSize;
    (void)dP_object;
    (void)dPSize;
    (void)dQ_object;
    (void)dQSize;
    (void)u_object;
    (void)uSize;

    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaImportCrtKey(
    JNIEnv* env, jobject this, jbyteArray n_object, jbyteArray e_object,
    jbyteArray d_object, jbyteArray p_object, jbyteArray q_object,
    jbyteArray dP_object, jbyteArray dQ_object, jbyteArray u_object)
{
#if !defined(NO_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
    int ret = 0;
    RsaKey* key = NULL;
    byte* n = NULL;
    byte* e = NULL;
    byte* d = NULL;
    byte* p = NULL;
    byte* q = NULL;
    byte* dP = NULL;
    byte* dQ = NULL;
    byte* u = NULL;
    word32 nSz = 0, eSz = 0, dSz = 0, pSz = 0;
    word32 qSz = 0, dPSz = 0, dQSz = 0, uSz = 0;

#ifndef WOLFSSL_PUBLIC_MP
    ret = NOT_COMPILED_IN;
#endif

    if (ret == 0) {
        key = (RsaKey*) getNativeStruct(env, this);
        if ((*env)->ExceptionOccurred(env)) {
            /* getNativeStruct may throw exception, prevent throwing another */
            return;
        }

        /* Get array pointers and sizes */
        n = getByteArray(env, n_object);
        nSz = getByteArrayLength(env, n_object);

        e = getByteArray(env, e_object);
        eSz = getByteArrayLength(env, e_object);

        d = getByteArray(env, d_object);
        dSz = getByteArrayLength(env, d_object);

        p = getByteArray(env, p_object);
        pSz = getByteArrayLength(env, p_object);

        q = getByteArray(env, q_object);
        qSz = getByteArrayLength(env, q_object);

        dP = getByteArray(env, dP_object);
        dPSz = getByteArrayLength(env, dP_object);

        dQ = getByteArray(env, dQ_object);
        dQSz = getByteArrayLength(env, dQ_object);

        u = getByteArray(env, u_object);
        uSz = getByteArrayLength(env, u_object);

        /* Validate inputs */
        if (key == NULL || n == NULL || e == NULL || d == NULL || p == NULL ||
            q == NULL || dP == NULL || dQ == NULL || u == NULL) {
            ret = BAD_FUNC_ARG;
        }
    }

#ifdef WOLFSSL_PUBLIC_MP
    /* Use manual import via mp_read_unsigned_bin() for compatibility with
     * older wolfSSL/FIPS versions that do not have
     * wc_RsaPrivateKeyDecodeRaw. */
    if (ret == 0) {
        /* Import n, e, d, p, q using mp_read_unsigned_bin() */
        ret = mp_read_unsigned_bin(&key->n, n, nSz);
    }
    if (ret == 0) {
        ret = mp_read_unsigned_bin(&key->e, e, eSz);
    }
    if (ret == 0) {
        ret = mp_read_unsigned_bin(&key->d, d, dSz);
    }
    if (ret == 0) {
        ret = mp_read_unsigned_bin(&key->p, p, pSz);
    }
    if (ret == 0) {
        ret = mp_read_unsigned_bin(&key->q, q, qSz);
    }
    /* Import CRT parameters dP, dQ, u */
    if (ret == 0) {
        ret = mp_read_unsigned_bin(&key->dP, dP, dPSz);
    }
    if (ret == 0) {
        ret = mp_read_unsigned_bin(&key->dQ, dQ, dQSz);
    }
    if (ret == 0) {
        ret = mp_read_unsigned_bin(&key->u, u, uSz);
    }
    if (ret == 0) {
        key->type = RSA_PRIVATE;
    }
#endif /* WOLFSSL_PUBLIC_MP */

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    /* Release all byte arrays */
    releaseByteArray(env, n_object, n, ret);
    releaseByteArray(env, e_object, e, ret);
    releaseByteArray(env, d_object, d, ret);
    releaseByteArray(env, p_object, p, ret);
    releaseByteArray(env, q_object, q, ret);
    releaseByteArray(env, dP_object, dP, ret);
    releaseByteArray(env, dQ_object, dQ, ret);
    releaseByteArray(env, u_object, u, ret);
#else
    (void)env;
    (void)this;
    (void)n_object;
    (void)e_object;
    (void)d_object;
    (void)p_object;
    (void)q_object;
    (void)dP_object;
    (void)dQ_object;
    (void)u_object;

    throwNotCompiledInException(env);
#endif /* !NO_RSA && !WOLFSSL_RSA_PUBLIC_ONLY */
}

