/* jni_rsa.c
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
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
    JNIEnv* env, jobject this, jobject n_object, jlong nSize, jobject e_object,
    jlong eSize)
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

