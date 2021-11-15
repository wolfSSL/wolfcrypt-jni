/* jni_rsa.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

#ifndef __ANDROID__
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

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
    jlong ret = 0;

#ifndef NO_RSA
    ret = (jlong) XMALLOC(sizeof(RsaKey), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Rsa object");

    LogStr("new Rsa() = %p\n", (void*)ret);
#else
    throwNotCompiledInException(env);
#endif

    return ret;
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

    ret = (!key || !rng)
        ? BAD_FUNC_ARG
        : wc_MakeRsaKey(key, size, e, rng);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("MakeRsaKey(%d, %lu) = %d\n", size, e, ret);
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

    ret = (!key || !n || !e)
        ? BAD_FUNC_ARG
        : wc_RsaPublicKeyDecodeRaw(n, nSize, e, eSize, key);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);
    
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

    ret = (!key || !n || !e)
        ? BAD_FUNC_ARG
        : wc_RsaPublicKeyDecodeRaw(n, nSize, e, eSize, key);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

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

    ret = (!key || !n || !e)
        ? BAD_FUNC_ARG
        : wc_RsaFlattenPublicKey(key, e, &eSize, n, &nSize);

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

    LogStr("RsaFlattenPublicKey(key, e, eSz, n, nSz) = %d\n", ret);
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

    ret = (!key || !n || !e)
        ? BAD_FUNC_ARG
        : wc_RsaFlattenPublicKey(key, e, (word32*) &eSz, n, (word32*) &nSz);

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

    ret = (!key)
        ? BAD_FUNC_ARG
        : wc_InitRsaKey(key, NULL);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("RsaInitKey(key) = %d\n", ret);
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

    ret = (!key)
        ? BAD_FUNC_ARG
        : wc_FreeRsaKey(key);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

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

    ret = (key == NULL)
        ? BAD_FUNC_ARG
        : wc_RsaSetRNG(key, rng);

    LogStr("wc_RsaSetRNG(key, rng) = %d\n", ret);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);
    else
        return JNI_TRUE;
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

    ret = (!key || !k)
        ? BAD_FUNC_ARG
        : wc_RsaPrivateKeyDecode(k, &index, key, kSz);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_RsaPrivateKeyDecode(k, kSize, key) = %d\n", ret);
    LogStr("key[%u]: [%p]\n", (word32)kSz, k);
    LogHex((byte*) k, 0, kSz);

    releaseByteArray(env, key_object, k, JNI_ABORT);
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

    if (!key || !k) {
        ret = BAD_FUNC_ARG;
    } else {
        length = wc_GetPkcs8TraditionalOffset(k, &offset, kSz);
        
        ret = (length < 0)
            ? length
            : wc_RsaPrivateKeyDecode(k, &offset, key, kSz);
    }

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

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

    ret = (!key || !k)
        ? BAD_FUNC_ARG
        : wc_RsaPublicKeyDecode(k, &index, key, kSz);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

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

    ret = (!key)
        ? BAD_FUNC_ARG
        : wc_RsaEncryptSize(key);

    if (ret < 0)
        throwWolfCryptExceptionFromError(env, ret);

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
    outputSz = wc_RsaEncryptSize(key);

    output = XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate ciphertext buffer");

        releaseByteArray(env, plaintext_object, plaintext, JNI_ABORT);

        return result;
    }

    ret = (!key || !rng || !plaintext)
        ? BAD_FUNC_ARG
        : wc_RsaPublicEncrypt(plaintext, size, output, outputSz, key, rng);

    if (ret >= 0) {
        outputSz = ret;
        result = (*env)->NewByteArray(env, outputSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, outputSz,
                                                         (const jbyte*) output);
        } else {
            throwWolfCryptException(env, "Failed to allocate ciphertext");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_RsaPublicEncrypt(in, inSz, out, outSz, key=, rng) = %d\n", ret);
    LogStr("output[%u]: [%p]\n", outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);

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
    outputSz = wc_RsaEncryptSize(key);

    output = XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate plaintext buffer");

        releaseByteArray(env, ciphertext_object, ciphertext, JNI_ABORT);

        return result;
    }

    ret = (!key || !ciphertext)
        ? BAD_FUNC_ARG
        : wc_RsaPrivateDecrypt(ciphertext, size, output, outputSz, key);

    if (ret >= 0) {
        outputSz = ret;
        result = (*env)->NewByteArray(env, outputSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, outputSz,
                                                         (const jbyte*) output);
        } else {
            throwWolfCryptException(env, "Failed to allocate plaintext");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_RsaPrivateDecrypt(in, inSz, out, outSz, key) = %d\n", ret);
    LogStr("output[%u]: [%p]\n", outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);

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
    outputSz = wc_RsaEncryptSize(key);

    output = XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate signature buffer");

        releaseByteArray(env, data_object, data, JNI_ABORT);

        return result;
    }

    ret = (!key || !rng || !data)
        ? BAD_FUNC_ARG
        : wc_RsaSSL_Sign(data, size, output, outputSz, key, rng);

    if (ret >= 0) {
        outputSz = ret;
        result = (*env)->NewByteArray(env, outputSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, outputSz,
                                                         (const jbyte*) output);
        } else {
            throwWolfCryptException(env, "Failed to allocate signature");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_RsaSSL_Sign(in, inSz, out, outSz, key, rng) = %d\n", ret);
    LogStr("output[%u]: [%p]\n", outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);

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
    outputSz = wc_RsaEncryptSize(key);

    output = XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate verify buffer");

        releaseByteArray(env, signature_object, signature, JNI_ABORT);

        return result;
    }

    ret = (!key || !signature)
        ? BAD_FUNC_ARG
        : wc_RsaSSL_Verify(signature, size, output, outputSz, key);

    if (ret >= 0) {
        outputSz = ret;
        result = (*env)->NewByteArray(env, outputSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, outputSz,
                                                         (const jbyte*) output);
        } else {
            throwWolfCryptException(env, "Failed to allocate verify");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_RsaSSL_Verify(in, inSz, out, outSz, key) = %d\n", ret);
    LogStr("output[%u]: [%p]\n", outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    releaseByteArray(env, signature_object, signature, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif

    return result;
}
