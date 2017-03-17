/* jni_rsa.c
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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
    RsaKey* key = (RsaKey*) getNativeStruct(env, this);
    RNG* rng = (RNG*) getNativeStruct(env, rng_object);

    ret = wc_MakeRsaKey(key, size, e, rng);
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
    RsaKey* key = (RsaKey*) getNativeStruct(env, this);
    byte* n = getDirectBufferAddress(env, n_object);
    byte* e = getDirectBufferAddress(env, e_object);

    ret = wc_RsaPublicKeyDecodeRaw(n, nSize, e, eSize, key);
    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);
    
    LogStr("wc_RsaPublicKeyDecodeRaw(n, nSz, e, eSz) = %d\n", ret);
    LogStr("n[%u]: [%p]\n", (word32)nSize, n);
    LogHex((byte*) n, nSize);
    LogStr("e[%u]: [%p]\n", (word32)eSize, e);
    LogHex((byte*) e, eSize);
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
    RsaKey* key = (RsaKey*) getNativeStruct(env, this);
    byte* n = getByteArray(env, n_object);
    byte* e = getByteArray(env, e_object);

    ret = wc_RsaPublicKeyDecodeRaw(n, nSize, e, eSize, key);
    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_RsaPublicKeyDecodeRaw(n, nSz, e, eSz) = %d\n", ret);
    LogStr("n[%u]: [%p]\n", (word32)nSize, n);
    LogHex((byte*) n, nSize);
    LogStr("e[%u]: [%p]\n", (word32)eSize, e);
    LogHex((byte*) e, eSize);
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
    RsaKey* key = (RsaKey*) getNativeStruct(env, this);
    byte* n = getDirectBufferAddress(env, n_object);
    byte* e = getDirectBufferAddress(env, e_object);
    word32 nSize = n ? getDirectBufferLimit(env, n_object) : 0;
    word32 eSize = e ? getDirectBufferLimit(env, e_object) : 0;

    ret = RsaFlattenPublicKey(key, e, &eSize, n, &nSize);
    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    } else {
        setDirectBufferLimit(env, n_object, nSize);
        setDirectBufferLimit(env, e_object, eSize);
    }

    LogStr("RsaFlattenPublicKey(key, e, eSz, n, nSz) = %d\n", ret);
    LogStr("n[%u]: [%p]\n", (word32)nSize, n);
    LogHex((byte*) n, nSize);
    LogStr("e[%u]: [%p]\n", (word32)eSize, e);
    LogHex((byte*) e, eSize);
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
    RsaKey* key = (RsaKey*) getNativeStruct(env, this);
    byte* n = getByteArray(env, n_object);
    byte* e = getByteArray(env, e_object);
    jlong nSz;
    jlong eSz;

    (*env)->GetLongArrayRegion(env, nSize, 0, 1, &nSz);
    (*env)->GetLongArrayRegion(env, eSize, 0, 1, &eSz);

    ret = RsaFlattenPublicKey(key, e, (word32*) &eSz, n, (word32*) &nSz);
    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    } else {
        (*env)->SetLongArrayRegion(env, nSize, 0, 1, &nSz);
        (*env)->SetLongArrayRegion(env, eSize, 0, 1, &eSz);
    }

    LogStr("RsaFlattenPublicKey(key, e, eSz, n, nSz) = %d\n", ret);
    LogStr("n[%u]: [%p]\n", (word32)nSz, n);
    LogHex((byte*) n, nSz);
    LogStr("e[%u]: [%p]\n", (word32)eSz, e);
    LogHex((byte*) e, eSz);

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

    ret = wc_InitRsaKey(key, NULL);
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

    ret = wc_FreeRsaKey(key);
    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_FreeRsaKey(key) = %d\n", ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaPrivateKeyDecode(
    JNIEnv* env, jobject this, jbyteArray key_object)
{
#ifndef NO_RSA
    int ret = 0;
    RsaKey* key = (RsaKey*) getNativeStruct(env, this);
    byte* k = getByteArray(env, key_object);
    word32 kSz = getByteArrayLength(env, key_object);
    word32 index = 0;

    ret = wc_RsaPrivateKeyDecode(k, &index, key, kSz);
    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_RsaPrivateKeyDecode(k, kSize, key) = %d\n", ret);
    LogStr("key[%u]: [%p]\n", (word32)kSz, k);
    LogHex((byte*) k, kSz);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaPrivateKeyDecodePKCS8
  (JNIEnv* env, jobject this, jbyteArray key_object)
{
#ifndef NO_RSA
    int ret    = 0;
    int length = 0;
    RsaKey* key = (RsaKey*) getNativeStruct(env, this);
    byte* k = getByteArray(env, key_object);
    word32 kSz = getByteArrayLength(env, key_object);
    word32 offset = 0;

    length = wc_GetPkcs8TraditionalOffset(k, &offset, kSz);

    if (length < 0) {
        throwWolfCryptExceptionFromError(env, length);

    } else {
        ret = wc_RsaPrivateKeyDecode(k, &offset, key, kSz);
        if (ret != 0)
            throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_RsaPrivateKeyDecodePKCS8(k, kSize, key) = %d\n", ret);
    LogStr("key[%u]: [%p]\n", (word32)kSz, k);
    LogHex((byte*) k, kSz);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Rsa_wc_1RsaPublicKeyDecode
  (JNIEnv* env, jobject this, jbyteArray key_object)
{
#ifndef NO_RSA
    int ret = 0;
    RsaKey* key = (RsaKey*) getNativeStruct(env, this);
    byte* k = getByteArray(env, key_object);
    word32 kSz = getByteArrayLength(env, key_object);
    word32 index = 0;

    ret = wc_RsaPublicKeyDecode(k, &index, key, kSz);
    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_RsaPublicKeyDecode(k, kSize, key) = %d\n", ret);
    LogStr("key[%u]: [%p]\n", (word32)kSz, k);
    LogHex((byte*) k, kSz);
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

    /* RsaEncryptSize doesn't sanitize key */
    if (!key) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);

    } else {
        ret = wc_RsaEncryptSize(key);
        if (ret < 0)
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
    RsaKey* key = (RsaKey*) getNativeStruct(env, this);
    RNG* rng = (RNG*) getNativeStruct(env, rng_object);
    byte* plaintext = getByteArray(env, plaintext_object);
    word32 size = getByteArrayLength(env, plaintext_object);
    byte* output = NULL;
    word32 outputSz = wc_RsaEncryptSize(key);

    output = XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate ciphertext buffer");
        return result;
    }

    ret = wc_RsaPublicEncrypt(plaintext, size, output, outputSz, key, rng);
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
    LogHex((byte*) output, outputSz);

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
    RsaKey* key = (RsaKey*) getNativeStruct(env, this);
    byte* ciphertext = getByteArray(env, ciphertext_object);
    word32 size = getByteArrayLength(env, ciphertext_object);
    byte* output = NULL;
    word32 outputSz = wc_RsaEncryptSize(key);

    output = XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate plaintext buffer");
        return result;
    }

    ret = wc_RsaPrivateDecrypt(ciphertext, size, output, outputSz, key);
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

    LogStr("wc_RsaPrivateDecrypt(in, inSz, out, outSz, key, rng) = %d\n", ret);
    LogStr("output[%u]: [%p]\n", outputSz, output);
    LogHex((byte*) output, outputSz);

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
    RsaKey* key = (RsaKey*) getNativeStruct(env, this);
    RNG* rng = (RNG*) getNativeStruct(env, rng_object);
    byte* data = getByteArray(env, data_object);
    word32 size = getByteArrayLength(env, data_object);
    byte* output = NULL;
    word32 outputSz = wc_RsaEncryptSize(key);

    output = XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate signature buffer");
        return result;
    }

    ret = wc_RsaSSL_Sign(data, size, output, outputSz, key, rng);
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
    LogHex((byte*) output, outputSz);

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
    RsaKey* key = (RsaKey*) getNativeStruct(env, this);
    byte* signature = getByteArray(env, signature_object);
    word32 size = getByteArrayLength(env, signature_object);
    byte* output = NULL;
    word32 outputSz = wc_RsaEncryptSize(key);

    output = XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate verify buffer");
        return result;
    }

    ret = wc_RsaSSL_Verify(signature, size, output, outputSz, key);
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
    LogHex((byte*) output, outputSz);

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    throwNotCompiledInException(env);
#endif

    return result;
}
