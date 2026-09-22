/* jni_shake.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/sha3.h>

#include <com_wolfssl_wolfcrypt_Shake.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

/* SHAKE-128/256 (FIPS 202 XOF) */
#if defined(WOLFSSL_SHA3) && \
    (defined(WOLFSSL_SHAKE128) || defined(WOLFSSL_SHAKE256))
    #define WOLFCRYPT_JNI_HAVE_SHAKE
#endif

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Shake_mallocNativeStruct_1internal
  (JNIEnv* env, jobject this)
{
#ifdef WOLFCRYPT_JNI_HAVE_SHAKE
    wc_Shake* shake = NULL;

    shake = (wc_Shake*) XMALLOC(sizeof(wc_Shake), NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (shake == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate wc_Shake object");
    }
    else {
        XMEMSET(shake, 0, sizeof(wc_Shake));
    }

    LogStr("new wc_Shake = %p\n", shake);

    return (jlong)(uintptr_t)shake;
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Shake_native_1init_1internal
  (JNIEnv* env, jobject this, jint hashType)
{
#ifdef WOLFCRYPT_JNI_HAVE_SHAKE
    int ret = 0;
    wc_Shake* shake = NULL;

    shake = (wc_Shake*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    if (shake == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        switch (hashType) {
#ifdef WOLFSSL_SHAKE128
            case WC_HASH_TYPE_SHAKE128:
                ret = wc_InitShake128(shake, NULL, INVALID_DEVID);
                break;
#endif
#ifdef WOLFSSL_SHAKE256
            case WC_HASH_TYPE_SHAKE256:
                ret = wc_InitShake256(shake, NULL, INVALID_DEVID);
                break;
#endif
            default:
                ret = BAD_FUNC_ARG;
                break;
        }
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }
#else
    (void)env;
    (void)this;
    (void)hashType;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Shake_native_1copy_1internal
  (JNIEnv* env, jobject this, jobject toBeCopied, jint hashType)
{
#ifdef WOLFCRYPT_JNI_HAVE_SHAKE
    int ret = 0;
    wc_Shake* shake = NULL;
    wc_Shake* tbc = NULL; /* tbc = to be copied */

    if (this == NULL || toBeCopied == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return;
    }

    shake = (wc_Shake*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    tbc = (wc_Shake*) getNativeStruct(env, toBeCopied);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    switch (hashType) {
#ifdef WOLFSSL_SHAKE128
        case WC_HASH_TYPE_SHAKE128:
            ret = wc_Shake128_Copy(tbc, shake);
            break;
#endif
#ifdef WOLFSSL_SHAKE256
        case WC_HASH_TYPE_SHAKE256:
            ret = wc_Shake256_Copy(tbc, shake);
            break;
#endif
        default:
            ret = BAD_FUNC_ARG;
            break;
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }
#else
    (void)env;
    (void)this;
    (void)toBeCopied;
    (void)hashType;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Shake_native_1update_1internal__Ljava_nio_ByteBuffer_2III
  (JNIEnv* env, jobject this, jobject data_buffer, jint offset, jint len,
   jint hashType)
{
#ifdef WOLFCRYPT_JNI_HAVE_SHAKE
    int ret = 0;
    byte* data = NULL;
    wc_Shake* shake = NULL;
    jlong dataSz = 0;

    shake = (wc_Shake*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    data = getDirectBufferAddress(env, data_buffer);
    dataSz = (*env)->GetDirectBufferCapacity(env, data_buffer);

    if (shake == NULL || data == NULL || offset < 0 || len < 0 ||
        ((jlong)offset + (jlong)len) > dataSz) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        switch (hashType) {
#ifdef WOLFSSL_SHAKE128
            case WC_HASH_TYPE_SHAKE128:
                ret = wc_Shake128_Update(shake, data + offset, len);
                break;
#endif
#ifdef WOLFSSL_SHAKE256
            case WC_HASH_TYPE_SHAKE256:
                ret = wc_Shake256_Update(shake, data + offset, len);
                break;
#endif
            default:
                ret = BAD_FUNC_ARG;
                break;
        }
    }

    if (ret < 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_Shake_Update(shake=%p, data, len) = %d\n", shake, ret);
    if (ret == 0) {
        LogStr("data[%u]: [%p]\n", (word32)len, data);
        LogHex(data, offset, len);
    }
#else
    (void)env;
    (void)this;
    (void)data_buffer;
    (void)offset;
    (void)len;
    (void)hashType;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Shake_native_1update_1internal___3BIII
  (JNIEnv* env, jobject this, jbyteArray data_buffer, jint offset, jint len,
   jint hashType)
{
#ifdef WOLFCRYPT_JNI_HAVE_SHAKE
    int ret = 0;
    wc_Shake* shake = NULL;
    byte* data = NULL;
    word32 dataSz = 0;

    shake = (wc_Shake*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    data = getByteArray(env, data_buffer);
    if ((*env)->ExceptionOccurred(env)) {
        /* GetByteArrayElements failed, leave its exception pending */
        return;
    }
    dataSz = getByteArrayLength(env, data_buffer);

    if (shake == NULL || data == NULL || offset < 0 || len < 0 ||
        ((jlong)offset + (jlong)len) > (jlong)dataSz) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        switch (hashType) {
#ifdef WOLFSSL_SHAKE128
            case WC_HASH_TYPE_SHAKE128:
                ret = wc_Shake128_Update(shake, data + offset, len);
                break;
#endif
#ifdef WOLFSSL_SHAKE256
            case WC_HASH_TYPE_SHAKE256:
                ret = wc_Shake256_Update(shake, data + offset, len);
                break;
#endif
            default:
                ret = BAD_FUNC_ARG;
                break;
        }
    }

    if (ret < 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_Shake_Update(shake=%p, data, len) = %d\n", shake, ret);
    if (ret == 0) {
        LogStr("data[%u]: [%p]\n", (word32)len, data);
        LogHex(data, offset, len);
    }

    releaseByteArray(env, data_buffer, data, JNI_ABORT);
#else
    (void)env;
    (void)this;
    (void)data_buffer;
    (void)offset;
    (void)len;
    (void)hashType;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Shake_native_1final_1internal__Ljava_nio_ByteBuffer_2III
  (JNIEnv* env, jobject this, jobject hash_buffer, jint position,
   jint hashType, jint outLen)
{
#ifdef WOLFCRYPT_JNI_HAVE_SHAKE
    int ret = 0;
    wc_Shake* shake = NULL;
    byte* hash = NULL;
    jlong hashSz = 0;

    shake = (wc_Shake*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    hash = getDirectBufferAddress(env, hash_buffer);
    hashSz = (*env)->GetDirectBufferCapacity(env, hash_buffer);

    if (shake == NULL || hash == NULL || position < 0 || outLen < 0 ||
        ((jlong)position + (jlong)outLen) > hashSz) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        switch (hashType) {
#ifdef WOLFSSL_SHAKE128
            case WC_HASH_TYPE_SHAKE128:
                ret = wc_Shake128_Final(shake, hash + position,
                    (word32)outLen);
                break;
#endif
#ifdef WOLFSSL_SHAKE256
            case WC_HASH_TYPE_SHAKE256:
                ret = wc_Shake256_Final(shake, hash + position,
                    (word32)outLen);
                break;
#endif
            default:
                ret = BAD_FUNC_ARG;
                break;
        }
    }

    if (ret < 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_Shake_Final(shake=%p, hash, outLen) = %d\n", shake, ret);
#else
    (void)env;
    (void)this;
    (void)hash_buffer;
    (void)position;
    (void)hashType;
    (void)outLen;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Shake_native_1final_1internal___3BII
  (JNIEnv* env, jobject this, jbyteArray hash_buffer, jint hashType,
   jint outLen)
{
#ifdef WOLFCRYPT_JNI_HAVE_SHAKE
    int ret = 0;
    wc_Shake* shake = NULL;
    byte* hash = NULL;
    word32 hashSz = 0;

    shake = (wc_Shake*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    hash = getByteArray(env, hash_buffer);
    if ((*env)->ExceptionOccurred(env)) {
        /* GetByteArrayElements failed, leave its exception pending */
        return;
    }
    hashSz = getByteArrayLength(env, hash_buffer);

    if (shake == NULL || hash == NULL || outLen < 0 ||
        (jlong)outLen > (jlong)hashSz) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        switch (hashType) {
#ifdef WOLFSSL_SHAKE128
            case WC_HASH_TYPE_SHAKE128:
                ret = wc_Shake128_Final(shake, hash, (word32)outLen);
                break;
#endif
#ifdef WOLFSSL_SHAKE256
            case WC_HASH_TYPE_SHAKE256:
                ret = wc_Shake256_Final(shake, hash, (word32)outLen);
                break;
#endif
            default:
                ret = BAD_FUNC_ARG;
                break;
        }
    }

    if (ret < 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_Shake_Final(shake=%p, hash, outLen) = %d\n", shake, ret);

    releaseByteArray(env, hash_buffer, hash, ret);
#else
    (void)env;
    (void)this;
    (void)hash_buffer;
    (void)hashType;
    (void)outLen;

    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Shake_native_1free_1internal
  (JNIEnv* env, jobject this, jint hashType)
{
#ifdef WOLFCRYPT_JNI_HAVE_SHAKE
    wc_Shake* shake = NULL;

    shake = (wc_Shake*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    if (shake != NULL) {
        switch (hashType) {
#ifdef WOLFSSL_SHAKE128
            case WC_HASH_TYPE_SHAKE128:
                wc_Shake128_Free(shake);
                break;
#endif
#ifdef WOLFSSL_SHAKE256
            case WC_HASH_TYPE_SHAKE256:
                wc_Shake256_Free(shake);
                break;
#endif
            default:
                break;
        }

        XMEMSET(shake, 0, sizeof(wc_Shake));
    }

    LogStr("wc_Shake_Free(shake=%p)\n", shake);
#else
    (void)env;
    (void)this;
    (void)hashType;
    throwNotCompiledInException(env);
#endif
}

