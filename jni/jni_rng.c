/* jni_rng.c
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
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <com_wolfssl_wolfcrypt_Rng.h>
#include <wolfcrypt_jni_error.h>
#include <wolfcrypt_jni_NativeStruct.h>


/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

#if !defined(WC_NO_RNG) && defined(NO_OLD_RNGNAME)
    #define RNG WC_RNG
#endif

JNIEXPORT jlong JNICALL
Java_com_wolfssl_wolfcrypt_Rng_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
#ifndef WC_NO_RNG
    RNG* rng = NULL;

    rng = (RNG*)XMALLOC(sizeof(RNG), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (rng == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate Rng object");
    }
    else {
        XMEMSET(rng, 0, sizeof(RNG));
    }

    LogStr("new Rng() = %p\n", rng);

    return (jlong)(uintptr_t)rng;
#else
    throwNotCompiledInException(env);

    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Rng_initRng(
    JNIEnv* env, jobject this)
{
#ifndef WC_NO_RNG
    int ret = 0;
    RNG* rng = (RNG*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    ret = (!rng)
        ? BAD_FUNC_ARG
        : wc_InitRng(rng);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_InitRng(rng=%p) = %d\n", rng, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Rng_freeRng(
    JNIEnv* env, jobject this)
{
#ifndef WC_NO_RNG
    int ret = 0;
    RNG* rng = (RNG*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    ret = (!rng)
        ? BAD_FUNC_ARG
        : wc_FreeRng(rng);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_FreeRng(rng=%p) = %d\n", rng, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Rng_rngGenerateBlock__Ljava_nio_ByteBuffer_2II(
    JNIEnv* env, jobject this, jobject buffer_buffer, jint position, jint size)
{
#ifndef WC_NO_RNG
    int ret = 0;
    RNG*  rng    = NULL;
    byte* buffer = NULL;

    rng = (RNG*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    buffer = getDirectBufferAddress(env, buffer_buffer);

    ret = (!rng || !buffer)
        ? BAD_FUNC_ARG
        : wc_RNG_GenerateBlock(rng, buffer + position, size);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_RNG_GenerateBlock(rng=%p, buffer, size) = %d\n", rng, ret);
    LogStr("output[%u]: [%p]\n", (word32)size, buffer);
    LogHex(buffer, 0, size);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Rng_rngGenerateBlock___3BII(
    JNIEnv* env, jobject this, jbyteArray buffer_buffer, jint offset,
    jint length)
{
#ifndef WC_NO_RNG
    int ret = 0;
    RNG*  rng    = NULL;
    byte* buffer = NULL;

    rng = (RNG*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    buffer = getByteArray(env, buffer_buffer);

    ret = (!rng || !buffer)
        ? BAD_FUNC_ARG
        : wc_RNG_GenerateBlock(rng, buffer + offset, length);
    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_RNG_GenerateBlock(rng=%p, buffer, length) = %d\n", rng, ret);
    LogStr("output[%u]: [%p]\n", (word32)length, buffer);
    LogHex(buffer, 0, length);

    releaseByteArray(env, buffer_buffer, buffer, ret);
#else
    throwNotCompiledInException(env);
#endif
}

