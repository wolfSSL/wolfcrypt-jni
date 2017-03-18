/* jni_rng.c
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
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <com_wolfssl_wolfcrypt_Rng.h>
#include <wolfcrypt_jni_error.h>
#include <wolfcrypt_jni_NativeStruct.h>


/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Rng_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    RNG* rng = (RNG*) XMALLOC(sizeof(RNG), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!rng)
        throwOutOfMemoryException(env, "Failed to allocate Rng object");

    LogStr("new Rng() = %p\n", rng);

    return (jlong) rng;
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Rng_initRng
  (JNIEnv* env, jobject class)
{
#ifndef WC_NO_RNG

    int ret = 0;
    RNG* rng = (RNG*) getNativeStruct(env, class);

    ret = wc_InitRng(rng);
    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_InitRng(rng=%p) = %d\n", rng, ret);

#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Rng_freeRng
  (JNIEnv* env, jobject class)
{
#ifndef WC_NO_RNG

    int ret = 0;
    RNG* rng = (RNG*) getNativeStruct(env, class);

    ret = wc_FreeRng(rng);
    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_FreeRng(rng=%p) = %d\n", rng, ret);

#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Rng_rngGenerateBlock__Ljava_nio_ByteBuffer_2II
  (JNIEnv* env, jobject class, jobject buf_buffer, jint position, jint sz)
{
#ifndef WC_NO_RNG

    int ret = 0;
    RNG* rng = (RNG*) getNativeStruct(env, class);
    byte* buf = getDirectBufferAddress(env, buf_buffer);

    if (!buf) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);

    } else {
        ret = wc_RNG_GenerateBlock(rng, buf + position, sz);
        if (ret != 0)
            throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_RNG_GenerateBlock(rng=%p, buf, sz) = %d\n", rng, ret);
    LogStr("output[%u]: [%p]\n", (word32)sz, buf);
    LogHex(buf, sz);

#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Rng_rngGenerateBlock___3B
  (JNIEnv* env, jobject class, jbyteArray buf_buffer)
{
#ifndef WC_NO_RNG

    int ret = 0;
    RNG* rng = (RNG*) getNativeStruct(env, class);
    byte* buf = getByteArray(env, buf_buffer);
    word32 bufSz = getByteArrayLength(env, buf_buffer);

    ret = wc_RNG_GenerateBlock(rng, buf, bufSz);
    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_RNG_GenerateBlock(rng=%p, buf, bufSz) = %d\n", rng, ret);
    LogStr("output[%u]: [%p]\n", (word32)bufSz, buf);
    LogHex(buf, bufSz);

    releaseByteArray(env, buf_buffer, buf, ret);

#else
    throwNotCompiledInException(env);
#endif
}

