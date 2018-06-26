/* jni_md5.c
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
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/md5.h>

#include <com_wolfssl_wolfcrypt_Md5.h>
#include <com_wolfssl_wolfcrypt_WolfCrypt.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL
Java_com_wolfssl_wolfcrypt_Md5_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    jlong ret = 0;

#ifndef NO_MD5
    ret = (jlong) XMALLOC(sizeof(Md5), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Md5 object");

    LogStr("new Md5() = %p\n", (void*)ret);
#else
    throwNotCompiledInException(env);
#endif

    return ret;
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Md5_native_1init(
    JNIEnv* env, jobject this)
{
#ifndef NO_MD5
    Md5* md5 = (Md5*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    if (!md5) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
    } else {
        wc_InitMd5(md5);
    }
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Md5_native_1update__Ljava_nio_ByteBuffer_2II(
    JNIEnv* env, jobject this, jobject data_buffer, jint position, jint len)
{
#ifndef NO_MD5
    Md5*  md5  = NULL;
    byte* data = NULL;

    md5 = (Md5*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    data = getDirectBufferAddress(env, data_buffer);

    if (!md5 || !data) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
    } else {
        wc_Md5Update(md5, data + position, len);
    }

    LogStr("wc_Md5Update(md5=%p, data, len)\n", md5);
    LogStr("data[%u]: [%p]\n", (word32)len, data);
    LogHex(data, 0, len);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Md5_native_1update___3BII(
    JNIEnv* env, jobject this, jbyteArray data_buffer, jint offset, jint len)
{
#ifndef NO_MD5
    Md5*   md5   = NULL;
    byte*  data  = NULL;
    jsize  bufSz = (*env)->GetArrayLength(env, data_buffer);

    md5 = (Md5*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    data = getByteArray(env, data_buffer);

    if (!md5 || !data || (offset > bufSz)) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
    } else {
        wc_Md5Update(md5, data + offset, len);
    }

    LogStr("wc_Md5Update(md5=%p, data, len)\n", md5);
    LogStr("data[%u]: [%p]\n", (word32)len, data + offset);
    LogHex(data, offset, len);

    releaseByteArray(env, data_buffer, data, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Md5_native_1final__Ljava_nio_ByteBuffer_2I(
    JNIEnv* env, jobject this, jobject hash_buffer, jint position)
{
#ifndef NO_MD5
    Md5*  md5  = NULL;
    byte* hash = NULL;

    md5 = (Md5*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    hash = getDirectBufferAddress(env, hash_buffer);

    if (!md5 || !hash) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
    } else {
        wc_Md5Final(md5, hash + position);
    }

    LogStr("wc_Md5Final(md5=%p, hash)\n", md5);
    LogStr("hash[%u]: [%p]\n", (word32)MD5_DIGEST_SIZE, hash);
    LogHex(hash, 0, MD5_DIGEST_SIZE);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Md5_native_1final___3B(
    JNIEnv* env, jobject this, jbyteArray hash_buffer)
{
#ifndef NO_MD5
    Md5*  md5  = NULL;
    byte* hash = NULL;

    md5 = (Md5*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    hash = getByteArray(env, hash_buffer);

    if (!md5 || !hash) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
    } else {
        wc_Md5Final(md5, hash);
    }

    LogStr("wc_Md5Final(md5=%p, hash)\n", md5);
    LogStr("hash[%u]: [%p]\n", (word32)MD5_DIGEST_SIZE, hash);
    LogHex(hash, 0, MD5_DIGEST_SIZE);

    releaseByteArray(env, hash_buffer, hash, 0);
#else
    throwNotCompiledInException(env);
#endif
}

