/* jni_sha.c
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
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>

#include <com_wolfssl_wolfcrypt_Sha.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Sha_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    jlong ret = 0;

#ifdef NO_SHA
    throwNotCompiledInException(env);
#else

    ret = (jlong) XMALLOC(sizeof(Sha), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Sha object");

    LogStr("new Sha() = %p\n", ret);

#endif

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Sha256_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    jlong ret = 0;

#ifdef NO_SHA256
    throwNotCompiledInException(env);
#else

    ret = (jlong) XMALLOC(sizeof(Sha256), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Sha256 object");

    LogStr("new Sha256() = %p\n", ret);

#endif

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Sha384_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    jlong ret = 0;

#ifndef WOLFSSL_SHA512
    throwNotCompiledInException(env);
#else

    ret = (jlong) XMALLOC(sizeof(Sha384), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Sha384 object");

    LogStr("new Sha384() = %p\n", ret);

#endif

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Sha512_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    jlong ret = 0;

#ifndef WOLFSSL_SHA512
    throwNotCompiledInException(env);
#else

    ret = (jlong) XMALLOC(sizeof(Sha512), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Sha512 object");

    LogStr("new Sha512() = %p\n", ret);

#endif

    return ret;
}
