/* jni_rsa.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
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

#include <com_wolfssl_wolfcrypt_Rsa.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

#ifndef __ANDROID__
    #include <wolfssl/options.h>
#endif

#include <wolfssl/wolfcrypt/rsa.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Rsa_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    jlong ret = 0;

#ifdef NO_RSA
    throwNotCompiledInException(env);
#else

    ret = (jlong) XMALLOC(sizeof(RsaKey), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Rsa object");

    LogStr("new Rsa() = %p\n", ret);

#endif

    return ret;
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Rsa_decodeRawPublicKey(
    JNIEnv* env, jobject this, jobject n_object, jlong nSize, jobject e_object,
    jlong eSize)
{
#ifdef NO_RSA
    throwNotCompiledInException(env);
#else

    RsaKey* key = (RsaKey*) getNativeStruct(env, this);
    byte* n = getDirectBufferAddress(env, n_object);
    byte* e = getDirectBufferAddress(env, e_object);

    if (!key || !n || !e)
        throwWolfCryptException(env, "Bad method argument provided");
    else if (wc_RsaPublicKeyDecodeRaw(n, nSize, e, eSize, key) != 0)
        throwWolfCryptException(env, "Failed to decode raw public key");

#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Rsa_exportRawPublicKey(
    JNIEnv* env, jobject this, jobject n_object, jobject e_object)
{
#ifdef NO_RSA
    throwNotCompiledInException(env);
#else

    RsaKey* key = (RsaKey*) getNativeStruct(env, this);
    byte* n = getDirectBufferAddress(env, n_object);
    byte* e = getDirectBufferAddress(env, e_object);
    word32 nSize = n ? getDirectBufferLimit(env, n_object) : 0;
    word32 eSize = e ? getDirectBufferLimit(env, e_object) : 0;

    if (!key || !n || !e)
        throwWolfCryptException(env, "Bad method argument provided");
    else if (RsaFlattenPublicKey(key, e, &eSize, n, &nSize) != 0)
        throwWolfCryptException(env, "Failed to export raw public key");
    else {
        setDirectBufferLimit(env, n_object, nSize);
        setDirectBufferLimit(env, e_object, eSize);
    }

#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Rsa_makeKey(
    JNIEnv *env, jobject this, jint size, jlong e, jobject rng_object)
{
#if defined(NO_RSA) || !defined(WOLFSSL_KEY_GEN)
    throwNotCompiledInException(env);
#else

    int ret = 0;
    RsaKey* key = (RsaKey*) getNativeStruct(env, this);
    RNG* rng = (RNG*) getNativeStruct(env, rng_object);

    if (!key || !rng)
        throwWolfCryptException(env, "Bad method argument provided");
    else if ((ret = MakeRsaKey(key, size, e, rng)) != 0)
        throwWolfCryptException(env, "Failed to make rsa key");

#endif
}
