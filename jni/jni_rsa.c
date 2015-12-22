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
#include <wolfssl/wolfcrypt/error-crypt.h>

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

    LogStr("new Rsa() = %p\n", (void*)ret);

#endif

    return ret;
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Rsa_decodeRawPublicKey__Ljava_nio_ByteBuffer_2JLjava_nio_ByteBuffer_2J(
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

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Rsa_decodeRawPublicKey___3BJ_3BJ(
    JNIEnv* env, jobject this, jbyteArray n_object, jlong nSize,
    jbyteArray e_object, jlong eSize)
{
    jint ret = NOT_COMPILED_IN;

#ifndef NO_RSA

    RsaKey* key = (RsaKey*) getNativeStruct(env, this);
    byte* n = getByteArray(env, n_object);
    byte* e = getByteArray(env, e_object);

    ret = (!key || !n || !e)
        ? BAD_FUNC_ARG
        : wc_RsaPublicKeyDecodeRaw(n, nSize, e, eSize, key);

    releaseByteArray(env, n_object, n, ret);
    releaseByteArray(env, e_object, e, ret);

#endif

    return ret;
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Rsa_exportRawPublicKey__Ljava_nio_ByteBuffer_2Ljava_nio_ByteBuffer_2(
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

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Rsa_exportRawPublicKey___3B_3B(
    JNIEnv* env, jobject this, jbyteArray n_object, jlongArray nSize,
    jbyteArray e_object, jlongArray eSize)
{
    jint ret = NOT_COMPILED_IN;

#ifndef NO_RSA
    RsaKey* key = (RsaKey*) getNativeStruct(env, this);
    byte* n = getByteArray(env, n_object);
    byte* e = getByteArray(env, e_object);
    word32 nSz;
    word32 eSz;

    (*env)->GetLongArrayRegion(env, nSize, 0, 1, (jlong*) &nSz);
    (*env)->GetLongArrayRegion(env, eSize, 0, 1, (jlong*) &eSz);

    ret = (!key || !n || !e)
        ? BAD_FUNC_ARG
        : RsaFlattenPublicKey(key, e, &eSz, n, &nSz);

    (*env)->SetLongArrayRegion(env, nSize, 0, 1, (jlong*) &nSz);
    (*env)->SetLongArrayRegion(env, eSize, 0, 1, (jlong*) &eSz);

    releaseByteArray(env, n_object, n, ret);
    releaseByteArray(env, e_object, e, ret);

#endif

    return ret;
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

    LogStr("rsa.makeKey(%d, %lu)\n", size, e);

    if (!key || !rng)
        throwWolfCryptException(env, "Bad method argument provided");
    else if ((ret = MakeRsaKey(key, size, e, rng)) != 0)
        throwWolfCryptException(env, "Failed to make rsa key");

#endif
}
