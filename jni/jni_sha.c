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
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>

#include <com_wolfssl_wolfcrypt_Sha.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL
Java_com_wolfssl_wolfcrypt_Sha_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    jlong ret = 0;

#ifndef NO_SHA
    ret = (jlong) XMALLOC(sizeof(Sha), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Sha object");

    LogStr("new Sha() = %p\n", (void*)ret);
#else
    throwNotCompiledInException(env);
#endif

    return ret;
}

JNIEXPORT jlong JNICALL
Java_com_wolfssl_wolfcrypt_Sha256_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    jlong ret = 0;

#ifndef NO_SHA256
    ret = (jlong) XMALLOC(sizeof(Sha256), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Sha256 object");

    LogStr("new Sha256() = %p\n", (void*)ret);
#else
    throwNotCompiledInException(env);
#endif

    return ret;
}

JNIEXPORT jlong JNICALL
Java_com_wolfssl_wolfcrypt_Sha384_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    jlong ret = 0;

#ifdef WOLFSSL_SHA512
    ret = (jlong) XMALLOC(sizeof(Sha384), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Sha384 object");

    LogStr("new Sha384() = %p\n", (void*)ret);
#else
    throwNotCompiledInException(env);
#endif

    return ret;
}

JNIEXPORT jlong JNICALL
Java_com_wolfssl_wolfcrypt_Sha512_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    jlong ret = 0;

#ifdef WOLFSSL_SHA512
    ret = (jlong) XMALLOC(sizeof(Sha512), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Sha512 object");

    LogStr("new Sha512() = %p\n", (void*)ret);
#else
    throwNotCompiledInException(env);
#endif

    return ret;
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha_initSha(
    JNIEnv* env, jobject this)
{
#ifndef NO_SHA
    int ret = 0;
    Sha* sha = (Sha*) getNativeStruct(env, this);

    ret = (!sha)
        ? BAD_FUNC_ARG
        : wc_InitSha(sha);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha_shaUpdate__Ljava_nio_ByteBuffer_2II(
    JNIEnv* env, jobject this, jobject data_buffer, jint position, jint len)
{
#ifndef NO_SHA
    int ret = 0;
    Sha* sha = (Sha*) getNativeStruct(env, this);
    byte* data = getDirectBufferAddress(env, data_buffer);

    ret = (!sha || !data)
        ? BAD_FUNC_ARG
        : wc_ShaUpdate(sha, data + position, len);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_ShaUpdate(sha=%p, data, len) = %d\n", sha, ret);
    LogStr("data[%u]: [%p]\n", (word32)len, data);
    LogHex(data, 0, len);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha_shaUpdate___3BII(
    JNIEnv* env, jobject this, jbyteArray data_buffer, jint offset, jint len)
{
#ifndef NO_SHA
    int ret = 0;
    Sha* sha = (Sha*) getNativeStruct(env, this);
    byte* data = getByteArray(env, data_buffer);

    ret = (!sha || !data || (offset > len))
        ? BAD_FUNC_ARG
        : wc_ShaUpdate(sha, data + offset, len);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_ShaUpdate_fips(sha=%p, data, len) = %d\n", sha, ret);
    LogStr("data[%u]: [%p]\n", (word32)len, data);
    LogHex(data, 0, len);

    releaseByteArray(env, data_buffer, data, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha_shaFinal__Ljava_nio_ByteBuffer_2I(
    JNIEnv* env, jobject this, jobject hash_buffer, jint position)
{
#ifndef NO_SHA
    int ret = 0;
    Sha* sha = (Sha*) getNativeStruct(env, this);
    byte* hash = getDirectBufferAddress(env, hash_buffer);

    ret = (!sha || !hash)
        ? BAD_FUNC_ARG
        : wc_ShaFinal(sha, hash + position);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_ShaFinal(sha=%p, hash) = %d\n", sha, ret);
    LogStr("hash[%u]: [%p]\n", (word32)SHA_DIGEST_SIZE, hash);
    LogHex(hash, 0, SHA_DIGEST_SIZE);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha_shaFinal___3B(
    JNIEnv* env, jobject this, jbyteArray hash_buffer)
{
#ifndef NO_SHA
    int ret = 0;
    Sha* sha = (Sha*) getNativeStruct(env, this);
    byte* hash = getByteArray(env, hash_buffer);

    ret = (!sha || !hash)
        ? BAD_FUNC_ARG
        : wc_ShaFinal(sha, hash);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_ShaFinal(sha=%p, hash) = %d\n", sha, ret);
    LogStr("hash[%u]: [%p]\n", (word32)SHA_DIGEST_SIZE, hash);
    LogHex(hash, 0, SHA_DIGEST_SIZE);

    releaseByteArray(env, hash_buffer, hash, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha256_initSha256(
    JNIEnv* env, jobject this)
{
#ifndef NO_SHA256
    int ret = 0;
    Sha256* sha = (Sha256*) getNativeStruct(env, this);

    ret = (!sha)
        ? BAD_FUNC_ARG
        : wc_InitSha256(sha);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha256_sha256Update__Ljava_nio_ByteBuffer_2II(
    JNIEnv* env, jobject this, jobject data_buffer, jint position, jint len)
{
#ifndef NO_SHA256
    int ret = 0;
    Sha256* sha = (Sha256*) getNativeStruct(env, this);
    byte* data = getDirectBufferAddress(env, data_buffer);

    ret = (!sha || !data)
        ? BAD_FUNC_ARG
        : wc_Sha256Update(sha, data + position, len);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_Sha256Update(sha=%p, data, len) = %d\n", sha, ret);
    LogStr("data[%u]: [%p]\n", (word32)len, data);
    LogHex(data, 0, len);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha256_sha256Update___3BII(
    JNIEnv* env, jobject this, jbyteArray data_buffer, jint offset,
   jint len)
{
#ifndef NO_SHA256
    int ret = 0;
    Sha256* sha = (Sha256*) getNativeStruct(env, this);
    byte* data = getByteArray(env, data_buffer);

    ret = (!sha || !data || (offset > len))
        ? BAD_FUNC_ARG
        : wc_Sha256Update(sha, data + offset, len);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_Sha256Update(sha=%p, data, len) = %d\n", sha, ret);
    LogStr("data[%u]: [%p]\n", (word32)len, data);
    LogHex(data, 0, len);

    releaseByteArray(env, data_buffer, data, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha256_sha256Final__Ljava_nio_ByteBuffer_2I(
    JNIEnv* env, jobject this, jobject hash_buffer, jint position)
{
#ifndef NO_SHA256
    int ret = 0;
    Sha256* sha = (Sha256*) getNativeStruct(env, this);
    byte* hash = getDirectBufferAddress(env, hash_buffer);

    ret = (!sha || !hash)
        ? BAD_FUNC_ARG
        : wc_Sha256Final(sha, hash + position);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_Sha256Final(sha=%p, hash) = %d\n", sha, ret);
    LogStr("hash[%u]: [%p]\n", (word32)SHA256_DIGEST_SIZE, hash);
    LogHex(hash, 0, SHA256_DIGEST_SIZE);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha256_sha256Final___3B(
    JNIEnv* env, jobject this, jbyteArray hash_buffer)
{
#ifndef NO_SHA256
    int ret = 0;
    Sha256* sha = (Sha256*) getNativeStruct(env, this);
    byte* hash = getByteArray(env, hash_buffer);

    ret = (!sha || !hash)
        ? BAD_FUNC_ARG
        : wc_Sha256Final(sha, hash);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_Sha256Final(sha=%p, hash) = %d\n", sha, ret);
    LogStr("hash[%u]: [%p]\n", (word32)SHA256_DIGEST_SIZE, hash);
    LogHex(hash, 0, SHA256_DIGEST_SIZE);

    releaseByteArray(env, hash_buffer, hash, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha384_initSha384(
    JNIEnv* env, jobject this)
{
#ifdef WOLFSSL_SHA512
    int ret = 0;
    Sha384* sha = (Sha384*) getNativeStruct(env, this);

    ret = (!sha)
        ? BAD_FUNC_ARG
        : wc_InitSha384(sha);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha384_sha384Update__Ljava_nio_ByteBuffer_2II(
    JNIEnv* env, jobject this, jobject data_buffer, jint position, jint len)
{
#ifdef WOLFSSL_SHA512
    int ret = 0;
    Sha384* sha = (Sha384*) getNativeStruct(env, this);
    byte* data = getDirectBufferAddress(env, data_buffer);

    ret = (!sha || !data)
        ? BAD_FUNC_ARG
        : wc_Sha384Update(sha, data + position, len);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_Sha384Update(sha=%p, data, len) = %d\n", sha, ret);
    LogStr("data[%u]: [%p]\n", (word32)len, data);
    LogHex(data, 0, len);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha384_sha384Update___3BII(
    JNIEnv* env, jobject this, jbyteArray data_buffer, jint offset,
   jint len)
{
#ifdef WOLFSSL_SHA512
    int ret = 0;
    Sha384* sha = (Sha384*) getNativeStruct(env, this);
    byte* data = getByteArray(env, data_buffer);

    ret = (!sha || !data || (offset > len))
        ? BAD_FUNC_ARG
        : wc_Sha384Update(sha, data + offset, len);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_Sha384Update(sha=%p, data, len) = %d\n", sha, ret);
    LogStr("data[%u]: [%p]\n", (word32)len, data + offset);
    LogHex(data, offset, len);

    releaseByteArray(env, data_buffer, data, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha384_sha384Final__Ljava_nio_ByteBuffer_2I(
    JNIEnv* env, jobject this, jobject hash_buffer, jint position)
{
#ifdef WOLFSSL_SHA512
    int ret = 0;
    Sha384* sha = (Sha384*) getNativeStruct(env, this);
    byte* hash = getDirectBufferAddress(env, hash_buffer);

    ret = (!sha || !hash)
        ? BAD_FUNC_ARG
        : wc_Sha384Final(sha, hash + position);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_Sha384Final(sha=%p, hash) = %d\n", sha, ret);
    LogStr("hash[%u]: [%p]\n", (word32)SHA384_DIGEST_SIZE, hash);
    LogHex(hash, 0, SHA384_DIGEST_SIZE);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha384_sha384Final___3B(
    JNIEnv* env, jobject this, jbyteArray hash_buffer)
{
#ifdef WOLFSSL_SHA512
    int ret = 0;
    Sha384* sha = (Sha384*) getNativeStruct(env, this);
    byte* hash = getByteArray(env, hash_buffer);

    ret = (!sha || !hash)
        ? BAD_FUNC_ARG
        : wc_Sha384Final(sha, hash);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_Sha384Final(sha=%p, hash) = %d\n", sha, ret);
    LogStr("hash[%u]: [%p]\n", (word32)SHA384_DIGEST_SIZE, hash);
    LogHex(hash, 0, SHA384_DIGEST_SIZE);

    releaseByteArray(env, hash_buffer, hash, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha512_initSha512(
    JNIEnv* env, jobject this)
{
#ifdef WOLFSSL_SHA512
    int ret = 0;
    Sha512* sha = (Sha512*) getNativeStruct(env, this);

    ret = (!sha)
        ? BAD_FUNC_ARG
        : wc_InitSha512(sha);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha512_sha512Update__Ljava_nio_ByteBuffer_2II(
    JNIEnv* env, jobject this, jobject data_buffer, jint position, jint len)
{
#ifdef WOLFSSL_SHA512
    int ret = 0;
    Sha512* sha = (Sha512*) getNativeStruct(env, this);
    byte* data = getDirectBufferAddress(env, data_buffer);

    ret = (!sha || !data)
        ? BAD_FUNC_ARG
        : wc_Sha512Update(sha, data + position, len);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_Sha512Update(sha=%p, data, len) = %d\n", sha, ret);
    LogStr("data[%u]: [%p]\n", (word32)len, data);
    LogHex(data, 0, len);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha512_sha512Update___3BII(
    JNIEnv* env, jobject this, jbyteArray data_buffer, jint offset,
   jint len)
{
#ifdef WOLFSSL_SHA512
    int ret = 0;
    Sha512* sha = (Sha512*) getNativeStruct(env, this);
    byte* data = getByteArray(env, data_buffer);

    ret = (!sha || !data || (offset > len))
        ? BAD_FUNC_ARG
        : wc_Sha512Update(sha, data + offset, len);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_Sha512Update(sha=%p, data, len) = %d\n", sha, ret);
    LogStr("data[%u]: [%p]\n", (word32)len, data + offset);
    LogHex(data, offset, len);

    releaseByteArray(env, data_buffer, data, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha512_sha512Final__Ljava_nio_ByteBuffer_2I(
    JNIEnv* env, jobject this, jobject hash_buffer, jint position)
{
#ifdef WOLFSSL_SHA512
    int ret = 0;
    Sha512* sha = (Sha512*) getNativeStruct(env, this);
    byte* hash = getDirectBufferAddress(env, hash_buffer);

    ret = (!sha || !hash)
        ? BAD_FUNC_ARG
        : wc_Sha512Final(sha, hash + position);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_Sha512Final(sha=%p, hash) = %d\n", sha, ret);
    LogStr("hash[%u]: [%p]\n", (word32)SHA512_DIGEST_SIZE, hash);
    LogHex(hash, 0, SHA512_DIGEST_SIZE);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha512_sha512Final___3B(
    JNIEnv* env, jobject this, jbyteArray hash_buffer)
{
#ifdef WOLFSSL_SHA512
    int ret = 0;
    Sha512* sha = (Sha512*) getNativeStruct(env, this);
    byte* hash = getByteArray(env, hash_buffer);

    ret = (!sha || !hash)
        ? BAD_FUNC_ARG
        : wc_Sha512Final(sha, hash);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_Sha512Final(sha=%p, hash) = %d\n", sha, ret);
    LogStr("hash[%u]: [%p]\n", (word32)SHA512_DIGEST_SIZE, hash);
    LogHex(hash, 0, SHA512_DIGEST_SIZE);

    releaseByteArray(env, hash_buffer, hash, ret);
#else
    throwNotCompiledInException(env);
#endif
}

