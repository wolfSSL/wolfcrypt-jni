/* jni_sha.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <stdint.h>

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#elif !defined(__ANDROID__)
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>

#include <com_wolfssl_wolfcrypt_Sha.h>
#include <com_wolfssl_wolfcrypt_Sha224.h>
#include <com_wolfssl_wolfcrypt_Sha256.h>
#include <com_wolfssl_wolfcrypt_Sha384.h>
#include <com_wolfssl_wolfcrypt_Sha512.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

#ifdef NO_OLD_WC_NAMES
    #ifndef NO_SHA
        #define Sha             wc_Sha
        #define SHA_BLOCK_SIZE  WC_SHA_BLOCK_SIZE
        #define SHA_DIGEST_SIZE WC_SHA_DIGEST_SIZE
        #define SHA_PAD_SIZE    WC_SHA_PAD_SIZE
    #endif
    #ifndef NO_SHA224
        #define Sha224             wc_Sha224
        #define SHA224_BLOCK_SIZE  WC_SHA224_BLOCK_SIZE
        #define SHA224_DIGEST_SIZE WC_SHA224_DIGEST_SIZE
        #define SHA224_PAD_SIZE    WC_SHA224_PAD_SIZE
    #endif
    #ifndef NO_SHA256
        #define Sha256             wc_Sha256
        #define SHA256_BLOCK_SIZE  WC_SHA256_BLOCK_SIZE
        #define SHA256_DIGEST_SIZE WC_SHA256_DIGEST_SIZE
        #define SHA256_PAD_SIZE    WC_SHA256_PAD_SIZE
    #endif
    #ifdef WOLFSSL_SHA384
        #define Sha384             wc_Sha384
        #define SHA384_BLOCK_SIZE  WC_SHA384_BLOCK_SIZE
        #define SHA384_DIGEST_SIZE WC_SHA384_DIGEST_SIZE
        #define SHA384_PAD_SIZE    WC_SHA384_PAD_SIZE
    #endif
    #ifdef WOLFSSL_SHA512
        #define Sha512             wc_Sha512
        #define SHA512_BLOCK_SIZE  WC_SHA512_BLOCK_SIZE
        #define SHA512_DIGEST_SIZE WC_SHA512_DIGEST_SIZE
        #define SHA512_PAD_SIZE    WC_SHA512_PAD_SIZE
    #endif
#endif

JNIEXPORT jlong JNICALL
Java_com_wolfssl_wolfcrypt_Sha_mallocNativeStruct_1internal(
    JNIEnv* env, jobject this)
{
#ifndef NO_SHA
    Sha* sha = NULL;

    sha = (Sha*) XMALLOC(sizeof(Sha), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sha == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate Sha object");
    }
    else {
        XMEMSET(sha, 0, sizeof(Sha));
    }

    LogStr("new Sha() = %p\n", sha);

    return (jlong)(uintptr_t)sha;
#else
    throwNotCompiledInException(env);

    return (jlong)0;
#endif
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Sha224_mallocNativeStruct_1internal
  (JNIEnv* env, jobject this)
{
#ifdef WOLFSSL_SHA224
    Sha224* sha = NULL;

    sha = (Sha224*) XMALLOC(sizeof(Sha224), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sha == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate Sha224 object");
    }
    else {
        XMEMSET(sha, 0, sizeof(Sha224));
    }

    LogStr("new Sha224() = %p\n", sha);

    return (jlong)(uintptr_t)sha;
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);

    return (jlong)0;
#endif
}

JNIEXPORT jlong JNICALL
Java_com_wolfssl_wolfcrypt_Sha256_mallocNativeStruct_1internal(
    JNIEnv* env, jobject this)
{
#ifndef NO_SHA256
    Sha256* sha = NULL;

    sha = (Sha256*) XMALLOC(sizeof(Sha256), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sha == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate Sha256 object");
    }
    else {
        XMEMSET(sha, 0, sizeof(Sha256));
    }

    LogStr("new Sha256() = %p\n", sha);

    return (jlong)(uintptr_t)sha;
#else
    throwNotCompiledInException(env);

    return (jlong)0;
#endif
}

JNIEXPORT jlong JNICALL
Java_com_wolfssl_wolfcrypt_Sha384_mallocNativeStruct_1internal(
    JNIEnv* env, jobject this)
{
#ifdef WOLFSSL_SHA384
    Sha384* sha = NULL;

    sha = (Sha384*) XMALLOC(sizeof(Sha384), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sha == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate Sha384 object");
    }
    else {
        XMEMSET(sha, 0, sizeof(Sha384));
    }

    LogStr("new Sha384() = %p\n", sha);

    return (jlong)(uintptr_t)sha;
#else
    throwNotCompiledInException(env);

    return (jlong)0;
#endif
}

JNIEXPORT jlong JNICALL
Java_com_wolfssl_wolfcrypt_Sha512_mallocNativeStruct_1internal(
    JNIEnv* env, jobject this)
{
#ifdef WOLFSSL_SHA512
    Sha512* sha = NULL;

    sha = (Sha512*) XMALLOC(sizeof(Sha512), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sha == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate Sha512 object");
    }
    else {
        XMEMSET(sha, 0, sizeof(Sha512));
    }

    LogStr("new Sha512() = %p\n", sha);

    return (jlong)(uintptr_t)sha;
#else
    throwNotCompiledInException(env);

    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha_native_1init_1internal(
    JNIEnv* env, jobject this)
{
#ifndef NO_SHA
    int ret = 0;
    Sha* sha = (Sha*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    ret = (!sha)
        ? BAD_FUNC_ARG
        : wc_InitSha(sha);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Sha_native_1copy_1internal
  (JNIEnv* env, jobject this, jobject toBeCopied)
{
#ifndef NO_SHA
    int ret = 0;
    Sha* sha = NULL;
    Sha* tbc = NULL; /* tbc = to be copied */

    if (this == NULL || toBeCopied == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
    }

    sha = (Sha*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    tbc = (Sha*) getNativeStruct(env, toBeCopied);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    ret = wc_ShaCopy(tbc, sha);
    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha_native_1update_1internal__Ljava_nio_ByteBuffer_2II(
    JNIEnv* env, jobject this, jobject data_buffer, jint position, jint len)
{
#ifndef NO_SHA
    int ret = 0;
    Sha*  sha  = NULL;
    byte* data = NULL;

    sha = (Sha*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    data = getDirectBufferAddress(env, data_buffer);

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
Java_com_wolfssl_wolfcrypt_Sha_native_1update_1internal___3BII(
    JNIEnv* env, jobject this, jbyteArray data_buffer, jint offset, jint len)
{
#ifndef NO_SHA
    int ret = 0;
    Sha*  sha  = NULL;
    byte* data = NULL;
    word32 dataSz = 0;

    sha = (Sha*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    data   = getByteArray(env, data_buffer);
    dataSz = getByteArrayLength(env, data_buffer);

    if (sha == NULL || data == NULL ||
        (word32)(offset + len) > dataSz) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_ShaUpdate(sha, data + offset, len);
    }

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_ShaUpdate_fips(sha=%p, data, len) = %d\n", sha, ret);
    LogStr("data[%u]: [%p]\n", (word32)len, data);
    LogHex(data, offset, len);

    releaseByteArray(env, data_buffer, data, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha_native_1final_1internal__Ljava_nio_ByteBuffer_2I(
    JNIEnv* env, jobject this, jobject hash_buffer, jint position)
{
#ifndef NO_SHA
    int ret = 0;
    Sha*  sha  = NULL;
    byte* hash = NULL;

    sha = (Sha*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    hash = getDirectBufferAddress(env, hash_buffer);

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
Java_com_wolfssl_wolfcrypt_Sha_native_1final_1internal___3B(
    JNIEnv* env, jobject this, jbyteArray hash_buffer)
{
#ifndef NO_SHA
    int ret = 0;
    Sha*  sha  = NULL;
    byte* hash = NULL;

    sha = (Sha*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    hash = getByteArray(env, hash_buffer);

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
Java_com_wolfssl_wolfcrypt_Sha256_native_1init_1internal(
    JNIEnv* env, jobject this)
{
#ifndef NO_SHA256
    int ret = 0;
    Sha256* sha = (Sha256*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    ret = (!sha)
        ? BAD_FUNC_ARG
        : wc_InitSha256(sha);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Sha256_native_1copy_1internal
  (JNIEnv* env, jobject this, jobject toBeCopied)
{
#ifndef NO_SHA256
    int ret = 0;
    Sha256* sha = NULL;
    Sha256* tbc = NULL; /* tbc = to be copied */

    if (this == NULL || toBeCopied == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
    }

    sha = (Sha256*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    tbc = (Sha256*) getNativeStruct(env, toBeCopied);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    ret = wc_Sha256Copy(tbc, sha);
    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha256_native_1update_1internal__Ljava_nio_ByteBuffer_2II(
    JNIEnv* env, jobject this, jobject data_buffer, jint position, jint len)
{
#ifndef NO_SHA256
    int ret = 0;
    Sha256* sha = NULL;
    byte*  data = NULL;

    sha = (Sha256*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    data = getDirectBufferAddress(env, data_buffer);

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
Java_com_wolfssl_wolfcrypt_Sha256_native_1update_1internal___3BII(
    JNIEnv* env, jobject this, jbyteArray data_buffer, jint offset,
    jint len)
{
#ifndef NO_SHA256
    int ret = 0;
    Sha256* sha = NULL;
    byte*  data = NULL;
    word32 dataSz = 0;

    sha = (Sha256*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    data   = getByteArray(env, data_buffer);
    dataSz = getByteArrayLength(env, data_buffer);

    if (sha == NULL || data == NULL ||
        (word32)(offset + len) > dataSz) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_Sha256Update(sha, data + offset, len);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_Sha256Update(sha=%p, data, len) = %d\n", sha, ret);
    LogStr("data[%u]: [%p]\n", (word32)len, data);
    LogHex(data, 0, len);

    releaseByteArray(env, data_buffer, data, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha256_native_1final_1internal__Ljava_nio_ByteBuffer_2I(
    JNIEnv* env, jobject this, jobject hash_buffer, jint position)
{
#ifndef NO_SHA256
    int ret = 0;
    Sha256* sha = NULL;
    byte*  hash = NULL;

    sha = (Sha256*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    hash = getDirectBufferAddress(env, hash_buffer);

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
Java_com_wolfssl_wolfcrypt_Sha256_native_1final_1internal___3B(
    JNIEnv* env, jobject this, jbyteArray hash_buffer)
{
#ifndef NO_SHA256
    int ret = 0;
    Sha256* sha = NULL;
    byte*  hash = NULL;

    sha = (Sha256*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    hash = getByteArray(env, hash_buffer);

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
Java_com_wolfssl_wolfcrypt_Sha384_native_1init_1internal(
    JNIEnv* env, jobject this)
{
#ifdef WOLFSSL_SHA384
    int ret = 0;
    Sha384* sha = (Sha384*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    ret = (!sha)
        ? BAD_FUNC_ARG
        : wc_InitSha384(sha);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Sha384_native_1copy_1internal
  (JNIEnv* env, jobject this, jobject toBeCopied)
{
#ifdef WOLFSSL_SHA384
    int ret = 0;
    Sha384* sha = NULL;
    Sha384* tbc = NULL; /* tbc = to be copied */

    if (this == NULL || toBeCopied == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
    }

    sha = (Sha384*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    tbc = (Sha384*) getNativeStruct(env, toBeCopied);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    ret = wc_Sha384Copy(tbc, sha);
    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha384_native_1update_1internal__Ljava_nio_ByteBuffer_2II(
    JNIEnv* env, jobject this, jobject data_buffer, jint position, jint len)
{
#ifdef WOLFSSL_SHA384
    int ret = 0;
    Sha384* sha = NULL;
    byte*  data = NULL;

    sha = (Sha384*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    data = getDirectBufferAddress(env, data_buffer);

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
Java_com_wolfssl_wolfcrypt_Sha384_native_1update_1internal___3BII(
    JNIEnv* env, jobject this, jbyteArray data_buffer, jint offset, jint len)
{
#ifdef WOLFSSL_SHA384
    int ret = 0;
    Sha384* sha = NULL;
    byte*  data = NULL;
    word32 dataSz = 0;

    sha = (Sha384*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    data   = getByteArray(env, data_buffer);
    dataSz = getByteArrayLength(env, data_buffer);

    if (sha == NULL || data == NULL ||
        (word32)(offset + len) > dataSz) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_Sha384Update(sha, data + offset, len);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_Sha384Update(sha=%p, data, len) = %d\n", sha, ret);
    LogStr("data[%u]: [%p]\n", (word32)len, data + offset);
    LogHex(data, offset, len);

    releaseByteArray(env, data_buffer, data, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha384_native_1final_1internal__Ljava_nio_ByteBuffer_2I(
    JNIEnv* env, jobject this, jobject hash_buffer, jint position)
{
#ifdef WOLFSSL_SHA384
    int ret = 0;
    Sha384* sha = NULL;
    byte*  hash = NULL;

    sha = (Sha384*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    hash = getDirectBufferAddress(env, hash_buffer);

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
Java_com_wolfssl_wolfcrypt_Sha384_native_1final_1internal___3B(
    JNIEnv* env, jobject this, jbyteArray hash_buffer)
{
#ifdef WOLFSSL_SHA384
    int ret = 0;
    Sha384* sha = NULL;
    byte*  hash = NULL;

    sha = (Sha384*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    hash = getByteArray(env, hash_buffer);

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
Java_com_wolfssl_wolfcrypt_Sha512_native_1init_1internal(
    JNIEnv* env, jobject this)
{
#ifdef WOLFSSL_SHA512
    int ret = 0;
    Sha512* sha = (Sha512*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    ret = (!sha)
        ? BAD_FUNC_ARG
        : wc_InitSha512(sha);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Sha512_native_1copy_1internal
  (JNIEnv* env, jobject this, jobject toBeCopied)
{
#ifdef WOLFSSL_SHA512
    int ret = 0;
    Sha512* sha = NULL;
    Sha512* tbc = NULL; /* tbc = to be copied */

    if (this == NULL || toBeCopied == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
    }

    sha = (Sha512*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    tbc = (Sha512*) getNativeStruct(env, toBeCopied);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    ret = wc_Sha512Copy(tbc, sha);
    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha512_native_1update_1internal__Ljava_nio_ByteBuffer_2II(
    JNIEnv* env, jobject this, jobject data_buffer, jint position, jint len)
{
#ifdef WOLFSSL_SHA512
    int ret = 0;
    Sha512* sha = NULL;
    byte*  data = NULL;

    sha = (Sha512*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    data = getDirectBufferAddress(env, data_buffer);

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
Java_com_wolfssl_wolfcrypt_Sha512_native_1update_1internal___3BII(
    JNIEnv* env, jobject this, jbyteArray data_buffer, jint offset,
    jint len)
{
#ifdef WOLFSSL_SHA512
    int ret = 0;
    Sha512* sha = NULL;
    byte*  data = NULL;
    word32 dataSz = 0;

    sha = (Sha512*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    data   = getByteArray(env, data_buffer);
    dataSz = getByteArrayLength(env, data_buffer);

    if (sha == NULL || data == NULL ||
        (word32)(offset + len) > dataSz) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_Sha512Update(sha, data + offset, len);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_Sha512Update(sha=%p, data, len) = %d\n", sha, ret);
    LogStr("data[%u]: [%p]\n", (word32)len, data + offset);
    LogHex(data, offset, len);

    releaseByteArray(env, data_buffer, data, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Sha512_native_1final_1internal__Ljava_nio_ByteBuffer_2I(
    JNIEnv* env, jobject this, jobject hash_buffer, jint position)
{
#ifdef WOLFSSL_SHA512
    int ret = 0;
    Sha512* sha = NULL;
    byte*  hash = NULL;

    sha = (Sha512*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    hash = getDirectBufferAddress(env, hash_buffer);

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
Java_com_wolfssl_wolfcrypt_Sha512_native_1final_1internal___3B(
    JNIEnv* env, jobject this, jbyteArray hash_buffer)
{
#ifdef WOLFSSL_SHA512
    int ret = 0;
    Sha512* sha = NULL;
    byte*  hash = NULL;

    sha = (Sha512*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    hash = getByteArray(env, hash_buffer);

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

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Sha224_native_1init_1internal
  (JNIEnv* env, jobject this)
{
#ifdef WOLFSSL_SHA224
    int ret = 0;
    Sha224* sha = (Sha224*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    if (sha == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_InitSha224(sha);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Sha224_native_1copy_1internal
  (JNIEnv* env, jobject this, jobject toBeCopied)
{
#ifdef WOLFSSL_SHA224
    int ret = 0;
    Sha224* sha = NULL;
    Sha224* tbc = NULL; /* tbc = to be copied */

    if (this == NULL || toBeCopied == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return;
    }

    sha = (Sha224*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    tbc = (Sha224*) getNativeStruct(env, toBeCopied);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    ret = wc_Sha224Copy(tbc, sha);
    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Sha224_native_1update_1internal__Ljava_nio_ByteBuffer_2II
  (JNIEnv* env, jobject this, jobject data_buffer, jint position, jint len)
{
#ifdef WOLFSSL_SHA224
    int ret = 0;
    Sha224* sha = NULL;
    byte*  data = NULL;

    sha = (Sha224*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    data = getDirectBufferAddress(env, data_buffer);

    if (sha == NULL || data == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_Sha224Update(sha, data + position, len);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_Sha224Update(sha=%p, data, len) = %d\n", sha, ret);
    LogStr("data[%u]: [%p]\n", (word32)len, data);
    LogHex(data, 0, len);
#else
    (void)env;
    (void)this;
    (void)data_buffer;
    (void)position;
    (void)len;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Sha224_native_1update_1internal___3BII
  (JNIEnv* env, jobject this, jbyteArray data_buffer, jint offset, jint len)
{
#ifdef WOLFSSL_SHA224
    int ret = 0;
    Sha224* sha = NULL;
    byte*  data = NULL;
    word32 dataSz = 0;

    sha = (Sha224*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    data   = getByteArray(env, data_buffer);
    dataSz = getByteArrayLength(env, data_buffer);

    if (sha == NULL || data == NULL ||
        (word32)(offset + len) > dataSz) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_Sha224Update(sha, data + offset, len);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_Sha224Update(sha=%p, data, len) = %d\n", sha, ret);
    LogStr("data[%u]: [%p]\n", (word32)len, data + offset);
    LogHex(data, offset, len);

    releaseByteArray(env, data_buffer, data, JNI_ABORT);
#else
    (void)env;
    (void)this;
    (void)data_buffer;
    (void)offset;
    (void)len;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Sha224_native_1final_1internal__Ljava_nio_ByteBuffer_2I
  (JNIEnv* env, jobject this, jobject hash_buffer, jint position)
{
#ifdef WOLFSSL_SHA224
    int ret = 0;
    Sha224* sha = NULL;
    byte*  hash = NULL;

    sha = (Sha224*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    hash = getDirectBufferAddress(env, hash_buffer);

    if (sha == NULL || hash == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_Sha224Final(sha, hash + position);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_Sha224Final(sha=%p, hash) = %d\n", sha, ret);
    LogStr("hash[%u]: [%p]\n", (word32)SHA224_DIGEST_SIZE, hash);
    LogHex(hash, 0, SHA224_DIGEST_SIZE);
#else
    (void)env;
    (void)this;
    (void)hash_buffer;
    (void)position;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Sha224_native_1final_1internal___3B
  (JNIEnv* env, jobject this, jbyteArray hash_buffer)
{
#ifdef WOLFSSL_SHA224
    int ret = 0;
    Sha224* sha = NULL;
    byte*  hash = NULL;

    sha = (Sha224*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    hash = getByteArray(env, hash_buffer);

    if (sha == NULL || hash == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_Sha224Final(sha, hash);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_Sha224Final(sha=%p, hash) = %d\n", sha, ret);
    LogStr("hash[%u]: [%p]\n", (word32)SHA224_DIGEST_SIZE, hash);
    LogHex(hash, 0, SHA224_DIGEST_SIZE);

    releaseByteArray(env, hash_buffer, hash, ret);
#else
    (void)env;
    (void)this;
    (void)hash_buffer;
    throwNotCompiledInException(env);
#endif
}

