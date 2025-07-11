/* jni_aesecb.c
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
#include <wolfssl/wolfcrypt/aes.h>

#include <com_wolfssl_wolfcrypt_AesEcb.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_AesEcb_mallocNativeStruct_1internal(
    JNIEnv* env, jobject this)
{
#if !defined(NO_AES) && defined(HAVE_AES_ECB)
    Aes* aes = NULL;

    aes = (Aes*)XMALLOC(sizeof(Aes), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (aes == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate AesEcb object");
    }
    else {
        XMEMSET(aes, 0, sizeof(Aes));
    }

    LogStr("new AesEcb() = %p\n", aes);

    return (jlong)(uintptr_t)aes;

#else
    throwNotCompiledInException(env);

    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_AesEcb_native_1set_1key_1internal(
    JNIEnv* env, jobject this, jbyteArray key_object, jbyteArray iv_object, jint opmode)
{
#if !defined(NO_AES) && defined(HAVE_AES_ECB)
    int ret = 0;
    Aes* aes  = NULL;
    byte* key = NULL;
    word32 keySz = 0;

    aes = (Aes*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    key = getByteArray(env, key_object);
    keySz = getByteArrayLength(env, key_object);

    /* ECB mode doesn't use IV, so iv_object is ignored */
    if (aes == NULL || key == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = wc_AesSetKey(aes, key, keySz, NULL, opmode);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_AesSetKey(aes=%p, key=%p, iv=NULL, opmode=%d) = %d\n",
        aes, key, opmode, ret);

    releaseByteArray(env, key_object, key, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif /* !NO_AES && HAVE_AES_ECB */
}

JNIEXPORT jint JNICALL
Java_com_wolfssl_wolfcrypt_AesEcb_native_1update_1internal__I_3BII_3BI(
    JNIEnv* env, jobject this, jint opmode,
    jbyteArray input_object, jint offset, jint length,
    jbyteArray output_object, jint outputOffset)
{
    int ret = 0;
#if !defined(NO_AES) && defined(HAVE_AES_ECB)
    Aes*  aes    = NULL;
    byte* input  = NULL;
    byte* output = NULL;

    aes = (Aes*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return 0;
    }

    input  = getByteArray(env, input_object);
    output = getByteArray(env, output_object);

    if (aes == NULL || input == NULL || output == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else if (offset < 0 || length < 0 || outputOffset < 0) {
        ret = BAD_FUNC_ARG;
    }
    else if (length == 0) {
        ret = 0;
    }
    else if ((length % AES_BLOCK_SIZE) != 0) {
        ret = BAD_FUNC_ARG; /* ECB requires block-aligned data */
    }
    else if ((word32)(offset + length) >
             getByteArrayLength(env, input_object)) {
        ret = BUFFER_E; /* buffer overflow check */
    }
    else if ((word32)(outputOffset + length) >
             getByteArrayLength(env, output_object)) {
        ret = BUFFER_E; /* buffer overflow check */
    }
    else if (opmode == AES_ENCRYPTION) {
        ret = wc_AesEcbEncrypt(aes, output+outputOffset, input+offset, length);
        LogStr("wc_AesEcbEncrypt(aes=%p, out, in, inSz) = %d\n", aes, ret);
    }
    else {
        ret = wc_AesEcbDecrypt(aes, output+outputOffset, input+offset, length);
        LogStr("wc_AesEcbDecrypt(aes=%p, out, in, inSz) = %d\n", aes, ret);
    }

    LogStr("input[%u]: [%p]\n", (word32)length, input + offset);
    LogHex((byte*) input, offset, length);
    LogStr("output[%u]: [%p]\n", (word32)length, output + outputOffset);
    LogHex((byte*) output, outputOffset, length);

    releaseByteArray(env, input_object, input, JNI_ABORT);
    releaseByteArray(env, output_object, output, ret);

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        ret = 0; /* 0 bytes stored in output */
    }
    else {
        ret = length;
    }
#else
    throwNotCompiledInException(env);
    ret = NOT_COMPILED_IN;
#endif /* !NO_AES && HAVE_AES_ECB */

    return ret;
}

JNIEXPORT jint JNICALL
Java_com_wolfssl_wolfcrypt_AesEcb_native_1update_1internal__ILjava_nio_ByteBuffer_2IILjava_nio_ByteBuffer_2I(
    JNIEnv* env, jobject this, jint opmode,
    jobject input_object, jint offset, jint length,
    jobject output_object, jint outputOffset)
{
    int ret = 0;

#if !defined(NO_AES) && defined(HAVE_AES_ECB)
    Aes*  aes    = NULL;
    byte* input  = NULL;
    byte* output = NULL;

    aes = (Aes*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return 0;
    }

    input  = getDirectBufferAddress(env, input_object);
    output = getDirectBufferAddress(env, output_object);

    if (aes == NULL || input == NULL || output == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else if (offset < 0 || length < 0) {
        ret = BAD_FUNC_ARG;
    }
    else if ((length % AES_BLOCK_SIZE) != 0) {
        ret = BAD_FUNC_ARG; /* ECB requires block-aligned data */
    }
    else if ((word32)(offset + length) >
             getDirectBufferLimit(env, input_object)) {
        ret = BUFFER_E; /* buffer overflow check */
    }
    else if ((word32)(outputOffset + length) >
             getDirectBufferLimit(env, output_object)) {
        ret = BUFFER_E; /* buffer overflow check */
    }
    else if (opmode == AES_ENCRYPTION) {
        ret = wc_AesEcbEncrypt(aes, output, input + offset, length);
        LogStr("wc_AesEcbEncrypt(aes=%p, out, in, inSz) = %d\n", aes, ret);
    }
    else {
        ret = wc_AesEcbDecrypt(aes, output, input + offset, length);
        LogStr("wc_AesEcbDecrypt(aes=%p, out, in, inSz) = %d\n", aes, ret);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        ret = 0; /* 0 bytes stored in output */
    }
    else {
        ret = length;
    }

    LogStr("input[%u]: [%p]\n", (word32)length, input + offset);
    LogHex((byte*) input, offset, length);
    LogStr("output[%u]: [%p]\n", (word32)length, output);
    LogHex((byte*) output, 0, length);
#else
    throwNotCompiledInException(env);
    ret = NOT_COMPILED_IN;
#endif /* !NO_AES && HAVE_AES_ECB */

    return ret;
}

