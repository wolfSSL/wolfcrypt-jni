/* jni_aesofb.c
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

#include <com_wolfssl_wolfcrypt_AesOfb.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_AesOfb_mallocNativeStruct_1internal(
    JNIEnv* env, jobject this)
{
#if !defined(NO_AES) && defined(WOLFSSL_AES_OFB)
    Aes* aes = NULL;

    aes = (Aes*)XMALLOC(sizeof(Aes), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (aes == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate AesOfb object");
    }
    else {
        XMEMSET(aes, 0, sizeof(Aes));
    }

    LogStr("new AesOfb() = %p\n", aes);

    return (jlong)(uintptr_t)aes;

#else
    throwNotCompiledInException(env);

    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_AesOfb_native_1set_1key_1internal(
    JNIEnv* env, jobject this, jbyteArray key_object, jbyteArray iv_object,
    jint opmode)
{
#if !defined(NO_AES) && defined(WOLFSSL_AES_OFB)
    int ret = 0;
    Aes* aes  = NULL;
    byte* key = NULL;
    byte* iv  = NULL;
    word32 keySz = 0;

    aes = (Aes*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    key = getByteArray(env, key_object);
    iv  = getByteArray(env, iv_object);
    keySz = getByteArrayLength(env, key_object);

    if (aes == NULL || key == NULL || iv == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = wc_AesSetKey(aes, key, keySz, iv, opmode);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_AesSetKey(aes=%p, key=%p, iv=%p, opmode=%d) = %d\n",
        aes, key, iv, opmode, ret);

    releaseByteArray(env, key_object, key, JNI_ABORT);
    releaseByteArray(env, iv_object, iv, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif /* !NO_AES && WOLFSSL_AES_OFB */
}

JNIEXPORT jint JNICALL
Java_com_wolfssl_wolfcrypt_AesOfb_native_1update_1internal__I_3BII_3BI(
    JNIEnv* env, jobject this, jint opmode,
    jbyteArray input_object, jint offset, jint length,
    jbyteArray output_object, jint outputOffset)
{
    int ret = 0;
#if !defined(NO_AES) && defined(WOLFSSL_AES_OFB)
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
    else if ((word32)(offset + length) >
             getByteArrayLength(env, input_object)) {
        ret = BUFFER_E; /* buffer overflow check */
    }
    else if ((word32)(outputOffset + length) >
             getByteArrayLength(env, output_object)) {
        ret = BUFFER_E; /* buffer overflow check */
    }
    else if (opmode == AES_ENCRYPTION) {
        ret = wc_AesOfbEncrypt(aes, output+outputOffset, input+offset, length);
        LogStr("wc_AesOfbEncrypt(aes=%p, out, in, inSz) = %d\n", aes, ret);
    }
    else {
#ifdef HAVE_AES_DECRYPT
        ret = wc_AesOfbDecrypt(aes, output+outputOffset, input+offset, length);
        LogStr("wc_AesOfbDecrypt(aes=%p, out, in, inSz) = %d\n", aes, ret);
#else
        /* If HAVE_AES_DECRYPT not defined, fall back to encrypt
         * (OFB mode uses same operation for both) */
        ret = wc_AesOfbEncrypt(aes, output+outputOffset, input+offset, length);
        LogStr("wc_AesOfbEncrypt(aes=%p, out, in, inSz) = %d\n", aes, ret);
#endif
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
#endif /* !NO_AES && WOLFSSL_AES_OFB */

    return ret;
}


JNIEXPORT jint JNICALL
Java_com_wolfssl_wolfcrypt_AesOfb_native_1update_1internal__ILjava_nio_ByteBuffer_2IILjava_nio_ByteBuffer_2I(
    JNIEnv* env, jobject this, jint opmode,
    jobject input_object, jint offset, jint length,
    jobject output_object, jint outputOffset)
{
    int ret = 0;

#if !defined(NO_AES) && defined(WOLFSSL_AES_OFB)
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
    else if ((word32)(offset + length) >
             getDirectBufferLimit(env, input_object)) {
        ret = BUFFER_E; /* buffer overflow check */
    }
    else if ((word32)(outputOffset + length) >
             getDirectBufferLimit(env, output_object)) {
        ret = BUFFER_E; /* buffer overflow check */
    }
    else if (opmode == AES_ENCRYPTION) {
        ret = wc_AesOfbEncrypt(aes, output, input + offset, length);
        LogStr("wc_AesOfbEncrypt(aes=%p, out, in, inSz) = %d\n", aes, ret);
    }
    else {
#ifdef HAVE_AES_DECRYPT
        ret = wc_AesOfbDecrypt(aes, output, input + offset, length);
        LogStr("wc_AesOfbDecrypt(aes=%p, out, in, inSz) = %d\n", aes, ret);
#else
        /* If HAVE_AES_DECRYPT not defined, fall back to encrypt
         * (OFB mode uses same operation for both) */
        ret = wc_AesOfbEncrypt(aes, output, input + offset, length);
        LogStr("wc_AesOfbEncrypt(aes=%p, out, in, inSz) = %d\n", aes, ret);
#endif
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
#endif

    return ret;
}
JNIEXPORT jint JNICALL
Java_com_wolfssl_wolfcrypt_AesOfb_native_1encrypt_1internal___3BII_3BI(
    JNIEnv* env, jobject this,
    jbyteArray input_object, jint offset, jint length,
    jbyteArray output_object, jint outputOffset)
{
    return Java_com_wolfssl_wolfcrypt_AesOfb_native_1update_1internal__I_3BII_3BI(
        env, this, AES_ENCRYPTION, input_object, offset, length,
        output_object, outputOffset);
}

JNIEXPORT jint JNICALL
Java_com_wolfssl_wolfcrypt_AesOfb_native_1decrypt_1internal___3BII_3BI(
    JNIEnv* env, jobject this,
    jbyteArray input_object, jint offset, jint length,
    jbyteArray output_object, jint outputOffset)
{
    return Java_com_wolfssl_wolfcrypt_AesOfb_native_1update_1internal__I_3BII_3BI(
        env, this, AES_DECRYPTION, input_object, offset, length,
        output_object, outputOffset);
}

JNIEXPORT jint JNICALL
Java_com_wolfssl_wolfcrypt_AesOfb_native_1encrypt_1internal__Ljava_nio_ByteBuffer_2IILjava_nio_ByteBuffer_2I(
    JNIEnv* env, jobject this,
    jobject input_object, jint offset, jint length,
    jobject output_object, jint outputOffset)
{
    return Java_com_wolfssl_wolfcrypt_AesOfb_native_1update_1internal__ILjava_nio_ByteBuffer_2IILjava_nio_ByteBuffer_2I(
        env, this, AES_ENCRYPTION, input_object, offset, length,
        output_object, outputOffset);
}

JNIEXPORT jint JNICALL
Java_com_wolfssl_wolfcrypt_AesOfb_native_1decrypt_1internal__Ljava_nio_ByteBuffer_2IILjava_nio_ByteBuffer_2I(
    JNIEnv* env, jobject this,
    jobject input_object, jint offset, jint length,
    jobject output_object, jint outputOffset)
{
    return Java_com_wolfssl_wolfcrypt_AesOfb_native_1update_1internal__ILjava_nio_ByteBuffer_2IILjava_nio_ByteBuffer_2I(
        env, this, AES_DECRYPTION, input_object, offset, length,
        output_object, outputOffset);
}

