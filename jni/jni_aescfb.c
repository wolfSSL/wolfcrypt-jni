/* jni_aescfb.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

#include <com_wolfssl_wolfcrypt_AesCfb.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

#if !defined(NO_AES) && defined(WOLFSSL_AES_CFB)

/* CFB segment sizes, must match constants in AesCfb.java */
#define CFB_JNI_MODE_128 128
#define CFB_JNI_MODE_8     8
#define CFB_JNI_MODE_1     1

/* Max bytes per wc_AesCfb1* call, keeps bit count (sz * 8) from
 * overflowing word32 */
#define CFB1_JNI_MAX_CHUNK 0x0FFFFFFFU

/* Run one AES-CFB operation, dispatching on segment size and direction.
 * Feedback state lives in the Aes struct, so the chunked CFB1 calls below
 * chain correctly. Returns 0 on success, negative on failure. */
static int AesCfbRunUpdate(Aes* aes, jint cfbMode, jint opmode,
    byte* out, const byte* in, word32 sz)
{
    int ret = 0;
#ifndef WOLFSSL_NO_AES_CFB_1_8
    word32 idx = 0;
    word32 chunk = 0;
#endif

    switch (cfbMode) {
        case CFB_JNI_MODE_128:
            if (opmode == AES_ENCRYPTION) {
                ret = wc_AesCfbEncrypt(aes, out, in, sz);
            }
            else {
            #ifdef HAVE_AES_DECRYPT
                ret = wc_AesCfbDecrypt(aes, out, in, sz);
            #else
                ret = NOT_COMPILED_IN;
            #endif
            }
            break;

    #ifndef WOLFSSL_NO_AES_CFB_1_8
        case CFB_JNI_MODE_8:
            if (opmode == AES_ENCRYPTION) {
                ret = wc_AesCfb8Encrypt(aes, out, in, sz);
            }
            else {
            #ifdef HAVE_AES_DECRYPT
                ret = wc_AesCfb8Decrypt(aes, out, in, sz);
            #else
                ret = NOT_COMPILED_IN;
            #endif
            }
            break;

        case CFB_JNI_MODE_1:
            /* Native CFB1 API takes size in bits */
            while ((ret == 0) && (idx < sz)) {
                chunk = sz - idx;
                if (chunk > CFB1_JNI_MAX_CHUNK) {
                    chunk = CFB1_JNI_MAX_CHUNK;
                }
                if (opmode == AES_ENCRYPTION) {
                    ret = wc_AesCfb1Encrypt(aes, out + idx, in + idx,
                        chunk * 8U);
                }
                else {
                #ifdef HAVE_AES_DECRYPT
                    ret = wc_AesCfb1Decrypt(aes, out + idx, in + idx,
                        chunk * 8U);
                #else
                    ret = NOT_COMPILED_IN;
                #endif
                }
                idx += chunk;
            }
            break;
    #endif /* !WOLFSSL_NO_AES_CFB_1_8 */

        default:
            ret = BAD_FUNC_ARG;
            break;
    }

    return ret;
}

#endif /* !NO_AES && WOLFSSL_AES_CFB */

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_AesCfb_mallocNativeStruct_1internal(
    JNIEnv* env, jobject this)
{
#if !defined(NO_AES) && defined(WOLFSSL_AES_CFB)
    Aes* aes = NULL;
    (void)this;

    aes = (Aes*)XMALLOC(sizeof(Aes), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (aes == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate AesCfb object");
    }
    else {
        XMEMSET(aes, 0, sizeof(Aes));
    }

    LogStr("new AesCfb() = %p\n", aes);

    return (jlong)(uintptr_t)aes;

#else
    (void)this;
    throwNotCompiledInException(env);

    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesCfb_wc_1AesInit(
    JNIEnv* env, jobject this)
{
#if !defined(NO_AES) && defined(WOLFSSL_AES_CFB)
    int ret = 0;
    Aes* aes = NULL;

    aes = (Aes*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, if so stop and return */
        return;
    }

    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_AesInit(aes=%p) = %d\n", aes, ret);
#else
    (void)this;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesCfb_wc_1AesFree(
    JNIEnv* env, jobject this)
{
#if !defined(NO_AES) && defined(WOLFSSL_AES_CFB)
    Aes* aes = NULL;

    aes = (Aes*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, if so stop and return */
        return;
    }

    wc_AesFree(aes);

    LogStr("wc_AesFree(aes=%p)\n", aes);
#else
    (void)this;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesCfb_native_1set_1key_1internal(
    JNIEnv* env, jobject this, jbyteArray key_object, jbyteArray iv_object)
{
#if !defined(NO_AES) && defined(WOLFSSL_AES_CFB)
    int ret = 0;
    Aes* aes  = NULL;
    byte* key = NULL;
    byte* iv  = NULL;
    word32 keySz = 0;
    jboolean keyIsCopy = JNI_FALSE;

    aes = (Aes*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    key = getByteArrayIsCopy(env, key_object, &keyIsCopy);
    if ((*env)->ExceptionOccurred(env)) {
        /* GetByteArrayElements failed, leave its exception pending */
        return;
    }
    keySz = getByteArrayLength(env, key_object);

    iv = getByteArray(env, iv_object);
    if ((*env)->ExceptionOccurred(env)) {
        zeroizeByteArrayCopy(key, keySz, keyIsCopy);
        releaseByteArray(env, key_object, key, JNI_ABORT);
        return;
    }

    if (aes == NULL || key == NULL || iv == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else if (getByteArrayLength(env, iv_object) != AES_BLOCK_SIZE) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* CFB uses the forward AES transform for both directions */
        ret = wc_AesSetKey(aes, key, keySz, iv, AES_ENCRYPTION);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_AesSetKey(aes=%p, key=%p, iv=%p, AES_ENCRYPTION) = %d\n",
        aes, key, iv, ret);

    /* Zeroize native key copy before JNI release */
    zeroizeByteArrayCopy(key, keySz, keyIsCopy);
    releaseByteArray(env, key_object, key, JNI_ABORT);
    releaseByteArray(env, iv_object, iv, JNI_ABORT);
#else
    (void)this;
    (void)key_object;
    (void)iv_object;
    throwNotCompiledInException(env);
#endif /* !NO_AES && WOLFSSL_AES_CFB */
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_AesCfb_native_1update_1internal__II_3BII_3BI(
    JNIEnv* env, jobject this, jint cfbMode, jint opmode,
    jbyteArray input_object, jint offset, jint length,
    jbyteArray output_object, jint outputOffset)
{
    int ret = 0;
#if !defined(NO_AES) && defined(WOLFSSL_AES_CFB)
    Aes*  aes    = NULL;
    byte* input  = NULL;
    byte* output = NULL;

    aes = (Aes*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return 0;
    }

    input = getByteArray(env, input_object);
    if ((*env)->ExceptionOccurred(env)) {
        /* GetByteArrayElements failed, leave its exception pending */
        return 0;
    }

    output = getByteArray(env, output_object);
    if ((*env)->ExceptionOccurred(env)) {
        releaseByteArray(env, input_object, input, JNI_ABORT);
        return 0;
    }

    if (aes == NULL || input == NULL || output == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else if (offset < 0 || length < 0 || outputOffset < 0) {
        ret = BAD_FUNC_ARG;
    }
    else if (length == 0) {
        ret = 0;
    }
    else if (((jlong)offset + (jlong)length) >
        getByteArrayLength(env, input_object)) {
        ret = BUFFER_E; /* buffer overflow check */
    }
    else if (((jlong)outputOffset + (jlong)length) >
        getByteArrayLength(env, output_object)) {
        ret = BUFFER_E; /* buffer overflow check */
    }
    else {
        ret = AesCfbRunUpdate(aes, cfbMode, opmode, output + outputOffset,
            input + offset, (word32)length);
        LogStr("AesCfbRunUpdate(aes=%p, mode=%d, dir=%d, sz=%d) = %d\n",
            aes, (int)cfbMode, (int)opmode, (int)length, ret);
    }

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
    (void)cfbMode;
    (void)opmode;
    (void)input_object;
    (void)offset;
    (void)length;
    (void)output_object;
    (void)outputOffset;
    throwNotCompiledInException(env);
    ret = NOT_COMPILED_IN;
#endif /* !NO_AES && WOLFSSL_AES_CFB */

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_AesCfb_native_1update_1internal__IILjava_nio_ByteBuffer_2IILjava_nio_ByteBuffer_2I(
    JNIEnv* env, jobject this, jint cfbMode, jint opmode,
    jobject input_object, jint offset, jint length,
    jobject output_object, jint outputOffset)
{
    int ret = 0;

#if !defined(NO_AES) && defined(WOLFSSL_AES_CFB)
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
    else if (offset < 0 || length < 0 || outputOffset < 0) {
        ret = BAD_FUNC_ARG;
    }
    else if (length == 0) {
        ret = 0;
    }
    else if (((jlong)offset + (jlong)length) >
        getDirectBufferLimit(env, input_object)) {
        ret = BUFFER_E; /* buffer overflow check */
    }
    else if (((jlong)outputOffset + (jlong)length) >
        getDirectBufferLimit(env, output_object)) {
        ret = BUFFER_E; /* buffer overflow check */
    }
    else {
        ret = AesCfbRunUpdate(aes, cfbMode, opmode, output + outputOffset,
            input + offset, (word32)length);
        LogStr("AesCfbRunUpdate(aes=%p, mode=%d, dir=%d, sz=%d) = %d\n",
            aes, (int)cfbMode, (int)opmode, (int)length, ret);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        ret = 0; /* 0 bytes stored in output */
    }
    else {
        ret = length;
    }
#else
    (void)cfbMode;
    (void)opmode;
    (void)input_object;
    (void)offset;
    (void)length;
    (void)output_object;
    (void)outputOffset;
    throwNotCompiledInException(env);
    ret = NOT_COMPILED_IN;
#endif /* !NO_AES && WOLFSSL_AES_CFB */

    return ret;
}

