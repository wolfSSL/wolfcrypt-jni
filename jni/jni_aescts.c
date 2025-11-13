/* jni_aescts.c
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
#include <wolfssl/openssl/aes.h>
#include <wolfssl/openssl/modes.h>

#include <com_wolfssl_wolfcrypt_AesCts.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_CTS) && \
    !defined(WOLFSSL_NO_OPENSSL_AES_LOW_LEVEL_API)

/* Wrapper structure to hold AES_KEY and IV for CTS operations */
typedef struct {
    AES_KEY key;
    byte iv[AES_BLOCK_SIZE];
} AesCtsCtx;


#endif /* OPENSSL_EXTRA && !NO_AES && HAVE_CTS */

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_AesCts_mallocNativeStruct_1internal
  (JNIEnv* env, jobject this)
{
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_CTS) && \
    !defined(WOLFSSL_NO_OPENSSL_AES_LOW_LEVEL_API)
    AesCtsCtx* ctx = NULL;

    ctx = (AesCtsCtx*)XMALLOC(sizeof(AesCtsCtx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate AesCts object");
    }
    else {
        XMEMSET(ctx, 0, sizeof(AesCtsCtx));
    }

    LogStr("new AesCts() = %p\n", ctx);

    return (jlong)(uintptr_t)ctx;

#else
    throwNotCompiledInException(env);

    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesCts_native_1set_1key_1internal
  (JNIEnv* env, jobject this, jbyteArray key_object, jbyteArray iv_object, jint opmode)
{
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_CTS) && \
    !defined(WOLFSSL_NO_OPENSSL_AES_LOW_LEVEL_API)
    int ret = 0;
    AesCtsCtx* ctx = NULL;
    byte* key = NULL;
    byte* iv  = NULL;
    word32 keySz = 0;

    ctx = (AesCtsCtx*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    key = getByteArray(env, key_object);
    iv  = getByteArray(env, iv_object);
    keySz = getByteArrayLength(env, key_object);

    if (ctx == NULL || key == NULL || iv == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Initialize AES_KEY structure using OpenSSL-compatible functions.
         * CTS uses CBC mode internally. */
        if (opmode == 0) {
            /* ENCRYPT_MODE */
            ret = AES_set_encrypt_key(key, keySz * 8, &ctx->key);
        }
        else {
            /* DECRYPT_MODE */
            ret = AES_set_decrypt_key(key, keySz * 8, &ctx->key);
        }

        /* Store IV for use in update operations */
        if (ret == 0) {
            XMEMCPY(ctx->iv, iv, AES_BLOCK_SIZE);
        }
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("AES_set_key(ctx=%p, keySz=%d, mode=%d) = %d\n",
        ctx, keySz, opmode, ret);

    releaseByteArray(env, key_object, key, JNI_ABORT);
    releaseByteArray(env, iv_object, iv, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif /* !NO_AES && HAVE_CTS */
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_AesCts_native_1update_1internal__I_3BII_3BI
  (JNIEnv* env, jobject this, jint opmode, jbyteArray input_object, jint offset, jint length, jbyteArray output_object, jint outputOffset)
{
    int ret = 0;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_CTS) && \
    !defined(WOLFSSL_NO_OPENSSL_AES_LOW_LEVEL_API)
    AesCtsCtx* ctx    = NULL;
    byte* input  = NULL;
    byte* output = NULL;
    byte  iv[AES_BLOCK_SIZE];
    size_t outLen = 0;

    ctx = (AesCtsCtx*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return 0;
    }

    input  = getByteArray(env, input_object);
    output = getByteArray(env, output_object);

    if (ctx == NULL || input == NULL || output == NULL ||
        offset < 0 || length < 0 || outputOffset < 0) {
        ret = BAD_FUNC_ARG;
    }
    else if (length < AES_BLOCK_SIZE) {
        /* CTS requires at least one block of input */
        ret = BUFFER_E;
    }
    else if ((word32)(offset + length) >
        getByteArrayLength(env, input_object)) {
        ret = BUFFER_E; /* buffer overflow check */
    }
    else if ((word32)(outputOffset + length) >
        getByteArrayLength(env, output_object)) {
        ret = BUFFER_E; /* buffer overflow check */
    }
    else {
        /* Make a copy of the stored IV. CTS functions modify the IV during
         * operation, so we use a local copy to preserve the original. */
        XMEMCPY(iv, ctx->iv, AES_BLOCK_SIZE);

        LogStr("update called: ctx=%p, opmode=%d, length=%d\n",
            ctx, opmode, length);
        LogStr("Input plaintext:\n");
        LogHex((byte*)(input + offset), 0, length);

        if (length == AES_BLOCK_SIZE) {
            /* RFC 3962/8009: Special case for exactly one block.
             * CTS reduces to plain CBC encryption - no stealing needed.
             * wolfSSL_CRYPTO_cts128_encrypt() expects len > one block. */
            if (opmode == 0) {
                /* ENCRYPT_MODE */
                AES_cbc_encrypt(input + offset, output + outputOffset,
                    (size_t)length, &ctx->key, iv, AES_ENCRYPT);
            }
            else {
                /* DECRYPT_MODE */
                AES_cbc_encrypt(input + offset, output + outputOffset,
                    (size_t)length, &ctx->key, iv, AES_DECRYPT);
            }
            outLen = length;
        }
        else if (opmode == 0) {
            /* ENCRYPT_MODE - more than one block */
            outLen = wolfSSL_CRYPTO_cts128_encrypt(input + offset,
                output + outputOffset, (size_t)length, &ctx->key,
                iv, (cbc128_f)AES_cbc_encrypt);
        }
        else {
            /* DECRYPT_MODE - more than one block */
            outLen = wolfSSL_CRYPTO_cts128_decrypt(input + offset,
                output + outputOffset, (size_t)length, &ctx->key,
                iv, (cbc128_f)AES_cbc_encrypt);
        }

        LogStr("Output ciphertext:\n");
        LogHex((byte*)(output + outputOffset), 0, (outLen > 0) ? outLen : 0);

        if (outLen == 0) {
            /* CTS functions return 0 on error */
            ret = BAD_FUNC_ARG;
        }
        else {
            ret = (int)outLen;
        }

        LogStr("CTS operation (ctx=%p, mode=%d, len=%d) = %d\n",
            ctx, opmode, length, ret);
    }

    LogStr("input[%u]: [%p]\n", (word32)length, input + offset);
    LogHex((byte*) input, offset, length);
    LogStr("output[%u]: [%p]\n", (word32)length, output + outputOffset);
    LogHex((byte*) output, outputOffset, length);

    releaseByteArray(env, input_object, input, JNI_ABORT);
    releaseByteArray(env, output_object, output,
        (ret > 0) ? 0 : JNI_ABORT);

    if (ret < 0) {
        throwWolfCryptExceptionFromError(env, ret);
        ret = 0; /* 0 bytes stored in output */
    }
#else
    throwNotCompiledInException(env);
#endif /* !NO_AES && HAVE_CTS */

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_AesCts_native_1update_1internal__ILjava_nio_ByteBuffer_2IILjava_nio_ByteBuffer_2I
  (JNIEnv* env, jobject this, jint opmode, jobject input_object, jint offset, jint length, jobject output_object, jint outputOffset)
{
    int ret = 0;

#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_CTS) && \
    !defined(WOLFSSL_NO_OPENSSL_AES_LOW_LEVEL_API)
    AesCtsCtx* ctx    = NULL;
    byte* input  = NULL;
    byte* output = NULL;
    byte  iv[AES_BLOCK_SIZE];
    size_t outLen = 0;

    ctx = (AesCtsCtx*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return 0;
    }

    input  = getDirectBufferAddress(env, input_object);
    output = getDirectBufferAddress(env, output_object);

    if (ctx == NULL || input == NULL || output == NULL ||
        offset < 0 || length < 0 || outputOffset < 0) {
        ret = BAD_FUNC_ARG;
    }
    else if (length < AES_BLOCK_SIZE) {
        /* CTS requires at least one block of input */
        ret = BUFFER_E;
    }
    else if ((word32)(offset + length) >
        getDirectBufferLimit(env, input_object)) {
        ret = BUFFER_E;
    }
    else if ((word32)(outputOffset + length) >
        getDirectBufferLimit(env, output_object)) {
        ret = BUFFER_E;
    }
    else {
        /* Make a copy of the stored IV. CTS functions modify the IV during
         * operation, so we use a local copy to preserve the original. */
        XMEMCPY(iv, ctx->iv, AES_BLOCK_SIZE);

        if (length == AES_BLOCK_SIZE) {
            /* RFC 3962/8009: Special case for exactly one block.
             * CTS reduces to plain CBC encryption - no stealing needed.
             * wolfSSL_CRYPTO_cts128_encrypt() expects len > one block. */
            if (opmode == 0) {
                /* ENCRYPT_MODE */
                AES_cbc_encrypt(input + offset, output + outputOffset,
                    (size_t)length, &ctx->key, iv, AES_ENCRYPT);
            }
            else {
                /* DECRYPT_MODE */
                AES_cbc_encrypt(input + offset, output + outputOffset,
                    (size_t)length, &ctx->key, iv, AES_DECRYPT);
            }
            outLen = length;
        }
        else if (opmode == 0) {
            /* ENCRYPT_MODE - more than one block */
            outLen = wolfSSL_CRYPTO_cts128_encrypt(input + offset,
                output + outputOffset, (size_t)length, &ctx->key,
                iv, (cbc128_f)AES_cbc_encrypt);
        }
        else {
            /* DECRYPT_MODE - more than one block */
            outLen = wolfSSL_CRYPTO_cts128_decrypt(input + offset,
                output + outputOffset, (size_t)length, &ctx->key,
                iv, (cbc128_f)AES_cbc_encrypt);
        }

        if (outLen == 0) {
            /* CTS functions return 0 on error */
            ret = BAD_FUNC_ARG;
        }
        else {
            ret = (int)outLen;
        }

        LogStr("CTS ByteBuffer operation (ctx=%p, mode=%d, len=%d) = %d\n",
            ctx, opmode, length, ret);
    }

    if (ret < 0) {
        throwWolfCryptExceptionFromError(env, ret);
        ret = 0; /* 0 bytes stored in output */
    }
#else
    throwNotCompiledInException(env);
#endif /* !NO_AES && HAVE_CTS */

    return ret;
}

