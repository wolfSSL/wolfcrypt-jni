/* jni_aesxts.c
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
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/memory.h>

#include <com_wolfssl_wolfcrypt_AesXts.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

#if !defined(NO_AES) && defined(WOLFSSL_AES_XTS)

typedef struct {
    XtsAes xaes;
#ifdef WOLFSSL_AESXTS_STREAM
    struct XtsAesStreamData stream;
#endif
} AesXtsCtx;

#define AESXTS_JAVA_ENCRYPT_MODE com_wolfssl_wolfcrypt_AesXts_ENCRYPT_MODE
#define AESXTS_JAVA_DECRYPT_MODE com_wolfssl_wolfcrypt_AesXts_DECRYPT_MODE

/* Check offset/len ranges fit in inSz/outSz byte buffers.
 * Returns 0, BAD_FUNC_ARG, or BUFFER_E. */
static int AesXtsCheckRange(jint offset, jint length, jint outputOffset,
    word32 inSz, word32 outSz)
{
    if (offset < 0 || length < 0 || outputOffset < 0) {
        return BAD_FUNC_ARG;
    }

    if (((jlong)offset + (jlong)length) > (jlong)inSz) {
        return BUFFER_E;
    }

    if (((jlong)outputOffset + (jlong)length) > (jlong)outSz) {
        return BUFFER_E;
    }

    return 0;
}

/* Reject partially overlapping in/out, only exact aliasing is supported.
 * Returns 0 or BAD_FUNC_ARG. */
static int AesXtsCheckOverlap(const byte* in, const byte* out, word32 sz)
{
    uintptr_t a = (uintptr_t)in;
    uintptr_t b = (uintptr_t)out;
    uintptr_t distance;

    if (a == b) {
        return 0;
    }

    /* subtract the smaller address so the distance cannot wrap */
    if (a > b) {
        distance = a - b;
    }
    else {
        distance = b - a;
    }

    if (distance < (uintptr_t)sz) {
        return BAD_FUNC_ARG;
    }

    return 0;
}

/* One-shot encrypt/decrypt of one data unit. Returns 0 on success. */
static int AesXtsCrypt(AesXtsCtx* ctx, jint opmode, const byte* in,
    byte* out, word32 sz, const byte* tweak, word32 tweakSz)
{
    int ret;

    if (ctx == NULL || in == NULL || out == NULL || tweak == NULL) {
        return BAD_FUNC_ARG;
    }

    if (tweakSz != AES_BLOCK_SIZE) {
        return BAD_FUNC_ARG;
    }

    if (sz < AES_BLOCK_SIZE) {
        return BUFFER_E;
    }

    if (AesXtsCheckOverlap(in, out, sz) != 0) {
        return BAD_FUNC_ARG;
    }

    if (opmode == AESXTS_JAVA_ENCRYPT_MODE) {
        ret = wc_AesXtsEncrypt(&ctx->xaes, out, in, sz, tweak, tweakSz);
    }
    else if (opmode == AESXTS_JAVA_DECRYPT_MODE) {
    #ifdef HAVE_AES_DECRYPT
        ret = wc_AesXtsDecrypt(&ctx->xaes, out, in, sz, tweak, tweakSz);
    #else
        ret = NOT_COMPILED_IN;
    #endif
    }
    else {
        ret = BAD_FUNC_ARG;
    }

    LogStr("XTS operation (ctx=%p, mode=%d, len=%u) = %d\n",
        ctx, opmode, sz, ret);

    return ret;
}

/* Encrypt/decrypt of one data unit with a sector number as tweak.
 * Returns 0 on success. */
static int AesXtsCryptSector(AesXtsCtx* ctx, jint opmode, const byte* in,
    byte* out, word32 sz, word64 sector)
{
    int ret;

    if (ctx == NULL || in == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }

    if (sz < AES_BLOCK_SIZE) {
        return BUFFER_E;
    }

    if (AesXtsCheckOverlap(in, out, sz) != 0) {
        return BAD_FUNC_ARG;
    }

    if (opmode == AESXTS_JAVA_ENCRYPT_MODE) {
        ret = wc_AesXtsEncryptSector(&ctx->xaes, out, in, sz, sector);
    }
    else if (opmode == AESXTS_JAVA_DECRYPT_MODE) {
    #ifdef HAVE_AES_DECRYPT
        ret = wc_AesXtsDecryptSector(&ctx->xaes, out, in, sz, sector);
    #else
        ret = NOT_COMPILED_IN;
    #endif
    }
    else {
        ret = BAD_FUNC_ARG;
    }

    LogStr("XTS sector operation (ctx=%p, mode=%d, len=%u) = %d\n",
        ctx, opmode, sz, ret);

    return ret;
}

#ifdef WOLFSSL_AESXTS_STREAM

/* Start streaming one data unit. Returns 0 on success. */
static int AesXtsStreamInit(AesXtsCtx* ctx, jint opmode, const byte* tweak,
    word32 tweakSz)
{
    int ret;

    if (ctx == NULL || tweak == NULL || tweakSz != AES_BLOCK_SIZE) {
        return BAD_FUNC_ARG;
    }

    if (opmode == AESXTS_JAVA_ENCRYPT_MODE) {
        ret = wc_AesXtsEncryptInit(&ctx->xaes, tweak, tweakSz, &ctx->stream);
    }
    else if (opmode == AESXTS_JAVA_DECRYPT_MODE) {
    #ifdef HAVE_AES_DECRYPT
        ret = wc_AesXtsDecryptInit(&ctx->xaes, tweak, tweakSz, &ctx->stream);
    #else
        ret = NOT_COMPILED_IN;
    #endif
    }
    else {
        ret = BAD_FUNC_ARG;
    }

    LogStr("XTS stream init (ctx=%p, mode=%d) = %d\n", ctx, opmode, ret);

    return ret;
}

/* Stream update (whole blocks) or final (0 bytes, or >= one block with
 * optional partial tail, no buffers needed for 0). Returns 0 on success. */
static int AesXtsStreamCrypt(AesXtsCtx* ctx, jint opmode, const byte* in,
    byte* out, word32 sz, jboolean isFinal)
{
    int ret;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }
    if (sz == 0) {
        if (isFinal == JNI_FALSE) {
            return BAD_FUNC_ARG;
        }
    }
    else {
        if (in == NULL || out == NULL) {
            return BAD_FUNC_ARG;
        }

        if (sz < AES_BLOCK_SIZE) {
            return BUFFER_E;
        }

        if (isFinal == JNI_FALSE && (sz % AES_BLOCK_SIZE) != 0) {
            return BAD_FUNC_ARG;
        }

        if (AesXtsCheckOverlap(in, out, sz) != 0) {
            return BAD_FUNC_ARG;
        }
    }

    if (opmode == AESXTS_JAVA_ENCRYPT_MODE) {
        if (isFinal != JNI_FALSE) {
            ret = wc_AesXtsEncryptFinal(&ctx->xaes, out, in, sz, &ctx->stream);
        }
        else {
            ret = wc_AesXtsEncryptUpdate(&ctx->xaes, out, in, sz, &ctx->stream);
        }
    }
    else if (opmode == AESXTS_JAVA_DECRYPT_MODE) {
    #ifdef HAVE_AES_DECRYPT
        if (isFinal != JNI_FALSE) {
            ret = wc_AesXtsDecryptFinal(&ctx->xaes, out, in, sz, &ctx->stream);
        }
        else {
            ret = wc_AesXtsDecryptUpdate(&ctx->xaes, out, in, sz, &ctx->stream);
        }
    #else
        ret = NOT_COMPILED_IN;
    #endif
    }
    else {
        ret = BAD_FUNC_ARG;
    }

    LogStr("XTS stream %s (ctx=%p, mode=%d, len=%u) = %d\n",
        (isFinal == JNI_TRUE) ? "final" : "update", ctx, opmode, sz, ret);

    return ret;
}

#endif /* WOLFSSL_AESXTS_STREAM */

#endif /* !NO_AES && WOLFSSL_AES_XTS */

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_AesXts_mallocNativeStruct_1internal
  (JNIEnv* env, jobject this)
{
#if !defined(NO_AES) && defined(WOLFSSL_AES_XTS)
    int ret = 0;
    AesXtsCtx* ctx = NULL;
    (void)this;

    ctx = (AesXtsCtx*)XMALLOC(sizeof(AesXtsCtx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate AesXts object");
        return (jlong)0;
    }
    XMEMSET(ctx, 0, sizeof(AesXtsCtx));

    ret = wc_AesXtsInit(&ctx->xaes, NULL, INVALID_DEVID);
    if (ret != 0) {
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        throwWolfCryptExceptionFromError(env, ret);
        return (jlong)0;
    }

    LogStr("new AesXts() = %p\n", ctx);

    return (jlong)(uintptr_t)ctx;

#else
    (void)this;
    throwNotCompiledInException(env);

    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesXts_native_1free
  (JNIEnv* env, jobject this)
{
#if !defined(NO_AES) && defined(WOLFSSL_AES_XTS)
    AesXtsCtx* ctx = NULL;

    ctx = (AesXtsCtx*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    LogStr("free AesXts %p\n", ctx);

    if (ctx != NULL) {
        wc_AesXtsFree(&ctx->xaes);

        /* memory is freed by NativeStruct.xfree() */
    #if (LIBWOLFSSL_VERSION_HEX >= 0x05008004) && \
        !defined(WOLFSSL_NO_FORCE_ZERO)
        wc_ForceZero(ctx, sizeof(AesXtsCtx));
    #else
        XMEMSET(ctx, 0, sizeof(AesXtsCtx));
    #endif
    }
#else
    (void)this;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesXts_native_1set_1key_1internal
  (JNIEnv* env, jobject this, jbyteArray key_object, jint opmode)
{
#if !defined(NO_AES) && defined(WOLFSSL_AES_XTS)
    int ret = 0;
    AesXtsCtx* ctx = NULL;
    byte* key = NULL;
    word32 keySz = 0;
    jboolean keyIsCopy = JNI_FALSE;

    ctx = (AesXtsCtx*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    key   = getByteArrayIsCopy(env, key_object, &keyIsCopy);
    keySz = getByteArrayLength(env, key_object);

    if (ctx == NULL || key == NULL || keySz == 0) {
        ret = BAD_FUNC_ARG;
    }
    else if (opmode != AESXTS_JAVA_ENCRYPT_MODE &&
             opmode != AESXTS_JAVA_DECRYPT_MODE) {
        ret = BAD_FUNC_ARG;
    }
#ifndef HAVE_AES_DECRYPT
    else if (opmode == AESXTS_JAVA_DECRYPT_MODE) {
        ret = NOT_COMPILED_IN;
    }
#endif
    else {
        /* native validates key length and rejects identical halves */
        ret = wc_AesXtsSetKeyNoInit(&ctx->xaes, key, keySz,
            (opmode == AESXTS_JAVA_ENCRYPT_MODE) ?
                AES_ENCRYPTION : AES_DECRYPTION);
    }

    LogStr("wc_AesXtsSetKeyNoInit(ctx=%p, keySz=%u, mode=%d) = %d\n",
        ctx, keySz, opmode, ret);

    zeroizeByteArrayCopy(key, keySz, keyIsCopy);
    releaseByteArray(env, key_object, key, JNI_ABORT);

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }
#else
    (void)this;
    (void)key_object;
    (void)opmode;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_AesXts_native_1update_1internal__I_3BII_3BI_3B
  (JNIEnv* env, jobject this, jint opmode, jbyteArray input_object,
   jint offset, jint length, jbyteArray output_object, jint outputOffset,
   jbyteArray tweak_object)
{
    int ret = 0;
#if !defined(NO_AES) && defined(WOLFSSL_AES_XTS)
    AesXtsCtx* ctx = NULL;
    byte* input  = NULL;
    byte* output = NULL;
    byte* tweak  = NULL;

    ctx = (AesXtsCtx*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return 0;
    }

    input  = getByteArray(env, input_object);
    output = getByteArray(env, output_object);
    tweak  = getByteArray(env, tweak_object);

    ret = AesXtsCheckRange(offset, length, outputOffset,
        getByteArrayLength(env, input_object),
        getByteArrayLength(env, output_object));
    if (ret == 0 && (input == NULL || output == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = AesXtsCrypt(ctx, opmode, input + offset, output + outputOffset,
            (word32)length, tweak, getByteArrayLength(env, tweak_object));
    }

    if (ret == 0) {
        ret = length;
    }

    releaseByteArray(env, input_object, input, JNI_ABORT);
    releaseByteArray(env, tweak_object, tweak, JNI_ABORT);
    releaseByteArray(env, output_object, output, (ret > 0) ? 0 : JNI_ABORT);

    if (ret < 0) {
        throwWolfCryptExceptionFromError(env, ret);
        ret = 0;
    }
#else
    (void)this;
    (void)opmode;
    (void)input_object;
    (void)offset;
    (void)length;
    (void)output_object;
    (void)outputOffset;
    (void)tweak_object;
    throwNotCompiledInException(env);
#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_AesXts_native_1update_1internal__ILjava_nio_ByteBuffer_2IILjava_nio_ByteBuffer_2I_3B
  (JNIEnv* env, jobject this, jint opmode, jobject input_object,
   jint offset, jint length, jobject output_object, jint outputOffset,
   jbyteArray tweak_object)
{
    int ret = 0;
#if !defined(NO_AES) && defined(WOLFSSL_AES_XTS)
    AesXtsCtx* ctx = NULL;
    byte* input  = NULL;
    byte* output = NULL;
    byte* tweak  = NULL;

    ctx = (AesXtsCtx*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return 0;
    }

    input  = getDirectBufferAddress(env, input_object);
    output = getDirectBufferAddress(env, output_object);
    tweak  = getByteArray(env, tweak_object);

    if (input == NULL || output == NULL) {
        ret = BAD_FUNC_ARG; /* null or non-direct ByteBuffer */
    }
    else {
        ret = AesXtsCheckRange(offset, length, outputOffset,
            getDirectBufferLimit(env, input_object),
            getDirectBufferLimit(env, output_object));
    }

    if (ret == 0) {
        ret = AesXtsCrypt(ctx, opmode, input + offset, output + outputOffset,
            (word32)length, tweak, getByteArrayLength(env, tweak_object));
    }

    if (ret == 0) {
        ret = length;
    }

    releaseByteArray(env, tweak_object, tweak, JNI_ABORT);

    if (ret < 0) {
        throwWolfCryptExceptionFromError(env, ret);
        ret = 0;
    }
#else
    (void)this;
    (void)opmode;
    (void)input_object;
    (void)offset;
    (void)length;
    (void)output_object;
    (void)outputOffset;
    (void)tweak_object;
    throwNotCompiledInException(env);
#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_AesXts_native_1update_1sector_1internal__I_3BII_3BIJ
  (JNIEnv* env, jobject this, jint opmode, jbyteArray input_object,
   jint offset, jint length, jbyteArray output_object, jint outputOffset,
   jlong sector)
{
    int ret = 0;
#if !defined(NO_AES) && defined(WOLFSSL_AES_XTS)
    AesXtsCtx* ctx = NULL;
    byte* input  = NULL;
    byte* output = NULL;

    ctx = (AesXtsCtx*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return 0;
    }

    input  = getByteArray(env, input_object);
    output = getByteArray(env, output_object);

    ret = AesXtsCheckRange(offset, length, outputOffset,
        getByteArrayLength(env, input_object),
        getByteArrayLength(env, output_object));
    if (ret == 0 && (input == NULL || output == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = AesXtsCryptSector(ctx, opmode, input + offset,
            output + outputOffset, (word32)length, (word64)sector);
    }

    if (ret == 0) {
        ret = length;
    }

    releaseByteArray(env, input_object, input, JNI_ABORT);
    releaseByteArray(env, output_object, output, (ret > 0) ? 0 : JNI_ABORT);

    if (ret < 0) {
        throwWolfCryptExceptionFromError(env, ret);
        ret = 0;
    }
#else
    (void)this;
    (void)opmode;
    (void)input_object;
    (void)offset;
    (void)length;
    (void)output_object;
    (void)outputOffset;
    (void)sector;
    throwNotCompiledInException(env);
#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_AesXts_native_1update_1sector_1internal__ILjava_nio_ByteBuffer_2IILjava_nio_ByteBuffer_2IJ
  (JNIEnv* env, jobject this, jint opmode, jobject input_object,
   jint offset, jint length, jobject output_object, jint outputOffset,
   jlong sector)
{
    int ret = 0;
#if !defined(NO_AES) && defined(WOLFSSL_AES_XTS)
    AesXtsCtx* ctx = NULL;
    byte* input  = NULL;
    byte* output = NULL;

    ctx = (AesXtsCtx*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return 0;
    }

    input  = getDirectBufferAddress(env, input_object);
    output = getDirectBufferAddress(env, output_object);

    if (input == NULL || output == NULL) {
        ret = BAD_FUNC_ARG; /* null or non-direct ByteBuffer */
    }
    else {
        ret = AesXtsCheckRange(offset, length, outputOffset,
            getDirectBufferLimit(env, input_object),
            getDirectBufferLimit(env, output_object));
    }

    if (ret == 0) {
        ret = AesXtsCryptSector(ctx, opmode, input + offset,
            output + outputOffset, (word32)length, (word64)sector);
    }

    if (ret == 0) {
        ret = length;
    }

    if (ret < 0) {
        throwWolfCryptExceptionFromError(env, ret);
        ret = 0;
    }
#else
    (void)this;
    (void)opmode;
    (void)input_object;
    (void)offset;
    (void)length;
    (void)output_object;
    (void)outputOffset;
    (void)sector;
    throwNotCompiledInException(env);
#endif

    return ret;
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesXts_native_1stream_1init_1internal
  (JNIEnv* env, jobject this, jint opmode, jbyteArray tweak_object)
{
#if !defined(NO_AES) && defined(WOLFSSL_AES_XTS) && \
    defined(WOLFSSL_AESXTS_STREAM)
    int ret = 0;
    AesXtsCtx* ctx = NULL;
    byte* tweak = NULL;

    ctx = (AesXtsCtx*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    tweak = getByteArray(env, tweak_object);

    ret = AesXtsStreamInit(ctx, opmode, tweak,
        getByteArrayLength(env, tweak_object));

    releaseByteArray(env, tweak_object, tweak, JNI_ABORT);

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }
#else
    (void)this;
    (void)opmode;
    (void)tweak_object;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_AesXts_native_1stream_1update_1internal__I_3BII_3BIZ
  (JNIEnv* env, jobject this, jint opmode, jbyteArray input_object,
   jint offset, jint length, jbyteArray output_object, jint outputOffset,
   jboolean isFinal)
{
    int ret = 0;
#if !defined(NO_AES) && defined(WOLFSSL_AES_XTS) && \
    defined(WOLFSSL_AESXTS_STREAM)
    AesXtsCtx* ctx = NULL;
    byte* input  = NULL;
    byte* output = NULL;
    const byte* in = NULL;
    byte* out = NULL;

    ctx = (AesXtsCtx*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return 0;
    }

    input  = getByteArray(env, input_object);
    output = getByteArray(env, output_object);

    ret = AesXtsCheckRange(offset, length, outputOffset,
        getByteArrayLength(env, input_object),
        getByteArrayLength(env, output_object));
    if (ret == 0) {
        /* zero length final may pass null arrays */
        if (length > 0 && input != NULL && output != NULL) {
            in  = input + offset;
            out = output + outputOffset;
        }
        ret = AesXtsStreamCrypt(ctx, opmode, in, out, (word32)length, isFinal);
    }
    if (ret == 0) {
        ret = length;
    }

    releaseByteArray(env, input_object, input, JNI_ABORT);
    releaseByteArray(env, output_object, output, (ret > 0) ? 0 : JNI_ABORT);

    if (ret < 0) {
        throwWolfCryptExceptionFromError(env, ret);
        ret = 0;
    }
#else
    (void)this;
    (void)opmode;
    (void)input_object;
    (void)offset;
    (void)length;
    (void)output_object;
    (void)outputOffset;
    (void)isFinal;
    throwNotCompiledInException(env);
#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_AesXts_native_1stream_1update_1internal__ILjava_nio_ByteBuffer_2IILjava_nio_ByteBuffer_2IZ
  (JNIEnv* env, jobject this, jint opmode, jobject input_object,
   jint offset, jint length, jobject output_object, jint outputOffset,
   jboolean isFinal)
{
    int ret = 0;
#if !defined(NO_AES) && defined(WOLFSSL_AES_XTS) && \
    defined(WOLFSSL_AESXTS_STREAM)
    AesXtsCtx* ctx = NULL;
    byte* input  = NULL;
    byte* output = NULL;
    const byte* in = NULL;
    byte* out = NULL;

    ctx = (AesXtsCtx*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return 0;
    }

    input  = getDirectBufferAddress(env, input_object);
    output = getDirectBufferAddress(env, output_object);

    if (input_object == NULL || output_object == NULL) {
        ret = BAD_FUNC_ARG;
    }
    /* An empty direct buffer may have no address, only a zero length final()
     * is allowed through without one */
    else if (length > 0 && (input == NULL || output == NULL)) {
        ret = BAD_FUNC_ARG; /* null or non-direct ByteBuffer */
    }
    else {
        ret = AesXtsCheckRange(offset, length, outputOffset,
            getDirectBufferLimit(env, input_object),
            getDirectBufferLimit(env, output_object));
    }
    if (ret == 0) {
        if (length > 0) {
            in  = input + offset;
            out = output + outputOffset;
        }
        ret = AesXtsStreamCrypt(ctx, opmode, in, out, (word32)length, isFinal);
    }
    if (ret == 0) {
        ret = length;
    }

    if (ret < 0) {
        throwWolfCryptExceptionFromError(env, ret);
        ret = 0;
    }
#else
    (void)this;
    (void)opmode;
    (void)input_object;
    (void)offset;
    (void)length;
    (void)output_object;
    (void)outputOffset;
    (void)isFinal;
    throwNotCompiledInException(env);
#endif

    return ret;
}

