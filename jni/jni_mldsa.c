/* jni_mldsa.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/types.h>

#if defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)
    /* Newer wolfSSL declares the wc_MlDsaKey API in wc_mldsa.h and keeps
     * dilithium.h only as a temporary compatibility shim slated for removal.
     * Prefer wc_mldsa.h when the compiler can confirm it exists, otherwise
     * fall back to dilithium.h (wolfSSL <= 5.9.1 releases). */
    #if defined(__has_include)
        #if __has_include(<wolfssl/wolfcrypt/wc_mldsa.h>)
            #define WC_JNI_HAVE_WC_MLDSA_H
        #endif
    #endif
    #ifdef WC_JNI_HAVE_WC_MLDSA_H
        #include <wolfssl/wolfcrypt/wc_mldsa.h>
    #else
        #include <wolfssl/wolfcrypt/dilithium.h>
    #endif
#endif
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>

#include <com_wolfssl_wolfcrypt_MlDsa.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

/* Compatibility mappings for wolfSSL releases that predate the ML-DSA rename
 * (<= 5.9.1, no WOLFSSL_HAVE_MLDSA). Releases since 5.7.4 already provide most
 * wc_MlDsaKey_* names as macros in dilithium.h, fill in the type and the names
 * missing from older releases in terms of the legacy API. */
#if defined(HAVE_DILITHIUM) && !defined(WOLFSSL_HAVE_MLDSA)

typedef dilithium_key wc_MlDsaKey;

#ifndef wc_MlDsaKey_SignCtx
    #define wc_MlDsaKey_SignCtx(key, ctx, ctxLen, sig, sigLen, msg, \
            msgLen, rng) \
        wc_dilithium_sign_ctx_msg((ctx), (ctxLen), (msg), (msgLen), \
            (sig), (sigLen), (key), (rng))
#endif
#ifndef wc_MlDsaKey_VerifyCtx
    #define wc_MlDsaKey_VerifyCtx(key, sig, sigLen, ctx, ctxLen, msg, \
            msgLen, res) \
        wc_dilithium_verify_ctx_msg((sig), (sigLen), (ctx), (ctxLen), \
            (msg), (msgLen), (res), (key))
#endif
#ifndef wc_MlDsaKey_KeyToDer
    #define wc_MlDsaKey_KeyToDer(key, output, len) \
        wc_Dilithium_KeyToDer((key), (output), (len))
#endif
#ifndef wc_MlDsaKey_PublicKeyToDer
    #define wc_MlDsaKey_PublicKeyToDer(key, output, len, withAlg) \
        wc_Dilithium_PublicKeyToDer((key), (output), (len), (withAlg))
#endif
#ifndef wc_MlDsaKey_PrivateKeyDecode
    #define wc_MlDsaKey_PrivateKeyDecode(key, input, sz, idx) \
        wc_Dilithium_PrivateKeyDecode((input), (idx), (key), (sz))
#endif
#ifndef wc_MlDsaKey_PublicKeyDecode
    #define wc_MlDsaKey_PublicKeyDecode(key, input, sz, idx) \
        wc_Dilithium_PublicKeyDecode((input), (idx), (key), (sz))
#endif
#ifndef wc_MlDsaKey_MakeKeyFromSeed
    #define wc_MlDsaKey_MakeKeyFromSeed(key, seed) \
        wc_dilithium_make_key_from_seed((key), (seed))
#endif
#ifndef wc_MlDsaKey_SignCtxHash
    #define wc_MlDsaKey_SignCtxHash(key, ctx, ctxLen, sig, sigLen, hash, \
            hashLen, hashAlg, rng) \
        wc_dilithium_sign_ctx_hash((ctx), (ctxLen), (hashAlg), (hash), \
            (hashLen), (sig), (sigLen), (key), (rng))
#endif
#ifndef wc_MlDsaKey_SignCtxWithSeed
    #define wc_MlDsaKey_SignCtxWithSeed(key, ctx, ctxLen, sig, sigLen, msg, \
            msgLen, seed) \
        wc_dilithium_sign_ctx_msg_with_seed((ctx), (ctxLen), (msg), \
            (msgLen), (sig), (sigLen), (key), (seed))
#endif
#ifndef wc_MlDsaKey_SignCtxHashWithSeed
    #define wc_MlDsaKey_SignCtxHashWithSeed(key, ctx, ctxLen, sig, sigLen, \
            hash, hashLen, hashAlg, seed) \
        wc_dilithium_sign_ctx_hash_with_seed((ctx), (ctxLen), (hashAlg), \
            (hash), (hashLen), (sig), (sigLen), (key), (seed))
#endif
#ifndef wc_MlDsaKey_VerifyCtxHash
    #define wc_MlDsaKey_VerifyCtxHash(key, sig, sigLen, ctx, ctxLen, hash, \
            hashLen, hashAlg, res) \
        wc_dilithium_verify_ctx_hash((sig), (sigLen), (ctx), (ctxLen), \
            (hashAlg), (hash), (hashLen), (res), (key))
#endif
#ifndef wc_MlDsaKey_ImportKey
    #define wc_MlDsaKey_ImportKey(key, priv, privSz, pub, pubSz) \
        wc_dilithium_import_key((priv), (privSz), (pub), (pubSz), (key))
#endif
#ifndef wc_MlDsaKey_CheckKey
    #define wc_MlDsaKey_CheckKey(key) \
        wc_dilithium_check_key(key)
#endif
#ifndef wc_MlDsaKey_PrivateKeyToDer
    #define wc_MlDsaKey_PrivateKeyToDer(key, output, len) \
        wc_Dilithium_PrivateKeyToDer((key), (output), (len))
#endif

#endif /* HAVE_DILITHIUM && !WOLFSSL_HAVE_MLDSA */

/* Sub-feature gates, normalized across the legacy (DILITHIUM) and MLDSA
 * spellings. Each JNI function below compiles its real body only when the
 * native wolfSSL build declares the functions it calls, otherwise it compiles
 * a NOT_COMPILED_IN stub. */
#if defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)

#if !defined(WOLFSSL_MLDSA_VERIFY_ONLY) && \
    !defined(WOLFSSL_DILITHIUM_VERIFY_ONLY) && \
    !defined(WOLFSSL_MLDSA_NO_MAKE_KEY) && \
    !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY)
    #define WC_JNI_MLDSA_HAVE_MAKE_KEY
#endif
#if !defined(WOLFSSL_MLDSA_VERIFY_ONLY) && \
    !defined(WOLFSSL_DILITHIUM_VERIFY_ONLY) && \
    !defined(WOLFSSL_MLDSA_NO_SIGN) && \
    !defined(WOLFSSL_DILITHIUM_NO_SIGN)
    #define WC_JNI_MLDSA_HAVE_SIGN
#endif
#if !defined(WOLFSSL_MLDSA_NO_VERIFY) && \
    !defined(WOLFSSL_DILITHIUM_NO_VERIFY)
    #define WC_JNI_MLDSA_HAVE_VERIFY
#endif
#if defined(WOLFSSL_MLDSA_PUBLIC_KEY) || \
    defined(WOLFSSL_DILITHIUM_PUBLIC_KEY)
    #define WC_JNI_MLDSA_HAVE_PUB_KEY
#endif
#if defined(WOLFSSL_MLDSA_PRIVATE_KEY) || \
    defined(WOLFSSL_DILITHIUM_PRIVATE_KEY)
    #define WC_JNI_MLDSA_HAVE_PRIV_KEY
#endif
#if !defined(WOLFSSL_MLDSA_NO_ASN1) && \
    !defined(WOLFSSL_DILITHIUM_NO_ASN1)
    #define WC_JNI_MLDSA_HAVE_ASN1
#endif
#if defined(WOLFSSL_MLDSA_CHECK_KEY) || \
    defined(WOLFSSL_DILITHIUM_CHECK_KEY)
    #define WC_JNI_MLDSA_HAVE_CHECK_KEY
#endif

#endif /* HAVE_DILITHIUM) || WOLFSSL_HAVE_MLDSA */

/* Force-zero a buffer before XFREE */
#if (LIBWOLFSSL_VERSION_HEX >= 0x05008004) && !defined(WOLFSSL_NO_FORCE_ZERO)
    #define MLDSA_FORCE_ZERO(p, len) wc_ForceZero((p), (len))
#else
    #define MLDSA_FORCE_ZERO(p, len) XMEMSET((p), 0, (len))
#endif

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_mallocNativeStruct
  (JNIEnv* env, jobject this)
{
#if defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)
    wc_MlDsaKey* key = NULL;

    key = (wc_MlDsaKey*)XMALLOC(sizeof(wc_MlDsaKey), NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (key == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate MlDsa object");
    }
    else {
        XMEMSET(key, 0, sizeof(wc_MlDsaKey));
    }

    LogStr("new MlDsa() = %p\n", key);

    return (jlong)(uintptr_t)key;
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1dilithium_1init
  (JNIEnv* env, jobject this)
{
#if defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)
    int ret = 0;
    wc_MlDsaKey* key = NULL;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_MlDsaKey_Init(key, NULL, INVALID_DEVID);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlDsaKey_Init(key=%p) = %d\n", key, ret);
#else
   (void)env;
   (void)this;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1dilithium_1free
  (JNIEnv* env, jobject this)
{
#if defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)
    wc_MlDsaKey* key = NULL;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    if (key != NULL) {
        wc_MlDsaKey_Free(key);
    }

    LogStr("wc_MlDsaKey_Free(key=%p)\n", key);
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1dilithium_1set_1level
  (JNIEnv* env, jobject this, jint level)
{
#if defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)
    int ret = 0;
    wc_MlDsaKey* key = NULL;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_MlDsaKey_SetParams(key, (byte)level);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlDsaKey_SetParams(key=%p, level=%d) = %d\n",
        key, (int)level, ret);
#else
   (void)env;
   (void)this;
   (void)level;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1dilithium_1get_1level
  (JNIEnv* env, jobject this)
{
#if defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)
    int ret = 0;
    byte level = 0;
    wc_MlDsaKey* key = NULL;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return 0;
    }

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_MlDsaKey_GetParams(key, &level);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return 0;
    }

    LogStr("wc_MlDsaKey_GetParams(key=%p) = %d\n", key, (int)level);
    return (jint)level;
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
    return 0;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1dilithium_1make_1key
  (JNIEnv* env, jobject this, jobject rng_object)
{
#if (defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)) && \
    defined(WC_JNI_MLDSA_HAVE_MAKE_KEY)
    int ret = 0;
    wc_MlDsaKey* key = NULL;
    WC_RNG* rng = NULL;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    rng = (WC_RNG*) getNativeStruct(env, rng_object);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    if (key == NULL || rng == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_MlDsaKey_MakeKey(key, rng);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlDsaKey_MakeKey(key=%p) = %d\n", key, ret);
#else
    (void)env;
    (void)this;
    (void)rng_object;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1dilithium_1sign_1ctx_1msg
  (JNIEnv* env, jobject this, jbyteArray ctx_object, jbyteArray msg_object, jobject rng_object)
{
    jbyteArray result = NULL;
#if (defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)) && \
    defined(WC_JNI_MLDSA_HAVE_SIGN)
    int ret = 0;
    int sigSz = 0;
    wc_MlDsaKey* key = NULL;
    WC_RNG* rng = NULL;
    byte* ctx = NULL;
    byte* msg = NULL;
    byte* sig = NULL;
    word32 ctxLen = 0;
    word32 msgLen = 0;
    word32 sigLen = 0;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    rng = (WC_RNG*) getNativeStruct(env, rng_object);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    if (key == NULL || rng == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    /* ctx_object may be null for an empty context. */
    if (ctx_object != NULL) {
        ctx = getByteArray(env, ctx_object);
        ctxLen = getByteArrayLength(env, ctx_object);
    }
    if (msg_object != NULL) {
        msg = getByteArray(env, msg_object);
        msgLen = getByteArrayLength(env, msg_object);
    }

    /* getByteArray() returns NULL with OutOfMemoryError pending when
     * GetByteArrayElements fails. Release what was acquired and return
     * without further JNI calls. */
    if ((ctx_object != NULL && ctx == NULL) ||
        (msg_object != NULL && msg == NULL)) {
        if (ctx != NULL) {
            releaseByteArray(env, ctx_object, ctx, JNI_ABORT);
        }
        if (msg != NULL) {
            releaseByteArray(env, msg_object, msg, JNI_ABORT);
        }
        return NULL;
    }

    /* FIPS 204 caps context length at 255 bytes (also enforced in Java). */
    if (ctxLen > com_wolfssl_wolfcrypt_MlDsa_ML_DSA_MAX_CTX_LEN) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = wc_MlDsaKey_GetSigLen(key, &sigSz);
        if (ret == 0) {
            sigLen = (word32)sigSz;
        }
    }

    if (ret == 0) {
        sig = (byte*)XMALLOC(sigLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (sig == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(sig, 0, sigLen);
        }
    }

    if (ret == 0) {
        ret = wc_MlDsaKey_SignCtx(key, ctx, (byte)ctxLen, sig, &sigLen,
            msg, msgLen, rng);
    }

    if (ret == 0) {
        result = (*env)->NewByteArray(env, sigLen);
        if (result != NULL) {
            (*env)->SetByteArrayRegion(env, result, 0, sigLen,
                (const jbyte*)sig);
        }
        else {
            throwWolfCryptException(env, "Failed to allocate sig");
        }
    }
    else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlDsaKey_SignCtx(key=%p) = %d\n", key, ret);

    if (sig != NULL) {
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (ctx_object != NULL) {
        releaseByteArray(env, ctx_object, ctx, JNI_ABORT);
    }
    if (msg_object != NULL) {
        releaseByteArray(env, msg_object, msg, JNI_ABORT);
    }
#else
    (void)env;
    (void)this;
    (void)ctx_object;
    (void)msg_object;
    (void)rng_object;
    throwNotCompiledInException(env);
#endif
    return result;
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1dilithium_1verify_1ctx_1msg
  (JNIEnv* env, jobject this, jbyteArray sig_object, jbyteArray ctx_object, jbyteArray msg_object)
{
    jboolean result = JNI_FALSE;
#if (defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)) && \
    defined(WC_JNI_MLDSA_HAVE_VERIFY)
    int ret = 0;
    int verifyRes = 0;
    wc_MlDsaKey* key = NULL;
    byte* sig = NULL;
    byte* ctx = NULL;
    byte* msg = NULL;
    word32 sigLen = 0;
    word32 ctxLen = 0;
    word32 msgLen = 0;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return JNI_FALSE;
    }

    if (key == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return JNI_FALSE;
    }

    if (sig_object != NULL) {
        sig = getByteArray(env, sig_object);
        sigLen = getByteArrayLength(env, sig_object);
    }
    if (ctx_object != NULL) {
        ctx = getByteArray(env, ctx_object);
        ctxLen = getByteArrayLength(env, ctx_object);
    }
    if (msg_object != NULL) {
        msg = getByteArray(env, msg_object);
        msgLen = getByteArrayLength(env, msg_object);
    }

    /* getByteArray() returns NULL with OutOfMemoryError pending when
     * GetByteArrayElements fails. Release what was acquired and return
     * without further JNI calls. */
    if ((sig_object != NULL && sig == NULL) ||
        (ctx_object != NULL && ctx == NULL) ||
        (msg_object != NULL && msg == NULL)) {
        if (sig != NULL) {
            releaseByteArray(env, sig_object, sig, JNI_ABORT);
        }
        if (ctx != NULL) {
            releaseByteArray(env, ctx_object, ctx, JNI_ABORT);
        }
        if (msg != NULL) {
            releaseByteArray(env, msg_object, msg, JNI_ABORT);
        }
        return JNI_FALSE;
    }

    /* FIPS 204 caps context length at 255 bytes (also enforced in Java). */
    if (ctxLen > com_wolfssl_wolfcrypt_MlDsa_ML_DSA_MAX_CTX_LEN) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = wc_MlDsaKey_VerifyCtx(key, sig, sigLen, ctx, (byte)ctxLen,
            msg, msgLen, &verifyRes);
    }

    if (ret == 0 && verifyRes == 1) {
        result = JNI_TRUE;
    }
    else if (ret != 0 && ret != SIG_VERIFY_E) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlDsaKey_VerifyCtx(key=%p) = %d (res=%d)\n",
        key, ret, verifyRes);

    if (sig_object != NULL) {
        releaseByteArray(env, sig_object, sig, JNI_ABORT);
    }
    if (ctx_object != NULL) {
        releaseByteArray(env, ctx_object, ctx, JNI_ABORT);
    }
    if (msg_object != NULL) {
        releaseByteArray(env, msg_object, msg, JNI_ABORT);
    }
#else
    (void)env;
    (void)this;
    (void)sig_object;
    (void)ctx_object;
    (void)msg_object;
    throwNotCompiledInException(env);
#endif
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1dilithium_1export_1public
  (JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;
#if (defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)) && \
    defined(WC_JNI_MLDSA_HAVE_PUB_KEY)
    int ret = 0;
    int pubSz = 0;
    wc_MlDsaKey* key = NULL;
    byte* output = NULL;
    word32 outputSz = 0;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    if (key == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    ret = wc_MlDsaKey_GetPubLen(key, &pubSz);
    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return NULL;
    }
    outputSz = (word32)pubSz;

    output = (byte*)XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate public key buffer");
        return NULL;
    }
    XMEMSET(output, 0, outputSz);

    ret = wc_MlDsaKey_ExportPubRaw(key, output, &outputSz);
    if (ret == 0) {
        result = (*env)->NewByteArray(env, outputSz);
        if (result != NULL) {
            (*env)->SetByteArrayRegion(env, result, 0, outputSz,
                (const jbyte*)output);
        }
        else {
            throwWolfCryptException(env, "Failed to allocate public key");
        }
    }
    else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlDsaKey_ExportPubRaw(key=%p) = %d\n", key, ret);

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
#endif
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1dilithium_1export_1private
  (JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;
#if (defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)) && \
    defined(WC_JNI_MLDSA_HAVE_PRIV_KEY)
    int ret = 0;
    int privSz = 0;
    wc_MlDsaKey* key = NULL;
    byte* output = NULL;
    word32 outputSz = 0;
    word32 outputBufSz = 0;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    if (key == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    ret = wc_MlDsaKey_GetPrivLen(key, &privSz);
    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return NULL;
    }
    outputSz = (word32)privSz;
    outputBufSz = outputSz;

    output = (byte*)XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate private key buffer");
        return NULL;
    }
    XMEMSET(output, 0, outputSz);

    ret = wc_MlDsaKey_ExportPrivRaw(key, output, &outputSz);
    if (ret == 0) {
        result = (*env)->NewByteArray(env, outputSz);
        if (result != NULL) {
            (*env)->SetByteArrayRegion(env, result, 0, outputSz,
                (const jbyte*)output);
        }
        else {
            throwWolfCryptException(env, "Failed to allocate private key");
        }
    }
    else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlDsaKey_ExportPrivRaw(key=%p) = %d\n", key, ret);

    MLDSA_FORCE_ZERO(output, outputBufSz);
    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
#endif
    return result;
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1dilithium_1import_1public
  (JNIEnv* env, jobject this, jbyteArray in_object)
{
#if (defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)) && \
    defined(WC_JNI_MLDSA_HAVE_PUB_KEY)
    int ret = 0;
    wc_MlDsaKey* key = NULL;
    byte* in = NULL;
    word32 inLen = 0;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    in = getByteArray(env, in_object);
    inLen = getByteArrayLength(env, in_object);

    if (key == NULL || in == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_MlDsaKey_ImportPubRaw(key, in, inLen);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlDsaKey_ImportPubRaw(key=%p) = %d\n", key, ret);

    releaseByteArray(env, in_object, in, JNI_ABORT);
#else
    (void)env;
    (void)this;
    (void)in_object;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1dilithium_1import_1private
  (JNIEnv* env, jobject this, jbyteArray in_object)
{
#if (defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)) && \
    defined(WC_JNI_MLDSA_HAVE_PRIV_KEY)
    int ret = 0;
    wc_MlDsaKey* key = NULL;
    byte* in = NULL;
    word32 inLen = 0;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    in = getByteArray(env, in_object);
    inLen = getByteArrayLength(env, in_object);

    if (key == NULL || in == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_MlDsaKey_ImportPrivRaw(key, in, inLen);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlDsaKey_ImportPrivRaw(key=%p) = %d\n", key, ret);

    releaseByteArray(env, in_object, in, JNI_ABORT);
#else
    (void)env;
    (void)this;
    (void)in_object;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1Dilithium_1PublicKeyToDer
  (JNIEnv* env, jobject this, jboolean withAlg)
{
    jbyteArray result = NULL;
#if (defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)) && \
    defined(WC_JNI_MLDSA_HAVE_PUB_KEY) && \
    defined(WC_JNI_MLDSA_HAVE_ASN1) && defined(WC_ENABLE_ASYM_KEY_EXPORT)
    int ret = 0;
    wc_MlDsaKey* key = NULL;
    byte* output = NULL;
    word32 outputSz = 0;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    if (key == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    /* Two-pass: first call with NULL output to get required size. */
    ret = wc_MlDsaKey_PublicKeyToDer(key, NULL, 0, (int)withAlg);
    if (ret <= 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return NULL;
    }
    outputSz = (word32)ret;

    output = (byte*)XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate public DER buffer");
        return NULL;
    }
    XMEMSET(output, 0, outputSz);

    ret = wc_MlDsaKey_PublicKeyToDer(key, output, outputSz, (int)withAlg);
    if (ret > 0) {
        result = (*env)->NewByteArray(env, ret);
        if (result != NULL) {
            (*env)->SetByteArrayRegion(env, result, 0, ret,
                (const jbyte*)output);
        }
        else {
            throwWolfCryptException(env, "Failed to allocate public DER");
        }
    }
    else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlDsaKey_PublicKeyToDer(key=%p) = %d\n", key, ret);

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    (void)env;
    (void)this;
    (void)withAlg;
    throwNotCompiledInException(env);
#endif
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1Dilithium_1KeyToDer
  (JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;
#if (defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)) && \
    defined(WC_JNI_MLDSA_HAVE_PRIV_KEY) && defined(WC_JNI_MLDSA_HAVE_ASN1)
    int ret = 0;
    wc_MlDsaKey* key = NULL;
    byte* output = NULL;
    word32 outputSz = 0;
    word32 outputBufSz = 0;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    if (key == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    /* Two-pass: first call with NULL output to get required size. */
    ret = wc_MlDsaKey_KeyToDer(key, NULL, 0);
    if (ret <= 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return NULL;
    }
    outputSz = (word32)ret;
    outputBufSz = outputSz;

    output = (byte*)XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate PKCS#8 buffer");
        return NULL;
    }
    XMEMSET(output, 0, outputSz);

    ret = wc_MlDsaKey_KeyToDer(key, output, outputSz);
    if (ret > 0) {
        result = (*env)->NewByteArray(env, ret);
        if (result != NULL) {
            (*env)->SetByteArrayRegion(env, result, 0, ret,
                (const jbyte*)output);
        }
        else {
            throwWolfCryptException(env, "Failed to allocate PKCS#8 DER");
        }
    }
    else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlDsaKey_KeyToDer(key=%p) = %d\n", key, ret);

    MLDSA_FORCE_ZERO(output, outputBufSz);
    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
#endif
    return result;
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1Dilithium_1PublicKeyDecode
  (JNIEnv* env, jobject this, jbyteArray der_object)
{
#if (defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)) && \
    defined(WC_JNI_MLDSA_HAVE_PUB_KEY) && defined(WC_JNI_MLDSA_HAVE_ASN1)
    int ret = 0;
    wc_MlDsaKey* key = NULL;
    byte* der = NULL;
    word32 derLen = 0;
    word32 idx = 0;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    der = getByteArray(env, der_object);
    derLen = getByteArrayLength(env, der_object);

    if (key == NULL || der == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_MlDsaKey_PublicKeyDecode(key, der, derLen, &idx);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlDsaKey_PublicKeyDecode(key=%p) = %d\n", key, ret);

    releaseByteArray(env, der_object, der, JNI_ABORT);
#else
    (void)env;
    (void)this;
    (void)der_object;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1Dilithium_1PrivateKeyDecode
  (JNIEnv* env, jobject this, jbyteArray der_object)
{
#if (defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)) && \
    defined(WC_JNI_MLDSA_HAVE_PRIV_KEY) && defined(WC_JNI_MLDSA_HAVE_ASN1)
    int ret = 0;
    wc_MlDsaKey* key = NULL;
    byte* der = NULL;
    byte* derCopy = NULL;
    word32 derLen = 0;
    word32 idx = 0;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    der = getByteArray(env, der_object);
    derLen = getByteArrayLength(env, der_object);

    if (key == NULL || der == NULL || derLen == 0) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Copy because PrivateKeyDecode may modify input buffer. */
        derCopy = (byte*)XMALLOC(derLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (derCopy == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMCPY(derCopy, der, derLen);
        }
    }

    if (ret == 0) {
        ret = wc_MlDsaKey_PrivateKeyDecode(key, derCopy, derLen, &idx);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlDsaKey_PrivateKeyDecode(key=%p) = %d\n", key, ret);

    if (derCopy != NULL) {
        MLDSA_FORCE_ZERO(derCopy, derLen);
        XFREE(derCopy, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    releaseByteArray(env, der_object, der, JNI_ABORT);
#else
    (void)env;
    (void)this;
    (void)der_object;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1dilithium_1pub_1size
  (JNIEnv* env, jobject this)
{
#if defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)
    int ret = 0;
    int pubSz = 0;
    wc_MlDsaKey* key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return 0;
    }

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_MlDsaKey_GetPubLen(key, &pubSz);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return 0;
    }
    return (jint)pubSz;
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1dilithium_1priv_1size
  (JNIEnv* env, jobject this)
{
#if defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)
    int ret = 0;
    int privSz = 0;
    wc_MlDsaKey* key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return 0;
    }

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_MlDsaKey_GetPrivLen(key, &privSz);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return 0;
    }
    return (jint)privSz;
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1dilithium_1sig_1size
  (JNIEnv* env, jobject this)
{
#if defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)
    int ret = 0;
    int sigSz = 0;
    wc_MlDsaKey* key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return 0;
    }

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_MlDsaKey_GetSigLen(key, &sigSz);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return 0;
    }
    return (jint)sigSz;
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
    return 0;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1dilithium_1make_1key_1from_1seed
  (JNIEnv* env, jobject this, jbyteArray seed_object)
{
#if (defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)) && \
    defined(WC_JNI_MLDSA_HAVE_MAKE_KEY)
    int ret = 0;
    wc_MlDsaKey* key = NULL;
    byte* seed = NULL;
    word32 seedLen = 0;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    seed = getByteArray(env, seed_object);
    seedLen = getByteArrayLength(env, seed_object);

    /* Native API takes no seed length, seed must be exactly 32 bytes */
    if (key == NULL || seed == NULL ||
        seedLen != com_wolfssl_wolfcrypt_MlDsa_ML_DSA_SEED_LEN) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_MlDsaKey_MakeKeyFromSeed(key, seed);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlDsaKey_MakeKeyFromSeed(key=%p) = %d\n", key, ret);

    releaseByteArray(env, seed_object, seed, JNI_ABORT);
#else
    (void)env;
    (void)this;
    (void)seed_object;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1dilithium_1sign_1ctx_1hash
  (JNIEnv* env, jobject this, jbyteArray ctx_object, jint hashAlg, jbyteArray hash_object, jobject rng_object)
{
    jbyteArray result = NULL;
#if (defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)) && \
    defined(WC_JNI_MLDSA_HAVE_SIGN)
    int ret = 0;
    int sigSz = 0;
    wc_MlDsaKey* key = NULL;
    WC_RNG* rng = NULL;
    byte* ctx = NULL;
    byte* hash = NULL;
    byte* sig = NULL;
    word32 ctxLen = 0;
    word32 hashLen = 0;
    word32 sigLen = 0;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    rng = (WC_RNG*) getNativeStruct(env, rng_object);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    if (key == NULL || rng == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    /* ctx_object may be null for an empty context. */
    if (ctx_object != NULL) {
        ctx = getByteArray(env, ctx_object);
        ctxLen = getByteArrayLength(env, ctx_object);
    }

    if (hash_object != NULL) {
        hash = getByteArray(env, hash_object);
        hashLen = getByteArrayLength(env, hash_object);
    }

    /* getByteArray() returns NULL with OutOfMemoryError pending when
     * GetByteArrayElements fails. Release what was acquired and return
     * without further JNI calls. */
    if ((ctx_object != NULL && ctx == NULL) ||
        (hash_object != NULL && hash == NULL)) {
        if (ctx != NULL) {
            releaseByteArray(env, ctx_object, ctx, JNI_ABORT);
        }
        if (hash != NULL) {
            releaseByteArray(env, hash_object, hash, JNI_ABORT);
        }
        return NULL;
    }

    /* FIPS 204 caps context length at 255 bytes. */
    if (ctxLen > com_wolfssl_wolfcrypt_MlDsa_ML_DSA_MAX_CTX_LEN) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = wc_MlDsaKey_GetSigLen(key, &sigSz);
        if (ret == 0) {
            sigLen = (word32)sigSz;
        }
    }

    if (ret == 0) {
        sig = (byte*)XMALLOC(sigLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (sig == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(sig, 0, sigLen);
        }
    }

    if (ret == 0) {
        ret = wc_MlDsaKey_SignCtxHash(key, ctx, (byte)ctxLen, sig, &sigLen,
            hash, hashLen, (int)hashAlg, rng);
    }

    if (ret == 0) {
        result = (*env)->NewByteArray(env, sigLen);
        if (result != NULL) {
            (*env)->SetByteArrayRegion(env, result, 0, sigLen,
                (const jbyte*)sig);
        }
        else {
            throwWolfCryptException(env, "Failed to allocate sig");
        }
    }
    else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlDsaKey_SignCtxHash(key=%p) = %d\n", key, ret);

    if (sig != NULL) {
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (ctx_object != NULL) {
        releaseByteArray(env, ctx_object, ctx, JNI_ABORT);
    }
    if (hash_object != NULL) {
        releaseByteArray(env, hash_object, hash, JNI_ABORT);
    }
#else
    (void)env;
    (void)this;
    (void)ctx_object;
    (void)hashAlg;
    (void)hash_object;
    (void)rng_object;
    throwNotCompiledInException(env);
#endif
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1dilithium_1sign_1ctx_1msg_1with_1seed
  (JNIEnv* env, jobject this, jbyteArray ctx_object, jbyteArray msg_object, jbyteArray seed_object)
{
    jbyteArray result = NULL;
#if (defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)) && \
    defined(WC_JNI_MLDSA_HAVE_SIGN)
    int ret = 0;
    int sigSz = 0;
    wc_MlDsaKey* key = NULL;
    byte* ctx = NULL;
    byte* msg = NULL;
    byte* seed = NULL;
    byte* sig = NULL;
    word32 ctxLen = 0;
    word32 msgLen = 0;
    word32 seedLen = 0;
    word32 sigLen = 0;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    if (key == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    /* ctx_object may be null for an empty context. */
    if (ctx_object != NULL) {
        ctx = getByteArray(env, ctx_object);
        ctxLen = getByteArrayLength(env, ctx_object);
    }

    if (msg_object != NULL) {
        msg = getByteArray(env, msg_object);
        msgLen = getByteArrayLength(env, msg_object);
    }

    if (seed_object != NULL) {
        seed = getByteArray(env, seed_object);
        seedLen = getByteArrayLength(env, seed_object);
    }

    /* getByteArray() returns NULL with OutOfMemoryError pending when
     * GetByteArrayElements fails. Release what was acquired and return
     * without further JNI calls. */
    if ((ctx_object != NULL && ctx == NULL) ||
        (msg_object != NULL && msg == NULL) ||
        (seed_object != NULL && seed == NULL)) {
        if (ctx != NULL) {
            releaseByteArray(env, ctx_object, ctx, JNI_ABORT);
        }
        if (msg != NULL) {
            releaseByteArray(env, msg_object, msg, JNI_ABORT);
        }
        if (seed != NULL) {
            releaseByteArray(env, seed_object, seed, JNI_ABORT);
        }
        return NULL;
    }

    /* FIPS 204 caps context length at 255 bytes */
    if (ctxLen > com_wolfssl_wolfcrypt_MlDsa_ML_DSA_MAX_CTX_LEN) {
        ret = BAD_FUNC_ARG;
    }

    /* Native API takes no seed length, seed must be exactly 32 bytes */
    if (ret == 0 && (seed == NULL ||
        seedLen != com_wolfssl_wolfcrypt_MlDsa_ML_DSA_RND_LEN)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = wc_MlDsaKey_GetSigLen(key, &sigSz);
        if (ret == 0) {
            sigLen = (word32)sigSz;
        }
    }

    if (ret == 0) {
        sig = (byte*)XMALLOC(sigLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (sig == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(sig, 0, sigLen);
        }
    }

    if (ret == 0) {
        ret = wc_MlDsaKey_SignCtxWithSeed(key, ctx, (byte)ctxLen, sig,
            &sigLen, msg, msgLen, seed);
    }

    if (ret == 0) {
        result = (*env)->NewByteArray(env, sigLen);
        if (result != NULL) {
            (*env)->SetByteArrayRegion(env, result, 0, sigLen,
                (const jbyte*)sig);
        }
        else {
            throwWolfCryptException(env, "Failed to allocate sig");
        }
    }
    else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlDsaKey_SignCtxWithSeed(key=%p) = %d\n", key, ret);

    if (sig != NULL) {
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (ctx_object != NULL) {
        releaseByteArray(env, ctx_object, ctx, JNI_ABORT);
    }
    if (msg_object != NULL) {
        releaseByteArray(env, msg_object, msg, JNI_ABORT);
    }
    if (seed_object != NULL) {
        releaseByteArray(env, seed_object, seed, JNI_ABORT);
    }
#else
    (void)env;
    (void)this;
    (void)ctx_object;
    (void)msg_object;
    (void)seed_object;
    throwNotCompiledInException(env);
#endif
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1dilithium_1sign_1ctx_1hash_1with_1seed
  (JNIEnv* env, jobject this, jbyteArray ctx_object, jint hashAlg, jbyteArray hash_object, jbyteArray seed_object)
{
    jbyteArray result = NULL;
#if (defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)) && \
    defined(WC_JNI_MLDSA_HAVE_SIGN)
    int ret = 0;
    int sigSz = 0;
    wc_MlDsaKey* key = NULL;
    byte* ctx = NULL;
    byte* hash = NULL;
    byte* seed = NULL;
    byte* sig = NULL;
    word32 ctxLen = 0;
    word32 hashLen = 0;
    word32 seedLen = 0;
    word32 sigLen = 0;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    if (key == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    /* ctx_object may be null for an empty context. */
    if (ctx_object != NULL) {
        ctx = getByteArray(env, ctx_object);
        ctxLen = getByteArrayLength(env, ctx_object);
    }

    if (hash_object != NULL) {
        hash = getByteArray(env, hash_object);
        hashLen = getByteArrayLength(env, hash_object);
    }

    if (seed_object != NULL) {
        seed = getByteArray(env, seed_object);
        seedLen = getByteArrayLength(env, seed_object);
    }

    /* getByteArray() returns NULL with OutOfMemoryError pending when
     * GetByteArrayElements fails. Release what was acquired and return
     * without further JNI calls. */
    if ((ctx_object != NULL && ctx == NULL) ||
        (hash_object != NULL && hash == NULL) ||
        (seed_object != NULL && seed == NULL)) {
        if (ctx != NULL) {
            releaseByteArray(env, ctx_object, ctx, JNI_ABORT);
        }
        if (hash != NULL) {
            releaseByteArray(env, hash_object, hash, JNI_ABORT);
        }
        if (seed != NULL) {
            releaseByteArray(env, seed_object, seed, JNI_ABORT);
        }
        return NULL;
    }

    /* FIPS 204 caps context length at 255 bytes */
    if (ctxLen > com_wolfssl_wolfcrypt_MlDsa_ML_DSA_MAX_CTX_LEN) {
        ret = BAD_FUNC_ARG;
    }

    /* Native API takes no seed length, seed must be exactly 32 bytes */
    if (ret == 0 && (seed == NULL ||
        seedLen != com_wolfssl_wolfcrypt_MlDsa_ML_DSA_RND_LEN)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = wc_MlDsaKey_GetSigLen(key, &sigSz);
        if (ret == 0) {
            sigLen = (word32)sigSz;
        }
    }

    if (ret == 0) {
        sig = (byte*)XMALLOC(sigLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (sig == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(sig, 0, sigLen);
        }
    }

    if (ret == 0) {
        ret = wc_MlDsaKey_SignCtxHashWithSeed(key, ctx, (byte)ctxLen, sig,
            &sigLen, hash, hashLen, (int)hashAlg, seed);
    }

    if (ret == 0) {
        result = (*env)->NewByteArray(env, sigLen);
        if (result != NULL) {
            (*env)->SetByteArrayRegion(env, result, 0, sigLen,
                (const jbyte*)sig);
        }
        else {
            throwWolfCryptException(env, "Failed to allocate sig");
        }
    }
    else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlDsaKey_SignCtxHashWithSeed(key=%p) = %d\n", key, ret);

    if (sig != NULL) {
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (ctx_object != NULL) {
        releaseByteArray(env, ctx_object, ctx, JNI_ABORT);
    }
    if (hash_object != NULL) {
        releaseByteArray(env, hash_object, hash, JNI_ABORT);
    }
    if (seed_object != NULL) {
        releaseByteArray(env, seed_object, seed, JNI_ABORT);
    }
#else
    (void)env;
    (void)this;
    (void)ctx_object;
    (void)hashAlg;
    (void)hash_object;
    (void)seed_object;
    throwNotCompiledInException(env);
#endif
    return result;
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1dilithium_1verify_1ctx_1hash
  (JNIEnv* env, jobject this, jbyteArray sig_object, jbyteArray ctx_object, jint hashAlg, jbyteArray hash_object)
{
    jboolean result = JNI_FALSE;
#if (defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)) && \
    defined(WC_JNI_MLDSA_HAVE_VERIFY)
    int ret = 0;
    int verifyRes = 0;
    wc_MlDsaKey* key = NULL;
    byte* sig = NULL;
    byte* ctx = NULL;
    byte* hash = NULL;
    word32 sigLen = 0;
    word32 ctxLen = 0;
    word32 hashLen = 0;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return JNI_FALSE;
    }

    if (key == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return JNI_FALSE;
    }

    if (sig_object != NULL) {
        sig = getByteArray(env, sig_object);
        sigLen = getByteArrayLength(env, sig_object);
    }

    if (ctx_object != NULL) {
        ctx = getByteArray(env, ctx_object);
        ctxLen = getByteArrayLength(env, ctx_object);
    }

    if (hash_object != NULL) {
        hash = getByteArray(env, hash_object);
        hashLen = getByteArrayLength(env, hash_object);
    }

    /* getByteArray() returns NULL with OutOfMemoryError pending when
     * GetByteArrayElements fails. Release what was acquired and return
     * without further JNI calls. */
    if ((sig_object != NULL && sig == NULL) ||
        (ctx_object != NULL && ctx == NULL) ||
        (hash_object != NULL && hash == NULL)) {
        if (sig != NULL) {
            releaseByteArray(env, sig_object, sig, JNI_ABORT);
        }
        if (ctx != NULL) {
            releaseByteArray(env, ctx_object, ctx, JNI_ABORT);
        }
        if (hash != NULL) {
            releaseByteArray(env, hash_object, hash, JNI_ABORT);
        }
        return JNI_FALSE;
    }

    /* FIPS 204 caps context length at 255 bytes */
    if (ctxLen > com_wolfssl_wolfcrypt_MlDsa_ML_DSA_MAX_CTX_LEN) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = wc_MlDsaKey_VerifyCtxHash(key, sig, sigLen, ctx, (byte)ctxLen,
            hash, hashLen, (int)hashAlg, &verifyRes);
    }

    if (ret == 0 && verifyRes == 1) {
        result = JNI_TRUE;
    }
    else if (ret != 0 && ret != SIG_VERIFY_E) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlDsaKey_VerifyCtxHash(key=%p) = %d (res=%d)\n",
        key, ret, verifyRes);

    if (sig_object != NULL) {
        releaseByteArray(env, sig_object, sig, JNI_ABORT);
    }
    if (ctx_object != NULL) {
        releaseByteArray(env, ctx_object, ctx, JNI_ABORT);
    }
    if (hash_object != NULL) {
        releaseByteArray(env, hash_object, hash, JNI_ABORT);
    }
#else
    (void)env;
    (void)this;
    (void)sig_object;
    (void)ctx_object;
    (void)hashAlg;
    (void)hash_object;
    throwNotCompiledInException(env);
#endif
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1MlDsaKey_1SignMuWithSeed
  (JNIEnv* env, jobject this, jbyteArray mu_object, jbyteArray seed_object)
{
    jbyteArray result = NULL;
/* External mu sign/verify has no legacy dilithium.h equivalent, only
 * available with the wc_MlDsaKey API in newer wolfSSL (wc_mldsa.h). */
#if defined(WOLFSSL_HAVE_MLDSA) && defined(WC_JNI_MLDSA_HAVE_SIGN)
    int ret = 0;
    int sigSz = 0;
    wc_MlDsaKey* key = NULL;
    byte* mu = NULL;
    byte* seed = NULL;
    byte* sig = NULL;
    word32 muLen = 0;
    word32 seedLen = 0;
    word32 sigLen = 0;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    if (key == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    if (mu_object != NULL) {
        mu = getByteArray(env, mu_object);
        muLen = getByteArrayLength(env, mu_object);
    }

    if (seed_object != NULL) {
        seed = getByteArray(env, seed_object);
        seedLen = getByteArrayLength(env, seed_object);
    }

    /* getByteArray() returns NULL with OutOfMemoryError pending when
     * GetByteArrayElements fails. Release what was acquired and return
     * without further JNI calls. */
    if ((mu_object != NULL && mu == NULL) ||
        (seed_object != NULL && seed == NULL)) {
        if (mu != NULL) {
            releaseByteArray(env, mu_object, mu, JNI_ABORT);
        }
        if (seed != NULL) {
            releaseByteArray(env, seed_object, seed, JNI_ABORT);
        }
        return NULL;
    }

    /* Native API takes no seed length, seed must be exactly 32 bytes */
    if (seed == NULL || mu == NULL ||
        seedLen != com_wolfssl_wolfcrypt_MlDsa_ML_DSA_RND_LEN) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = wc_MlDsaKey_GetSigLen(key, &sigSz);
        if (ret == 0) {
            sigLen = (word32)sigSz;
        }
    }

    if (ret == 0) {
        sig = (byte*)XMALLOC(sigLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (sig == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(sig, 0, sigLen);
        }
    }

    if (ret == 0) {
        ret = wc_MlDsaKey_SignMuWithSeed(key, sig, &sigLen, mu, muLen, seed);
    }

    if (ret == 0) {
        result = (*env)->NewByteArray(env, sigLen);
        if (result != NULL) {
            (*env)->SetByteArrayRegion(env, result, 0, sigLen,
                (const jbyte*)sig);
        }
        else {
            throwWolfCryptException(env, "Failed to allocate sig");
        }
    }
    else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlDsaKey_SignMuWithSeed(key=%p) = %d\n", key, ret);

    if (sig != NULL) {
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (mu_object != NULL) {
        releaseByteArray(env, mu_object, mu, JNI_ABORT);
    }
    if (seed_object != NULL) {
        releaseByteArray(env, seed_object, seed, JNI_ABORT);
    }
#else
    (void)env;
    (void)this;
    (void)mu_object;
    (void)seed_object;
    throwNotCompiledInException(env);
#endif
    return result;
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1MlDsaKey_1VerifyMu
  (JNIEnv* env, jobject this, jbyteArray sig_object, jbyteArray mu_object)
{
    jboolean result = JNI_FALSE;
/* External mu sign/verify has no legacy dilithium.h equivalent, only
 * available with the wc_MlDsaKey API in newer wolfSSL (wc_mldsa.h). */
#if defined(WOLFSSL_HAVE_MLDSA) && defined(WC_JNI_MLDSA_HAVE_VERIFY)
    int ret = 0;
    int verifyRes = 0;
    wc_MlDsaKey* key = NULL;
    byte* sig = NULL;
    byte* mu = NULL;
    word32 sigLen = 0;
    word32 muLen = 0;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return JNI_FALSE;
    }

    if (key == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return JNI_FALSE;
    }

    if (sig_object != NULL) {
        sig = getByteArray(env, sig_object);
        sigLen = getByteArrayLength(env, sig_object);
    }

    if (mu_object != NULL) {
        mu = getByteArray(env, mu_object);
        muLen = getByteArrayLength(env, mu_object);
    }

    /* getByteArray() returns NULL with OutOfMemoryError pending when
     * GetByteArrayElements fails. Release what was acquired and return
     * without further JNI calls. */
    if ((sig_object != NULL && sig == NULL) ||
        (mu_object != NULL && mu == NULL)) {
        if (sig != NULL) {
            releaseByteArray(env, sig_object, sig, JNI_ABORT);
        }
        if (mu != NULL) {
            releaseByteArray(env, mu_object, mu, JNI_ABORT);
        }
        return JNI_FALSE;
    }

    /* Native validates muLen itself (must be 64). */
    ret = wc_MlDsaKey_VerifyMu(key, sig, sigLen, mu, muLen, &verifyRes);

    if (ret == 0 && verifyRes == 1) {
        result = JNI_TRUE;
    }
    else if (ret != 0 && ret != SIG_VERIFY_E) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlDsaKey_VerifyMu(key=%p) = %d (res=%d)\n",
        key, ret, verifyRes);

    if (sig_object != NULL) {
        releaseByteArray(env, sig_object, sig, JNI_ABORT);
    }
    if (mu_object != NULL) {
        releaseByteArray(env, mu_object, mu, JNI_ABORT);
    }
#else
    (void)env;
    (void)this;
    (void)sig_object;
    (void)mu_object;
    throwNotCompiledInException(env);
#endif
    return result;
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1dilithium_1import_1key
  (JNIEnv* env, jobject this, jbyteArray priv_object, jbyteArray pub_object)
{
#if (defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)) && \
    defined(WC_JNI_MLDSA_HAVE_PRIV_KEY)
    int ret = 0;
    wc_MlDsaKey* key = NULL;
    byte* priv = NULL;
    byte* pub = NULL;
    word32 privLen = 0;
    word32 pubLen = 0;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    priv = getByteArray(env, priv_object);
    privLen = getByteArrayLength(env, priv_object);
    pub = getByteArray(env, pub_object);
    pubLen = getByteArrayLength(env, pub_object);

    if (key == NULL || priv == NULL || pub == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_MlDsaKey_ImportKey(key, priv, privLen, pub, pubLen);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlDsaKey_ImportKey(key=%p) = %d\n", key, ret);

    releaseByteArray(env, priv_object, priv, JNI_ABORT);
    releaseByteArray(env, pub_object, pub, JNI_ABORT);
#else
    (void)env;
    (void)this;
    (void)priv_object;
    (void)pub_object;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1dilithium_1check_1key
  (JNIEnv* env, jobject this)
{
#if (defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)) && \
    defined(WC_JNI_MLDSA_HAVE_CHECK_KEY)
    int ret = 0;
    wc_MlDsaKey* key = NULL;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_MlDsaKey_CheckKey(key);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlDsaKey_CheckKey(key=%p) = %d\n", key, ret);
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_MlDsa_wc_1Dilithium_1PrivateKeyToDer
  (JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;
#if (defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)) && \
    defined(WC_JNI_MLDSA_HAVE_PRIV_KEY) && defined(WC_JNI_MLDSA_HAVE_ASN1)
    int ret = 0;
    wc_MlDsaKey* key = NULL;
    byte* output = NULL;
    word32 outputSz = 0;
    word32 outputBufSz = 0;

    key = (wc_MlDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    if (key == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    /* Two-pass: first call with NULL output to get required size. */
    ret = wc_MlDsaKey_PrivateKeyToDer(key, NULL, 0);
    if (ret <= 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return NULL;
    }
    outputSz = (word32)ret;
    outputBufSz = outputSz;

    output = (byte*)XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate PKCS#8 buffer");
        return NULL;
    }
    XMEMSET(output, 0, outputSz);

    ret = wc_MlDsaKey_PrivateKeyToDer(key, output, outputSz);
    if (ret > 0) {
        result = (*env)->NewByteArray(env, ret);
        if (result != NULL) {
            (*env)->SetByteArrayRegion(env, result, 0, ret,
                (const jbyte*)output);
        }
        else {
            throwWolfCryptException(env, "Failed to allocate PKCS#8 DER");
        }
    }
    else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlDsaKey_PrivateKeyToDer(key=%p) = %d\n", key, ret);

    MLDSA_FORCE_ZERO(output, outputBufSz);
    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
#endif
    return result;
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_MlDsaLevelEnabled
  (JNIEnv* env, jclass jcl, jint level)
{
    (void)env;
    (void)jcl;
#if defined(HAVE_DILITHIUM) || defined(WOLFSSL_HAVE_MLDSA)
    jboolean enabled = JNI_FALSE;
    wc_MlDsaKey* key = NULL;

    key = (wc_MlDsaKey*)XMALLOC(sizeof(wc_MlDsaKey), NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (key != NULL) {
        if (wc_MlDsaKey_Init(key, NULL, INVALID_DEVID) == 0) {
            if (wc_MlDsaKey_SetParams(key, (byte)level) == 0) {
                enabled = JNI_TRUE;
            }
            wc_MlDsaKey_Free(key);
        }
        XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return enabled;
#else
    (void)level;
    return JNI_FALSE;
#endif
}
