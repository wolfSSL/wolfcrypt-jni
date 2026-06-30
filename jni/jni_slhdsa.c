/* jni_slhdsa.c
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

#ifdef WOLFSSL_HAVE_SLHDSA
    #include <wolfssl/wolfcrypt/wc_slhdsa.h>
    #include <wolfssl/wolfcrypt/hash.h>
    #include <wolfssl/wolfcrypt/sha256.h>
    #include <wolfssl/wolfcrypt/sha512.h>
    #include <wolfssl/wolfcrypt/sha3.h>
#endif
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>

#include <com_wolfssl_wolfcrypt_SlhDsa.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

/* A WOLFSSL_SLHDSA_VERIFY_ONLY build provides only public-key verify. DER
 * encode (KeyToDer / PublicKeyToDer) additionally needs
 * WC_ENABLE_ASYM_KEY_EXPORT. */
#ifdef WOLFSSL_HAVE_SLHDSA

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    #define WC_JNI_SLHDSA_HAVE_MAKE_KEY
    #define WC_JNI_SLHDSA_HAVE_SIGN
    #define WC_JNI_SLHDSA_HAVE_PRIV_KEY
#endif
#ifdef WC_ENABLE_ASYM_KEY_EXPORT
    #define WC_JNI_SLHDSA_HAVE_ASN1_EXPORT
#endif

#endif /* WOLFSSL_HAVE_SLHDSA */

#ifdef WOLFSSL_HAVE_SLHDSA
/* FIPS 205 Section 10.2.2 HashSLH-DSA pre-hash digest lengths for the SHAKE
 * parameter sets: SHAKE128 produces a 256-bit (32-byte) output and SHAKE256 a
 * 512-bit (64-byte) output. wolfSSL has no fixed-size constant for these XOFs,
 * so name them explicitly here rather than borrowing the SHA-2 sizes. */
#define WC_JNI_SLHDSA_SHAKE128_PH_LEN 32
#define WC_JNI_SLHDSA_SHAKE256_PH_LEN 64

/* Maximum FIPS 205 pre-hash digest length across the PH functions
 * (SHA-256 = 32, SHA-512 = 64, SHAKE128 = 32, SHAKE256 = 64), used to size
 * local digest buffers. */
#ifdef WOLFSSL_SHA512
    #define WC_JNI_SLHDSA_MAX_PH_LEN WC_SHA512_DIGEST_SIZE
#else
    #define WC_JNI_SLHDSA_MAX_PH_LEN WC_JNI_SLHDSA_SHAKE256_PH_LEN
#endif

/* Compute the FIPS 205 Section 10.2.2 HashSLH-DSA pre-hash PH(msg) into the
 * caller's 64-byte digest buffer, selecting the hash function and digest
 * length from the key's parameter set per the standardized pre-hash OIDs:
 *   SHA2-128  -> SHA-256  (32 bytes)
 *   SHA2-192/256 -> SHA-512  (64 bytes)
 *   SHAKE-128 -> SHAKE128 (32 bytes)
 *   SHAKE-192/256 -> SHAKE256 (64 bytes)
 * On success returns 0 and sets *digestLen and *hashType. */
static int slhdsa_prehash_msg(SlhDsaKey* key, const byte* msg, word32 msgLen,
    byte* digest, word32* digestLen, enum wc_HashType* hashType)
{
    int ret;
    int param;
    int category;

    if (key == NULL || key->params == NULL || digest == NULL ||
        digestLen == NULL || hashType == NULL) {
        return BAD_FUNC_ARG;
    }

    param = (int)key->params->param;
    /* Category index: 0 = 128-bit, 1 = 192-bit, 2 = 256-bit. */
    category = (param % 6) / 2;

    if (SLHDSA_IS_SHA2(param)) {
        if (category == 0) {
#ifndef NO_SHA256
            ret = wc_Sha256Hash(msg, msgLen, digest);
            *digestLen = WC_SHA256_DIGEST_SIZE;
            *hashType = WC_HASH_TYPE_SHA256;
#else
            ret = NOT_COMPILED_IN;
#endif
        }
        else {
#ifdef WOLFSSL_SHA512
            ret = wc_Sha512Hash(msg, msgLen, digest);
            *digestLen = WC_SHA512_DIGEST_SIZE;
            *hashType = WC_HASH_TYPE_SHA512;
#else
            ret = NOT_COMPILED_IN;
#endif
        }
    }
    else {
        if (category == 0) {
#ifdef WOLFSSL_SHAKE128
            ret = wc_Shake128Hash(msg, msgLen, digest,
                WC_JNI_SLHDSA_SHAKE128_PH_LEN);
            *digestLen = WC_JNI_SLHDSA_SHAKE128_PH_LEN;
            *hashType = WC_HASH_TYPE_SHAKE128;
#else
            ret = NOT_COMPILED_IN;
#endif
        }
        else {
#ifdef WOLFSSL_SHAKE256
            ret = wc_Shake256Hash(msg, msgLen, digest,
                WC_JNI_SLHDSA_SHAKE256_PH_LEN);
            *digestLen = WC_JNI_SLHDSA_SHAKE256_PH_LEN;
            *hashType = WC_HASH_TYPE_SHAKE256;
#else
            ret = NOT_COMPILED_IN;
#endif
        }
    }

    return ret;
}
#endif /* WOLFSSL_HAVE_SLHDSA */

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_mallocNativeStruct
  (JNIEnv* env, jobject this)
{
#ifdef WOLFSSL_HAVE_SLHDSA
    SlhDsaKey* key = NULL;

    key = (SlhDsaKey*)XMALLOC(sizeof(SlhDsaKey), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (key == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate SlhDsa object");
    }
    else {
        XMEMSET(key, 0, sizeof(SlhDsaKey));
    }

    LogStr("new SlhDsa() = %p\n", key);

    return (jlong)(uintptr_t)key;
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1init
  (JNIEnv* env, jobject this, jint param)
{
#ifdef WOLFSSL_HAVE_SLHDSA
    int ret = 0;
    SlhDsaKey* key = NULL;

    key = (SlhDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_SlhDsaKey_Init(key, (enum SlhDsaParam)param, NULL,
            INVALID_DEVID);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_SlhDsaKey_Init(key=%p, param=%d) = %d\n", key, (int)param, ret);
#else
    (void)env;
    (void)this;
    (void)param;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1free
  (JNIEnv* env, jobject this)
{
#ifdef WOLFSSL_HAVE_SLHDSA
    SlhDsaKey* key = NULL;

    key = (SlhDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    if (key != NULL) {
        wc_SlhDsaKey_Free(key);
    }

    LogStr("wc_SlhDsaKey_Free(key=%p)\n", key);
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1get_1param
  (JNIEnv* env, jobject this)
{
#ifdef WOLFSSL_HAVE_SLHDSA
    SlhDsaKey* key = (SlhDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return -1;
    }

    if (key == NULL || key->params == NULL) {
        return -1;
    }

    return (jint)key->params->param;
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
    return -1;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1make_1key
  (JNIEnv* env, jobject this, jobject rng_object)
{
#if defined(WOLFSSL_HAVE_SLHDSA) && defined(WC_JNI_SLHDSA_HAVE_MAKE_KEY)
    int ret = 0;
    SlhDsaKey* key = NULL;
    WC_RNG* rng = NULL;

    key = (SlhDsaKey*) getNativeStruct(env, this);
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
        ret = wc_SlhDsaKey_MakeKey(key, rng);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_SlhDsaKey_MakeKey(key=%p) = %d\n", key, ret);
#else
    (void)env;
    (void)this;
    (void)rng_object;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1make_1key_1with_1seeds
  (JNIEnv* env, jobject this, jbyteArray skSeed_object, jbyteArray skPrf_object, jbyteArray pkSeed_object)
{
#if defined(WOLFSSL_HAVE_SLHDSA) && defined(WC_JNI_SLHDSA_HAVE_MAKE_KEY)
    int ret = 0;
    SlhDsaKey* key = NULL;
    byte* skSeed = NULL;
    byte* skPrf = NULL;
    byte* pkSeed = NULL;
    word32 skSeedLen = 0;
    word32 skPrfLen = 0;
    word32 pkSeedLen = 0;

    key = (SlhDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    if (skSeed_object != NULL) {
        skSeed = getByteArray(env, skSeed_object);
        skSeedLen = getByteArrayLength(env, skSeed_object);
    }

    if (skPrf_object != NULL) {
        skPrf = getByteArray(env, skPrf_object);
        skPrfLen = getByteArrayLength(env, skPrf_object);
    }

    if (pkSeed_object != NULL) {
        pkSeed = getByteArray(env, pkSeed_object);
        pkSeedLen = getByteArrayLength(env, pkSeed_object);
    }

    if ((skSeed_object != NULL && skSeed == NULL) ||
        (skPrf_object != NULL && skPrf == NULL) ||
        (pkSeed_object != NULL && pkSeed == NULL)) {

        if (skSeed != NULL) {
            releaseByteArray(env, skSeed_object, skSeed, JNI_ABORT);
        }
        if (skPrf != NULL) {
            releaseByteArray(env, skPrf_object, skPrf, JNI_ABORT);
        }
        if (pkSeed != NULL) {
            releaseByteArray(env, pkSeed_object, pkSeed, JNI_ABORT);
        }
        return;
    }

    if (key == NULL || skSeed == NULL || skPrf == NULL || pkSeed == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_SlhDsaKey_MakeKeyWithRandom(key, skSeed, skSeedLen,
            skPrf, skPrfLen, pkSeed, pkSeedLen);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_SlhDsaKey_MakeKeyWithRandom(key=%p) = %d\n", key, ret);

    if (skSeed_object != NULL) {
        releaseByteArray(env, skSeed_object, skSeed, JNI_ABORT);
    }
    if (skPrf_object != NULL) {
        releaseByteArray(env, skPrf_object, skPrf, JNI_ABORT);
    }
    if (pkSeed_object != NULL) {
        releaseByteArray(env, pkSeed_object, pkSeed, JNI_ABORT);
    }
#else
    (void)env;
    (void)this;
    (void)skSeed_object;
    (void)skPrf_object;
    (void)pkSeed_object;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1sign
  (JNIEnv* env, jobject this, jbyteArray ctx_object, jbyteArray msg_object, jobject rng_object)
{
    jbyteArray result = NULL;
#if defined(WOLFSSL_HAVE_SLHDSA) && defined(WC_JNI_SLHDSA_HAVE_SIGN)
    int ret = 0;
    int sigSz = 0;
    SlhDsaKey* key = NULL;
    WC_RNG* rng = NULL;
    byte* ctx = NULL;
    byte* msg = NULL;
    byte* sig = NULL;
    word32 ctxLen = 0;
    word32 msgLen = 0;
    word32 sigLen = 0;

    key = (SlhDsaKey*) getNativeStruct(env, this);
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

    /* FIPS 205 caps context length at 255 bytes (also enforced in Java). */
    if (ctxLen > com_wolfssl_wolfcrypt_SlhDsa_SLH_DSA_MAX_CONTEXT_LEN) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        sigSz = wc_SlhDsaKey_SigSize(key);
        if (sigSz < 0) {
            ret = sigSz;
        }
        else {
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
        ret = wc_SlhDsaKey_Sign(key, ctx, (byte)ctxLen, msg, msgLen,
            sig, &sigLen, rng);
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

    LogStr("wc_SlhDsaKey_Sign(key=%p) = %d\n", key, ret);

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

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1sign_1msg_1prehash
  (JNIEnv* env, jobject this, jbyteArray ctx_object, jbyteArray msg_object, jobject rng_object)
{
    jbyteArray result = NULL;
#if defined(WOLFSSL_HAVE_SLHDSA) && defined(WC_JNI_SLHDSA_HAVE_SIGN)
    int ret = 0;
    int sigSz = 0;
    SlhDsaKey* key = NULL;
    WC_RNG* rng = NULL;
    byte* ctx = NULL;
    byte* msg = NULL;
    byte* sig = NULL;
    word32 ctxLen = 0;
    word32 msgLen = 0;
    word32 sigLen = 0;
    byte digest[WC_JNI_SLHDSA_MAX_PH_LEN];
    word32 digestLen = 0;
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;

    key = (SlhDsaKey*) getNativeStruct(env, this);
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

    /* FIPS 205 caps context length at 255 bytes (also enforced in Java). */
    if (ctxLen > com_wolfssl_wolfcrypt_SlhDsa_SLH_DSA_MAX_CONTEXT_LEN) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = slhdsa_prehash_msg(key, msg, msgLen, digest, &digestLen,
            &hashType);
    }

    if (ret == 0) {
        sigSz = wc_SlhDsaKey_SigSize(key);
        if (sigSz < 0) {
            ret = sigSz;
        }
        else {
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
        ret = wc_SlhDsaKey_SignHash(key, ctx, (byte)ctxLen, digest, digestLen,
            hashType, sig, &sigLen, rng);
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

    LogStr("wc_SlhDsaKey_SignHash(prehash, key=%p) = %d\n", key, ret);

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

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1sign_1deterministic
  (JNIEnv* env, jobject this, jbyteArray ctx_object, jbyteArray msg_object)
{
    jbyteArray result = NULL;
#if defined(WOLFSSL_HAVE_SLHDSA) && defined(WC_JNI_SLHDSA_HAVE_SIGN)
    int ret = 0;
    int sigSz = 0;
    SlhDsaKey* key = NULL;
    byte* ctx = NULL;
    byte* msg = NULL;
    byte* sig = NULL;
    word32 ctxLen = 0;
    word32 msgLen = 0;
    word32 sigLen = 0;

    key = (SlhDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    if (key == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    if (ctx_object != NULL) {
        ctx = getByteArray(env, ctx_object);
        ctxLen = getByteArrayLength(env, ctx_object);
    }

    if (msg_object != NULL) {
        msg = getByteArray(env, msg_object);
        msgLen = getByteArrayLength(env, msg_object);
    }

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

    /* FIPS 205 caps context length at 255 bytes (also enforced in Java). */
    if (ctxLen > com_wolfssl_wolfcrypt_SlhDsa_SLH_DSA_MAX_CONTEXT_LEN) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        sigSz = wc_SlhDsaKey_SigSize(key);
        if (sigSz < 0) {
            ret = sigSz;
        }
        else {
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
        ret = wc_SlhDsaKey_SignDeterministic(key, ctx, (byte)ctxLen, msg,
            msgLen, sig, &sigLen);
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

    LogStr("wc_SlhDsaKey_SignDeterministic(key=%p) = %d\n", key, ret);

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
    throwNotCompiledInException(env);
#endif
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1sign_1hash
  (JNIEnv* env, jobject this, jbyteArray ctx_object, jint hashAlg, jbyteArray hash_object, jobject rng_object)
{
    jbyteArray result = NULL;
#if defined(WOLFSSL_HAVE_SLHDSA) && defined(WC_JNI_SLHDSA_HAVE_SIGN)
    int ret = 0;
    int sigSz = 0;
    SlhDsaKey* key = NULL;
    WC_RNG* rng = NULL;
    byte* ctx = NULL;
    byte* hash = NULL;
    byte* sig = NULL;
    word32 ctxLen = 0;
    word32 hashLen = 0;
    word32 sigLen = 0;

    key = (SlhDsaKey*) getNativeStruct(env, this);
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

    if (ctx_object != NULL) {
        ctx = getByteArray(env, ctx_object);
        ctxLen = getByteArrayLength(env, ctx_object);
    }

    if (hash_object != NULL) {
        hash = getByteArray(env, hash_object);
        hashLen = getByteArrayLength(env, hash_object);
    }

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

    /* FIPS 205 caps context length at 255 bytes. */
    if (ctxLen > com_wolfssl_wolfcrypt_SlhDsa_SLH_DSA_MAX_CONTEXT_LEN) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        sigSz = wc_SlhDsaKey_SigSize(key);
        if (sigSz < 0) {
            ret = sigSz;
        }
        else {
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
        ret = wc_SlhDsaKey_SignHash(key, ctx, (byte)ctxLen, hash, hashLen,
            (enum wc_HashType)hashAlg, sig, &sigLen, rng);
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

    LogStr("wc_SlhDsaKey_SignHash(key=%p) = %d\n", key, ret);

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

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1verify
  (JNIEnv* env, jobject this, jbyteArray sig_object, jbyteArray ctx_object, jbyteArray msg_object)
{
    jboolean result = JNI_FALSE;
#ifdef WOLFSSL_HAVE_SLHDSA
    int ret = 0;
    SlhDsaKey* key = NULL;
    byte* sig = NULL;
    byte* ctx = NULL;
    byte* msg = NULL;
    word32 sigLen = 0;
    word32 ctxLen = 0;
    word32 msgLen = 0;

    key = (SlhDsaKey*) getNativeStruct(env, this);
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

    /* FIPS 205 caps context length at 255 bytes. */
    if (ctxLen > com_wolfssl_wolfcrypt_SlhDsa_SLH_DSA_MAX_CONTEXT_LEN) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = wc_SlhDsaKey_Verify(key, ctx, (byte)ctxLen, msg, msgLen,
            sig, sigLen);
    }

    if (ret == 0) {
        result = JNI_TRUE;
    }
    else if (ret != SIG_VERIFY_E && ret != BAD_LENGTH_E) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_SlhDsaKey_Verify(key=%p) = %d\n", key, ret);

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

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1verify_1msg_1prehash
  (JNIEnv* env, jobject this, jbyteArray sig_object, jbyteArray ctx_object, jbyteArray msg_object)
{
    jboolean result = JNI_FALSE;
#ifdef WOLFSSL_HAVE_SLHDSA
    int ret = 0;
    SlhDsaKey* key = NULL;
    byte* sig = NULL;
    byte* ctx = NULL;
    byte* msg = NULL;
    word32 sigLen = 0;
    word32 ctxLen = 0;
    word32 msgLen = 0;
    byte digest[WC_JNI_SLHDSA_MAX_PH_LEN];
    word32 digestLen = 0;
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;

    key = (SlhDsaKey*) getNativeStruct(env, this);
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

    /* FIPS 205 caps context length at 255 bytes. */
    if (ctxLen > com_wolfssl_wolfcrypt_SlhDsa_SLH_DSA_MAX_CONTEXT_LEN) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = slhdsa_prehash_msg(key, msg, msgLen, digest, &digestLen,
            &hashType);
    }

    if (ret == 0) {
        ret = wc_SlhDsaKey_VerifyHash(key, ctx, (byte)ctxLen, digest,
            digestLen, hashType, sig, sigLen);
    }

    if (ret == 0) {
        result = JNI_TRUE;
    }
    else if (ret != SIG_VERIFY_E && ret != BAD_LENGTH_E) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_SlhDsaKey_VerifyHash(prehash, key=%p) = %d\n", key, ret);

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

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1verify_1hash
  (JNIEnv* env, jobject this, jbyteArray sig_object, jbyteArray ctx_object, jint hashAlg, jbyteArray hash_object)
{
    jboolean result = JNI_FALSE;
#ifdef WOLFSSL_HAVE_SLHDSA
    int ret = 0;
    SlhDsaKey* key = NULL;
    byte* sig = NULL;
    byte* ctx = NULL;
    byte* hash = NULL;
    word32 sigLen = 0;
    word32 ctxLen = 0;
    word32 hashLen = 0;

    key = (SlhDsaKey*) getNativeStruct(env, this);
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

    /* FIPS 205 caps context length at 255 bytes. */
    if (ctxLen > com_wolfssl_wolfcrypt_SlhDsa_SLH_DSA_MAX_CONTEXT_LEN) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = wc_SlhDsaKey_VerifyHash(key, ctx, (byte)ctxLen, hash, hashLen,
            (enum wc_HashType)hashAlg, sig, sigLen);
    }

    if (ret == 0) {
        result = JNI_TRUE;
    }
    else if (ret != SIG_VERIFY_E && ret != BAD_LENGTH_E) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_SlhDsaKey_VerifyHash(key=%p) = %d\n", key, ret);

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

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1export_1public
  (JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;
#ifdef WOLFSSL_HAVE_SLHDSA
    int ret = 0;
    int pubSz = 0;
    SlhDsaKey* key = NULL;
    byte* output = NULL;
    word32 outputSz = 0;

    key = (SlhDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    if (key == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    pubSz = wc_SlhDsaKey_PublicSize(key);
    if (pubSz < 0) {
        throwWolfCryptExceptionFromError(env, pubSz);
        return NULL;
    }
    outputSz = (word32)pubSz;

    output = (byte*)XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate public key buffer");
        return NULL;
    }
    XMEMSET(output, 0, outputSz);

    ret = wc_SlhDsaKey_ExportPublic(key, output, &outputSz);
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

    LogStr("wc_SlhDsaKey_ExportPublic(key=%p) = %d\n", key, ret);

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
#endif
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1export_1private
  (JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;
#if defined(WOLFSSL_HAVE_SLHDSA) && defined(WC_JNI_SLHDSA_HAVE_PRIV_KEY)
    int ret = 0;
    int privSz = 0;
    SlhDsaKey* key = NULL;
    byte* output = NULL;
    word32 outputSz = 0;
    word32 outputBufSz = 0;

    key = (SlhDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    if (key == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    privSz = wc_SlhDsaKey_PrivateSize(key);
    if (privSz < 0) {
        throwWolfCryptExceptionFromError(env, privSz);
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

    ret = wc_SlhDsaKey_ExportPrivate(key, output, &outputSz);
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

    LogStr("wc_SlhDsaKey_ExportPrivate(key=%p) = %d\n", key, ret);

    wc_ForceZero(output, outputBufSz);
    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
#endif
    return result;
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1import_1public
  (JNIEnv* env, jobject this, jbyteArray in_object)
{
#ifdef WOLFSSL_HAVE_SLHDSA
    int ret = 0;
    SlhDsaKey* key = NULL;
    byte* in = NULL;
    word32 inLen = 0;

    key = (SlhDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    in = getByteArray(env, in_object);
    inLen = getByteArrayLength(env, in_object);

    if (key == NULL || in == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_SlhDsaKey_ImportPublic(key, in, inLen);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_SlhDsaKey_ImportPublic(key=%p) = %d\n", key, ret);

    releaseByteArray(env, in_object, in, JNI_ABORT);
#else
    (void)env;
    (void)this;
    (void)in_object;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1import_1private
  (JNIEnv* env, jobject this, jbyteArray in_object)
{
#if defined(WOLFSSL_HAVE_SLHDSA) && defined(WC_JNI_SLHDSA_HAVE_PRIV_KEY)
    int ret = 0;
    SlhDsaKey* key = NULL;
    byte* in = NULL;
    word32 inLen = 0;

    key = (SlhDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    in = getByteArray(env, in_object);
    inLen = getByteArrayLength(env, in_object);

    if (key == NULL || in == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_SlhDsaKey_ImportPrivate(key, in, inLen);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_SlhDsaKey_ImportPrivate(key=%p) = %d\n", key, ret);

    releaseByteArray(env, in_object, in, JNI_ABORT);
#else
    (void)env;
    (void)this;
    (void)in_object;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1PublicKeyToDer
  (JNIEnv* env, jobject this, jboolean withAlg)
{
    jbyteArray result = NULL;
#if defined(WOLFSSL_HAVE_SLHDSA) && defined(WC_JNI_SLHDSA_HAVE_ASN1_EXPORT)
    int ret = 0;
    SlhDsaKey* key = NULL;
    byte* output = NULL;
    word32 outputSz = 0;

    key = (SlhDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    if (key == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    /* Call with NULL output to get required size. */
    ret = wc_SlhDsaKey_PublicKeyToDer(key, NULL, 0, (int)withAlg);
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

    ret = wc_SlhDsaKey_PublicKeyToDer(key, output, outputSz, (int)withAlg);
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

    LogStr("wc_SlhDsaKey_PublicKeyToDer(key=%p) = %d\n", key, ret);

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    (void)env;
    (void)this;
    (void)withAlg;
    throwNotCompiledInException(env);
#endif
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1KeyToDer
  (JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;
#if defined(WOLFSSL_HAVE_SLHDSA) && defined(WC_JNI_SLHDSA_HAVE_PRIV_KEY) && \
    defined(WC_JNI_SLHDSA_HAVE_ASN1_EXPORT)
    int ret = 0;
    SlhDsaKey* key = NULL;
    byte* output = NULL;
    word32 outputSz = 0;
    word32 outputBufSz = 0;

    key = (SlhDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    if (key == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    /* Call with NULL output to get required size. */
    ret = wc_SlhDsaKey_KeyToDer(key, NULL, 0);
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

    ret = wc_SlhDsaKey_KeyToDer(key, output, outputSz);
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

    LogStr("wc_SlhDsaKey_KeyToDer(key=%p) = %d\n", key, ret);

    wc_ForceZero(output, outputBufSz);
    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
#endif
    return result;
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1PublicKeyDecode
  (JNIEnv* env, jobject this, jbyteArray der_object)
{
#ifdef WOLFSSL_HAVE_SLHDSA
    int ret = 0;
    SlhDsaKey* key = NULL;
    byte* der = NULL;
    word32 derLen = 0;
    word32 idx = 0;

    key = (SlhDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    der = getByteArray(env, der_object);
    derLen = getByteArrayLength(env, der_object);

    if (key == NULL || der == NULL || derLen == 0) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_SlhDsaKey_PublicKeyDecode(der, &idx, key, derLen);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_SlhDsaKey_PublicKeyDecode(key=%p) = %d\n", key, ret);

    releaseByteArray(env, der_object, der, JNI_ABORT);
#else
    (void)env;
    (void)this;
    (void)der_object;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1PrivateKeyDecode
  (JNIEnv* env, jobject this, jbyteArray der_object)
{
#if defined(WOLFSSL_HAVE_SLHDSA) && defined(WC_JNI_SLHDSA_HAVE_PRIV_KEY)
    int ret = 0;
    SlhDsaKey* key = NULL;
    byte* der = NULL;
    byte* derCopy = NULL;
    word32 derLen = 0;
    word32 idx = 0;

    key = (SlhDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    der = getByteArray(env, der_object);
    derLen = getByteArrayLength(env, der_object);

    if (key == NULL || der == NULL || derLen == 0) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Copy because PrivateKeyDecode may modify the input buffer. */
        derCopy = (byte*)XMALLOC(derLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (derCopy == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMCPY(derCopy, der, derLen);
        }
    }

    if (ret == 0) {
        ret = wc_SlhDsaKey_PrivateKeyDecode(derCopy, &idx, key, derLen);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_SlhDsaKey_PrivateKeyDecode(key=%p) = %d\n", key, ret);

    if (derCopy != NULL) {
        wc_ForceZero(derCopy, derLen);
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

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1pub_1size
  (JNIEnv* env, jobject this)
{
#ifdef WOLFSSL_HAVE_SLHDSA
    int ret = 0;
    SlhDsaKey* key = (SlhDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return 0;
    }

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_SlhDsaKey_PublicSize(key);
    }

    if (ret < 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return 0;
    }
    return (jint)ret;
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1priv_1size
  (JNIEnv* env, jobject this)
{
#if defined(WOLFSSL_HAVE_SLHDSA) && defined(WC_JNI_SLHDSA_HAVE_PRIV_KEY)
    int ret = 0;
    SlhDsaKey* key = (SlhDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return 0;
    }

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_SlhDsaKey_PrivateSize(key);
    }

    if (ret < 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return 0;
    }
    return (jint)ret;
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1sig_1size
  (JNIEnv* env, jobject this)
{
#ifdef WOLFSSL_HAVE_SLHDSA
    int ret = 0;
    SlhDsaKey* key = (SlhDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return 0;
    }

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_SlhDsaKey_SigSize(key);
    }

    if (ret < 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return 0;
    }
    return (jint)ret;
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
    return 0;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_SlhDsa_wc_1SlhDsaKey_1check_1key
  (JNIEnv* env, jobject this)
{
#if defined(WOLFSSL_HAVE_SLHDSA) && defined(WC_JNI_SLHDSA_HAVE_PRIV_KEY)
    int ret = 0;
    SlhDsaKey* key = NULL;

    key = (SlhDsaKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_SlhDsaKey_CheckKey(key);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_SlhDsaKey_CheckKey(key=%p) = %d\n", key, ret);
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
#endif
}
