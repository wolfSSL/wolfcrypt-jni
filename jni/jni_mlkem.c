/* jni_mlkem.c
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
#ifdef HAVE_FIPS
    #include <wolfssl/wolfcrypt/fips.h>
#endif
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/memory.h>
#ifdef WOLFSSL_HAVE_MLKEM
    #include <wolfssl/wolfcrypt/wc_mlkem.h>
#endif

#include <com_wolfssl_wolfcrypt_MlKem.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

#if !defined(WC_NO_RNG) && defined(NO_OLD_RNGNAME)
    #define RNG WC_RNG
#endif

#ifdef WOLFSSL_HAVE_MLKEM

/* Zeroize sensitive buffer 'buf' of size 'sz' bytes, using wc_ForceZero
 * when available, otherwise XMEMSET. */
#if (LIBWOLFSSL_VERSION_HEX >= 0x05008004) && !defined(WOLFSSL_NO_FORCE_ZERO)
    #define MLKEM_FORCE_ZERO(buf, sz) wc_ForceZero((buf), (sz))
#else
    #define MLKEM_FORCE_ZERO(buf, sz) XMEMSET((buf), 0, (sz))
#endif

/* Map Java level (512/768/1024) to native WC_ML_KEM_* type. Returns the
 * native type on success, or -1 if the level is not recognized. */
static int mlkem_level_to_type(jint level)
{
    switch (level) {
        case 512:
            return WC_ML_KEM_512;
        case 768:
            return WC_ML_KEM_768;
        case 1024:
            return WC_ML_KEM_1024;
        default:
            return -1;
    }
}

#endif /* WOLFSSL_HAVE_MLKEM */

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_MlKem_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
#ifdef WOLFSSL_HAVE_MLKEM
    MlKemKey* key = NULL;

    key = (MlKemKey*)XMALLOC(sizeof(MlKemKey), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (key == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate MlKem object");
    }
    else {
        XMEMSET(key, 0, sizeof(MlKemKey));
    }

    LogStr("new MlKem() = %p\n", key);

    return (jlong)(uintptr_t)key;
#else
    (void)this;
    throwNotCompiledInException(env);

    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_MlKem_wc_1mlkem_1init(
    JNIEnv* env, jobject this, jint level)
{
#ifdef WOLFSSL_HAVE_MLKEM
    int ret = 0;
    int type = 0;
    MlKemKey* key = NULL;

    key = (MlKemKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    type = mlkem_level_to_type(level);
    if ((key == NULL) || (type < 0)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_MlKemKey_Init(key, type, NULL, INVALID_DEVID);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlKemKey_Init(key=%p, type=%d) = %d\n", key, type, ret);
#else
    (void)this;
    (void)level;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_MlKem_wc_1mlkem_1free(
    JNIEnv* env, jobject this)
{
#ifdef WOLFSSL_HAVE_MLKEM
    MlKemKey* key = (MlKemKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception */
        return;
    }

    if (key != NULL) {
        wc_MlKemKey_Free(key);
    }

    LogStr("wc_MlKemKey_Free(key=%p)\n", key);
#else
    (void)this;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_MlKem_wc_1mlkem_1make_1key(
    JNIEnv* env, jobject this, jobject rng_object)
{
#ifdef WOLFSSL_HAVE_MLKEM
    int ret = 0;
    MlKemKey* key = NULL;
    RNG* rng = NULL;

    key = (MlKemKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    rng = (RNG*) getNativeStruct(env, rng_object);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    if (key == NULL || rng == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_MlKemKey_MakeKey(key, rng);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlKemKey_MakeKey(key=%p) = %d\n", key, ret);
#else
    (void)this;
    (void)rng_object;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_MlKem_wc_1mlkem_1make_1key_1from_1seed(
    JNIEnv* env, jobject this, jbyteArray seed_object)
{
#ifdef WOLFSSL_HAVE_MLKEM
    int ret = 0;
    MlKemKey* key = NULL;
    byte* seed = NULL;
    word32 seedSz = 0;

    key = (MlKemKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    seed = getByteArray(env, seed_object);
    seedSz = getByteArrayLength(env, seed_object);

    /* getByteArray() can return NULL with a pending exception */
    if (seed_object != NULL && seed == NULL) {
        return;
    }

    if (key == NULL || seed == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_MlKemKey_MakeKeyWithRandom(key, seed, seedSz);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlKemKey_MakeKeyWithRandom(key=%p, seedSz=%u) = %d\n",
        key, (word32)seedSz, ret);

    releaseByteArray(env, seed_object, seed, JNI_ABORT);
#else
    (void)this;
    (void)seed_object;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_MlKem_wc_1mlkem_1encapsulate(
    JNIEnv* env, jobject this, jobject rng_object)
{
    jbyteArray result = NULL;

#ifdef WOLFSSL_HAVE_MLKEM
    int ret = 0;
    MlKemKey* key = NULL;
    RNG* rng = NULL;
    byte* output = NULL;
    word32 ctSz = 0;
    word32 ssSz = 0;
    word32 totalSz = 0;

    key = (MlKemKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    rng = (RNG*) getNativeStruct(env, rng_object);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    if (key == NULL || rng == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    ret = wc_MlKemKey_CipherTextSize(key, &ctSz);
    if (ret == 0) {
        ret = wc_MlKemKey_SharedSecretSize(key, &ssSz);
    }
    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return NULL;
    }

    totalSz = ctSz + ssSz;
    output = (byte*)XMALLOC(totalSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate encapsulation");
        return NULL;
    }
    XMEMSET(output, 0, totalSz);

    /* Native layout returned to Java: ciphertext || sharedSecret */
    ret = wc_MlKemKey_Encapsulate(key, output, output + ctSz, rng);

    if (ret == 0) {
        result = (*env)->NewByteArray(env, totalSz);
        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, totalSz,
                (const jbyte*) output);
        }
        else {
            throwWolfCryptException(env, "Failed to allocate encapsulation");
        }
    }
    else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlKemKey_Encapsulate(key=%p, ctSz=%u, ssSz=%u) = %d\n",
        key, (word32)ctSz, (word32)ssSz, ret);

    MLKEM_FORCE_ZERO(output, totalSz);
    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    (void)this;
    (void)rng_object;
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_MlKem_wc_1mlkem_1encapsulate_1with_1random(
    JNIEnv* env, jobject this, jbyteArray rand_object)
{
    jbyteArray result = NULL;

#ifdef WOLFSSL_HAVE_MLKEM
    int ret = 0;
    MlKemKey* key = NULL;
    byte* rand = NULL;
    word32 randSz = 0;
    byte* output = NULL;
    word32 ctSz = 0;
    word32 ssSz = 0;
    word32 totalSz = 0;

    key = (MlKemKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    rand = getByteArray(env, rand_object);
    randSz = getByteArrayLength(env, rand_object);

    /* getByteArray() can return NULL with a pending exception */
    if (rand_object != NULL && rand == NULL) {
        return NULL;
    }

    if (key == NULL || rand == NULL) {
        releaseByteArray(env, rand_object, rand, JNI_ABORT);
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    ret = wc_MlKemKey_CipherTextSize(key, &ctSz);
    if (ret == 0) {
        ret = wc_MlKemKey_SharedSecretSize(key, &ssSz);
    }
    if (ret != 0) {
        releaseByteArray(env, rand_object, rand, JNI_ABORT);
        throwWolfCryptExceptionFromError(env, ret);
        return NULL;
    }

    totalSz = ctSz + ssSz;
    output = (byte*)XMALLOC(totalSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        releaseByteArray(env, rand_object, rand, JNI_ABORT);
        throwOutOfMemoryException(env, "Failed to allocate encapsulation");
        return NULL;
    }
    XMEMSET(output, 0, totalSz);

    /* Native layout returned to Java: ciphertext || sharedSecret */
    ret = wc_MlKemKey_EncapsulateWithRandom(key, output, output + ctSz,
        rand, randSz);

    if (ret == 0) {
        result = (*env)->NewByteArray(env, totalSz);
        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, totalSz,
                (const jbyte*) output);
        }
        else {
            throwWolfCryptException(env, "Failed to allocate encapsulation");
        }
    }
    else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlKemKey_EncapsulateWithRandom(key=%p, ctSz=%u, ssSz=%u)"
        " = %d\n", key, (word32)ctSz, (word32)ssSz, ret);

    MLKEM_FORCE_ZERO(output, totalSz);
    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    releaseByteArray(env, rand_object, rand, JNI_ABORT);
#else
    (void)this;
    (void)rand_object;
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_MlKem_wc_1mlkem_1decapsulate(
    JNIEnv* env, jobject this, jbyteArray ct_object)
{
    jbyteArray result = NULL;

#ifdef WOLFSSL_HAVE_MLKEM
    int ret = 0;
    MlKemKey* key = NULL;
    byte* ct = NULL;
    word32 ctSz = 0;
    byte* output = NULL;
    word32 ssSz = 0;

    key = (MlKemKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    ct = getByteArray(env, ct_object);
    ctSz = getByteArrayLength(env, ct_object);

    /* getByteArray() can return NULL with a pending exception */
    if (ct_object != NULL && ct == NULL) {
        return NULL;
    }

    if (key == NULL || ct == NULL) {
        releaseByteArray(env, ct_object, ct, JNI_ABORT);
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    ret = wc_MlKemKey_SharedSecretSize(key, &ssSz);
    if (ret != 0) {
        releaseByteArray(env, ct_object, ct, JNI_ABORT);
        throwWolfCryptExceptionFromError(env, ret);
        return NULL;
    }

    output = (byte*)XMALLOC(ssSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        releaseByteArray(env, ct_object, ct, JNI_ABORT);
        throwOutOfMemoryException(env, "Failed to allocate shared secret");
        return NULL;
    }
    XMEMSET(output, 0, ssSz);

    PRIVATE_KEY_UNLOCK();
    ret = wc_MlKemKey_Decapsulate(key, output, ct, ctSz);
    PRIVATE_KEY_LOCK();

    if (ret == 0) {
        result = (*env)->NewByteArray(env, ssSz);
        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, ssSz,
                (const jbyte*) output);
        }
        else {
            throwWolfCryptException(env, "Failed to allocate shared secret");
        }
    }
    else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlKemKey_Decapsulate(key=%p, ctSz=%u, ssSz=%u) = %d\n",
        key, (word32)ctSz, (word32)ssSz, ret);

    MLKEM_FORCE_ZERO(output, ssSz);
    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    releaseByteArray(env, ct_object, ct, JNI_ABORT);
#else
    (void)this;
    (void)ct_object;
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_MlKem_wc_1mlkem_1export_1public(
    JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;

#ifdef WOLFSSL_HAVE_MLKEM
    int ret = 0;
    MlKemKey* key = NULL;
    byte* output = NULL;
    word32 outputSz = 0;

    key = (MlKemKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    if (key == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    ret = wc_MlKemKey_PublicKeySize(key, &outputSz);
    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return NULL;
    }

    output = (byte*)XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate public key");
        return NULL;
    }
    XMEMSET(output, 0, outputSz);

    ret = wc_MlKemKey_EncodePublicKey(key, output, outputSz);

    if (ret == 0) {
        result = (*env)->NewByteArray(env, outputSz);
        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, outputSz,
                (const jbyte*) output);
        }
        else {
            throwWolfCryptException(env, "Failed to allocate public key");
        }
    }
    else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlKemKey_EncodePublicKey(key=%p, outputSz=%u) = %d\n",
        key, (word32)outputSz, ret);

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    (void)this;
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_MlKem_wc_1mlkem_1export_1private(
    JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;

#ifdef WOLFSSL_HAVE_MLKEM
    int ret = 0;
    MlKemKey* key = NULL;
    byte* output = NULL;
    word32 outputSz = 0;

    key = (MlKemKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    if (key == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    ret = wc_MlKemKey_PrivateKeySize(key, &outputSz);
    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return NULL;
    }

    output = (byte*)XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate private key");
        return NULL;
    }
    XMEMSET(output, 0, outputSz);

    PRIVATE_KEY_UNLOCK();
    ret = wc_MlKemKey_EncodePrivateKey(key, output, outputSz);
    PRIVATE_KEY_LOCK();

    if (ret == 0) {
        result = (*env)->NewByteArray(env, outputSz);
        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, outputSz,
                (const jbyte*) output);
        }
        else {
            throwWolfCryptException(env, "Failed to allocate private key");
        }
    }
    else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlKemKey_EncodePrivateKey(key=%p, outputSz=%u) = %d\n",
        key, (word32)outputSz, ret);

    MLKEM_FORCE_ZERO(output, outputSz);
    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    (void)this;
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_MlKem_wc_1mlkem_1import_1public(
    JNIEnv* env, jobject this, jbyteArray pub_object)
{
#ifdef WOLFSSL_HAVE_MLKEM
    int ret = 0;
    MlKemKey* key = NULL;
    byte* pub = NULL;
    word32 pubSz = 0;

    key = (MlKemKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    pub = getByteArray(env, pub_object);
    pubSz = getByteArrayLength(env, pub_object);

    /* getByteArray() can return NULL with a pending exception */
    if (pub_object != NULL && pub == NULL) {
        return;
    }

    if (key == NULL || pub == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_MlKemKey_DecodePublicKey(key, pub, pubSz);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlKemKey_DecodePublicKey(key=%p, pubSz=%u) = %d\n",
        key, (word32)pubSz, ret);

    releaseByteArray(env, pub_object, pub, JNI_ABORT);
#else
    (void)this;
    (void)pub_object;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_MlKem_wc_1mlkem_1import_1private(
    JNIEnv* env, jobject this, jbyteArray priv_object)
{
#ifdef WOLFSSL_HAVE_MLKEM
    int ret = 0;
    MlKemKey* key = NULL;
    byte* priv = NULL;
    word32 privSz = 0;

    key = (MlKemKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    priv = getByteArray(env, priv_object);
    privSz = getByteArrayLength(env, priv_object);

    /* getByteArray() can return NULL with a pending exception */
    if (priv_object != NULL && priv == NULL) {
        return;
    }

    if (key == NULL || priv == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_MlKemKey_DecodePrivateKey(key, priv, privSz);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_MlKemKey_DecodePrivateKey(key=%p, privSz=%u) = %d\n",
        key, (word32)privSz, ret);

    releaseByteArray(env, priv_object, priv, JNI_ABORT);
#else
    (void)this;
    (void)priv_object;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_MlKem_wc_1mlkem_1public_1key_1size(
    JNIEnv* env, jobject this)
{
#ifdef WOLFSSL_HAVE_MLKEM
    int ret = 0;
    MlKemKey* key = NULL;
    word32 sz = 0;

    key = (MlKemKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return 0;
    }

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_MlKemKey_PublicKeySize(key, &sz);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return 0;
    }

    return (jint)sz;
#else
    (void)this;
    throwNotCompiledInException(env);
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_MlKem_wc_1mlkem_1private_1key_1size(
    JNIEnv* env, jobject this)
{
#ifdef WOLFSSL_HAVE_MLKEM
    int ret = 0;
    MlKemKey* key = NULL;
    word32 sz = 0;

    key = (MlKemKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return 0;
    }

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_MlKemKey_PrivateKeySize(key, &sz);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return 0;
    }

    return (jint)sz;
#else
    (void)this;
    throwNotCompiledInException(env);
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_MlKem_wc_1mlkem_1ciphertext_1size(
    JNIEnv* env, jobject this)
{
#ifdef WOLFSSL_HAVE_MLKEM
    int ret = 0;
    MlKemKey* key = NULL;
    word32 sz = 0;

    key = (MlKemKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return 0;
    }

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_MlKemKey_CipherTextSize(key, &sz);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return 0;
    }

    return (jint)sz;
#else
    (void)this;
    throwNotCompiledInException(env);
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_MlKem_wc_1mlkem_1shared_1secret_1size(
    JNIEnv* env, jobject this)
{
#ifdef WOLFSSL_HAVE_MLKEM
    int ret = 0;
    MlKemKey* key = NULL;
    word32 sz = 0;

    key = (MlKemKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return 0;
    }

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_MlKemKey_SharedSecretSize(key, &sz);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return 0;
    }

    return (jint)sz;
#else
    (void)this;
    throwNotCompiledInException(env);
    return 0;
#endif
}

