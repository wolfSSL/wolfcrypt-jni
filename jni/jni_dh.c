/* jni_dh.c
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
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include <com_wolfssl_wolfcrypt_Dh.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

#if !defined(WC_NO_RNG) && defined(NO_OLD_RNGNAME)
    #define RNG WC_RNG
#endif

/* Some FIPS versions don't have DH_MAX_SIZE defined */
#ifndef DH_MAX_SIZE
    #ifdef USE_FAST_MATH
        /* FP implementation support numbers up to FP_MAX_BITS / 2 bits. */
        #define DH_MAX_SIZE    (FP_MAX_BITS / 2)
    #elif defined(WOLFSSL_SP_MATH_ALL) || defined(WOLFSSL_SP_MATH)
        /* SP implementation supports numbers of SP_INT_BITS bits. */
        #define DH_MAX_SIZE    (((SP_INT_BITS + 7) / 8) * 8)
    #else
        #ifdef WOLFSSL_MYSQL_COMPATIBLE
            /* Integer maths is dynamic but we only go up to 8192 bits. */
            #define DH_MAX_SIZE 8192
        #else
            /* Integer maths is dynamic but we only go up to 4096 bits. */
            #define DH_MAX_SIZE 4096
        #endif
    #endif
#endif

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Dh_mallocNativeStruct_1internal(
    JNIEnv* env, jobject this)
{
#ifndef NO_DH
    DhKey* dh = NULL;

    dh = (DhKey*)XMALLOC(sizeof(DhKey), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (dh == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate Dh object");
    }
    else {
        XMEMSET(dh, 0, sizeof(DhKey));
    }

    LogStr("new Dh() = %p\n", dh);

    return (jlong)(uintptr_t)dh;
#else
    throwNotCompiledInException(env);

    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Dh_wc_1InitDhKey(
    JNIEnv* env, jobject this)
{
#ifndef NO_DH
    int ret = 0;
    DhKey* key = (DhKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception */
        return;
    }

    ret = wc_InitDhKey(key);
    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_InitDhKey(key=%p)\n", key);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Dh_wc_1FreeDhKey(
    JNIEnv* env, jobject this)
{
#ifndef NO_DH
    int ret = 0;
    DhKey* key = (DhKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception */
        return;
    }

    ret = wc_FreeDhKey(key);
    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_FreeDhKey(key=%p)\n", key);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Dh_wc_1DhSetKey(
    JNIEnv* env, jobject this, jbyteArray p_object, jbyteArray g_object)
{
#ifndef NO_DH
    int ret = 0;
    DhKey* key = NULL;
    byte* p = NULL;
    byte* g = NULL;
    word32 pSz = 0, gSz = 0;

    key = (DhKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    p = getByteArray(env, p_object);
    pSz = getByteArrayLength(env, p_object);
    g = getByteArray(env, g_object);
    gSz = getByteArrayLength(env, g_object);

    if (key == NULL || p == NULL || g == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_DhSetKey(key, p, pSz, g, gSz);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_DhSetKey(key=%p, p, pSz, g, gSz) = %d\n", key, ret);
    LogStr("p[%u]: [%p]\n", (word32)pSz, p);
    LogHex((byte*) p, 0, pSz);
    LogStr("g[%u]: [%p]\n", (word32)gSz, g);
    LogHex((byte*) g, 0, gSz);

    releaseByteArray(env, p_object, p, JNI_ABORT);
    releaseByteArray(env, g_object, g, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Dh_wc_1DhGenerateKeyPair(
    JNIEnv* env, jobject this, jobject rng_object, jint size)
{
#ifndef NO_DH
    int ret = 0;
    DhKey* key = NULL;
    RNG* rng   = NULL;
    byte* priv = NULL;
    byte* pub  = NULL;
    word32 privSz = size;
    word32 pubSz  = size;
    int lBitPriv = 0, lBitPub  = 0;
    byte lBit[1] = { 0x00 };
    int exceptionThrown = 0;

    key = (DhKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    rng = (RNG*) getNativeStruct(env, rng_object);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    if (key == NULL || rng == NULL || (size < 0)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {

        priv = XMALLOC(privSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (priv == NULL) {
            throwOutOfMemoryException(env,
                "Failed to allocate private key buffer");
            return;
        }
        XMEMSET(priv, 0, privSz);

        pub = XMALLOC(pubSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (pub == NULL) {
            XFREE(priv, NULL, DYNAMIC_TYPE_TMP_BUFFER);

            throwOutOfMemoryException(env,
                "Failed to allocate public key buffer");
            return;
        }
        XMEMSET(pub, 0, pubSz);

        PRIVATE_KEY_UNLOCK();
        ret = wc_DhGenerateKeyPair(key, rng, priv, &privSz, pub, &pubSz);
        PRIVATE_KEY_LOCK();
    }

    if (ret == 0) {

        /* keys should be positive, if leading bit is set, add zero byte */
        if (priv[0] & 0x80) {
            lBitPriv = 1;
        }

        if (pub[0] & 0x80) {
            lBitPub = 1;
        }

        jbyteArray privateKey = (*env)->NewByteArray(env, lBitPriv + privSz);
        jbyteArray publicKey  = (*env)->NewByteArray(env, lBitPub + pubSz);

        if (privateKey) {
            if (lBitPriv) {
                (*env)->SetByteArrayRegion(env, privateKey, 0, 1,
                                                            (const jbyte*)lBit);
                (*env)->SetByteArrayRegion(env, privateKey, 1, privSz,
                                                            (const jbyte*)priv);
            } else {
                (*env)->SetByteArrayRegion(env, privateKey, 0, privSz,
                                                            (const jbyte*)priv);
            }

            setByteArrayMember(env, this, "privateKey", privateKey);
            if ((*env)->ExceptionOccurred(env)) {
                /* if exception raised, skip any additional JNI functions */
                exceptionThrown = 1;
            }

        } else {
            throwWolfCryptException(env, "Failed to allocate privateKey");
            exceptionThrown = 1;
        }

        if (publicKey && (exceptionThrown == 0)) {
            if (lBitPub) {
                (*env)->SetByteArrayRegion(env, publicKey, 0, 1,
                                                            (const jbyte*)lBit);
                (*env)->SetByteArrayRegion(env, publicKey, 1, pubSz,
                                                             (const jbyte*)pub);
            } else {
                (*env)->SetByteArrayRegion(env, publicKey, 0, pubSz,
                                                             (const jbyte*)pub);
            }

            setByteArrayMember(env, this, "publicKey", publicKey);
        } else {
            throwWolfCryptException(env, "Failed to allocate publicKey");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_DhGenerateKeyPair(key, rng, priv, privSz, pub, pubSz) = %d\n",
        ret);
    LogStr("private[%u]: [%p]\n", privSz, priv);
    LogHex(priv, 0, privSz);
    LogStr("public[%u]: [%p]\n", pubSz, pub);
    LogHex(pub, 0, pubSz);

    if (priv != NULL) {
        XMEMSET(priv, 0, privSz);
        XFREE(priv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (pub != NULL) {
        XMEMSET(pub, 0, pubSz);
        XFREE(pub, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Dh_wc_1DhCheckPubKey(
    JNIEnv* env, jobject this, jbyteArray pub_object)
{
#ifndef NO_DH
    int ret = 0;
    DhKey* key = NULL;
    byte*  pub = NULL;
    word32 pubSz = 0;

    key = (DhKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    pub   = getByteArray(env, pub_object);
    pubSz = getByteArrayLength(env, pub_object);

    if (key == NULL || pub == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_DhCheckPubKey(key, pub, pubSz);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_DhCheckPubKey(key=%p, pub, pubSz) = %d\n", key, ret);
    LogStr("p[%u]: [%p]\n", (word32)pubSz, pub);
    LogHex((byte*) pub, 0, pubSz);

    releaseByteArray(env, pub_object, pub, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Dh_wc_1DhAgree(
    JNIEnv* env, jobject this, jbyteArray priv_object, jbyteArray pub_object)
{
    jbyteArray result = NULL;

#ifndef NO_DH
    int ret = 0;
    DhKey* key = NULL;
    byte* priv = NULL;
    byte* pub  = NULL;
    byte* secret = NULL;
    word32 privSz = 0, pubSz = 0, secretSz = 0;

    key = (DhKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    priv   = getByteArray(env, priv_object);
    privSz = getByteArrayLength(env, priv_object);
    pub    = getByteArray(env, pub_object);
    pubSz  = getByteArrayLength(env, pub_object);

    /* Use safe maximum buffer size that covers all common DH group sizes.
     * DH_MAX_SIZE is in bits, so convert to bytes and round up if needed. */
    secretSz = (DH_MAX_SIZE + 7) / 8;

    secret = XMALLOC(secretSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (secret == NULL) {
        throwOutOfMemoryException(
            env, "Failed to allocate shared secret buffer");

        releaseByteArray(env, priv_object, priv, JNI_ABORT);
        releaseByteArray(env, pub_object, pub, JNI_ABORT);

        return result;
    }
    XMEMSET(secret, 0, secretSz);

    if (key == NULL || priv == NULL || pub == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        PRIVATE_KEY_UNLOCK();
        ret = wc_DhAgree(key, secret, &secretSz, priv, privSz, pub, pubSz);
        PRIVATE_KEY_LOCK();
    }

    if (ret == 0) {
        result = (*env)->NewByteArray(env, secretSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, secretSz,
                (const jbyte*)secret);
        } else {
            throwWolfCryptException(env, "Failed to allocate shared secret");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_DhAgree(key, secret, secretSz, priv, privSz, pub, pubSz) = %d\n",
        ret);
    LogStr("secret[%u]: [%p]\n", secretSz, secret);
    LogHex(secret, 0, secretSz);

    if (secret != NULL) {
        XMEMSET(secret, 0, secretSz);
        XFREE(secret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    releaseByteArray(env, priv_object, priv, JNI_ABORT);
    releaseByteArray(env, pub_object, pub, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jobjectArray JNICALL
Java_com_wolfssl_wolfcrypt_Dh_wc_1DhCopyNamedKey(
    JNIEnv* env, jclass class, jint name)
{
    jobjectArray result = NULL;

#ifndef NO_DH
    int ret = 0;
    byte* p = NULL;
    byte* g = NULL;
    word32 pSz = 0;
    word32 gSz = 0;
    jbyteArray pArray = NULL;
    jbyteArray gArray = NULL;

    /* wc_DhCopyNamedKey() not available in FIPSv2 */
    #if !defined(HAVE_FIPS) || \
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 5))

        /* Get sizes */
        ret = wc_DhCopyNamedKey(name, NULL, &pSz, NULL, &gSz, NULL, NULL);
        if (ret != 0 && ret != LENGTH_ONLY_E) {
            throwWolfCryptExceptionFromError(env, ret);
            return NULL;
        }

        /* Allocate buffers */
        p = (byte*)XMALLOC(pSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (p == NULL) {
            throwOutOfMemoryException(env, "Failed to allocate p buffer");
            return NULL;
        }
        XMEMSET(p, 0, pSz);

        g = (byte*)XMALLOC(gSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (g == NULL) {
            XFREE(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            throwOutOfMemoryException(env, "Failed to allocate g buffer");
            return NULL;
        }
        XMEMSET(g, 0, gSz);

        /* Copy named key parameters */
        ret = wc_DhCopyNamedKey(name, p, &pSz, g, &gSz, NULL, NULL);
        if (ret != 0) {
            XFREE(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(g, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            throwWolfCryptExceptionFromError(env, ret);
            return NULL;
        }

    #else
        /* FIPSv2 fallback using individual wc_Dh_ffdheXXXX_Get() functions.
         * These functions return const DhParams* containing p, g, and
         * optionally q parameters. */
        const DhParams* params = NULL;

        /* Get FFDHE parameters based on named group */
        switch (name) {
            #ifdef HAVE_FFDHE_2048
            case 256:
                params = wc_Dh_ffdhe2048_Get();
                break;
            #endif

            #ifdef HAVE_FFDHE_3072
            case 257:
                params = wc_Dh_ffdhe3072_Get();
                break;
            #endif

            #ifdef HAVE_FFDHE_4096
            case 258:
                params = wc_Dh_ffdhe4096_Get();
                break;
            #endif

            #ifdef HAVE_FFDHE_6144
            case 259:
                params = wc_Dh_ffdhe6144_Get();
                break;
            #endif

            #ifdef HAVE_FFDHE_8192
            case 260:
                params = wc_Dh_ffdhe8192_Get();
                break;
            #endif

            default:
                throwWolfCryptException(env, "Unsupported FFDHE group");
                return NULL;
        }

        if (params == NULL) {
            throwWolfCryptException(env,
                "Failed to get FFDHE parameters from native wolfSSL library");
            return NULL;
        }

        /* Get sizes from DhParams structure */
        pSz = params->p_len;
        gSz = params->g_len;

        /* Allocate buffers and copy from const params */
        p = (byte*)XMALLOC(pSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (p == NULL) {
            throwOutOfMemoryException(env, "Failed to allocate p buffer");
            return NULL;
        }
        XMEMCPY(p, params->p, pSz);

        g = (byte*)XMALLOC(gSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (g == NULL) {
            XFREE(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            throwOutOfMemoryException(env, "Failed to allocate g buffer");
            return NULL;
        }
        XMEMCPY(g, params->g, gSz);

    #endif /* FIPS version check */

    /* Create byte arrays for p and g */
    pArray = (*env)->NewByteArray(env, pSz);
    gArray = (*env)->NewByteArray(env, gSz);

    if (pArray && gArray) {
        (*env)->SetByteArrayRegion(env, pArray, 0, pSz, (const jbyte*)p);
        (*env)->SetByteArrayRegion(env, gArray, 0, gSz, (const jbyte*)g);

        /* Create object array to hold both p and g */
        result = (*env)->NewObjectArray(env, 2,
            (*env)->FindClass(env, "[B"), NULL);

        if (result) {
            (*env)->SetObjectArrayElement(env, result, 0, pArray);
            (*env)->SetObjectArrayElement(env, result, 1, gArray);
        }
        else {
            throwWolfCryptException(env,
                "Failed to allocate DH params array");
        }
    }
    else {
        throwWolfCryptException(env, "Failed to allocate DH params");
    }

    (void)ret;

    LogStr("wc_DhCopyNamedKey(name=%d) = %d\n", name, ret);
    LogStr("p[%u]: [%p]\n", (word32)pSz, p);
    LogHex((byte*) p, 0, pSz);
    LogStr("g[%u]: [%p]\n", (word32)gSz, g);
    LogHex((byte*) g, 0, gSz);

    XFREE(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(g, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jobjectArray JNICALL
Java_com_wolfssl_wolfcrypt_Dh_wc_1DhGenerateParams(
    JNIEnv* env, jclass class, jobject rng_object, jint modSz)
{
    jobjectArray result = NULL;

#if !defined(NO_DH) && defined(WOLFSSL_KEY_GEN)
    int ret = 0;
    DhKey* dh = NULL;
    RNG* rng = NULL;
    byte* p = NULL;
    byte* g = NULL;
    word32 pSz = 0;
    word32 gSz = 0;

    /* Get RNG object */
    rng = (RNG*) getNativeStruct(env, rng_object);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception */
        return NULL;
    }

    if (rng == NULL || modSz <= 0) {
        throwWolfCryptException(env,
            "Invalid arguments to wc_DhGenerateParams");
        return NULL;
    }

    /* Allocate temporary DhKey structure */
    dh = (DhKey*)XMALLOC(sizeof(DhKey), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (dh == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate DhKey");
        return NULL;
    }
    XMEMSET(dh, 0, sizeof(DhKey));

    /* Initialize DH key */
    ret = wc_InitDhKey(dh);
    if (ret != 0) {
        XFREE(dh, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        throwWolfCryptExceptionFromError(env, ret);
        return NULL;
    }

    /* Generate DH parameters */
    ret = wc_DhGenerateParams(rng, modSz, dh);
    if (ret != 0) {
        wc_FreeDhKey(dh);
        XFREE(dh, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        throwWolfCryptExceptionFromError(env, ret);
        return NULL;
    }

    /* Get sizes for p and g - use modSz in bytes as buffer size */
    pSz = (modSz + 7) / 8;  /* modSz is in bits, convert to bytes */
    gSz = (modSz + 7) / 8;

    /* Allocate buffers for p and g */
    p = (byte*)XMALLOC(pSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (p == NULL) {
        wc_FreeDhKey(dh);
        XFREE(dh, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        throwOutOfMemoryException(env, "Failed to allocate p buffer");
        return NULL;
    }
    XMEMSET(p, 0, pSz);

    g = (byte*)XMALLOC(gSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (g == NULL) {
        XFREE(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeDhKey(dh);
        XFREE(dh, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        throwOutOfMemoryException(env, "Failed to allocate g buffer");
        return NULL;
    }
    XMEMSET(g, 0, gSz);

    /* Export parameters from DhKey */
    ret = wc_DhExportParamsRaw(dh, p, &pSz, NULL, NULL, g, &gSz);
    if (ret != 0) {
        XFREE(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(g, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeDhKey(dh);
        XFREE(dh, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        throwWolfCryptExceptionFromError(env, ret);
        return NULL;
    }

    /* Create byte arrays for p and g */
    jbyteArray pArray = (*env)->NewByteArray(env, pSz);
    jbyteArray gArray = (*env)->NewByteArray(env, gSz);

    if (pArray && gArray) {
        (*env)->SetByteArrayRegion(env, pArray, 0, pSz, (const jbyte*)p);
        (*env)->SetByteArrayRegion(env, gArray, 0, gSz, (const jbyte*)g);

        /* Create object array to hold both p and g */
        result = (*env)->NewObjectArray(env, 2,
            (*env)->FindClass(env, "[B"), NULL);

        if (result) {
            (*env)->SetObjectArrayElement(env, result, 0, pArray);
            (*env)->SetObjectArrayElement(env, result, 1, gArray);
        }
        else {
            throwWolfCryptException(env,
                "Failed to allocate DH params array");
        }
    }
    else {
        throwWolfCryptException(env, "Failed to allocate DH params");
    }

    LogStr("wc_DhGenerateParams(rng=%p, modSz=%d) = %d\n", rng, modSz, ret);
    LogStr("p[%u]: [%p]\n", (word32)pSz, p);
    LogHex((byte*) p, 0, pSz);
    LogStr("g[%u]: [%p]\n", (word32)gSz, g);
    LogHex((byte*) g, 0, gSz);

    /* Clean up */
    XFREE(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(g, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    wc_FreeDhKey(dh);
    XFREE(dh, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    (void)rng_object;
    (void)modSz;
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Dh_wc_1DhImportKeyPair(
    JNIEnv* env, jobject this, jbyteArray priv_object, jbyteArray pub_object,
    jbyteArray p_object, jbyteArray g_object)
{
#if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)
    int ret = 0;
    DhKey* key = NULL;
    byte* priv = NULL;
    byte* pub  = NULL;
    byte* p    = NULL;
    byte* g    = NULL;
    word32 privSz = 0, pubSz = 0, pSz = 0, gSz = 0;

    key = (DhKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception */
        return;
    }

    if (key == NULL) {
        throwWolfCryptException(env, "Invalid DhKey object");
        return;
    }

    /* Get parameters p and g (required) */
    p = getByteArray(env, p_object);
    pSz = getByteArrayLength(env, p_object);
    g = getByteArray(env, g_object);
    gSz = getByteArrayLength(env, g_object);

    if (p == NULL || g == NULL) {
        releaseByteArray(env, p_object, p, JNI_ABORT);
        releaseByteArray(env, g_object, g, JNI_ABORT);
        throwWolfCryptException(env, "DH parameters p and g are required");
        return;
    }

    /* Set DH parameters first */
    ret = wc_DhSetKey(key, p, pSz, g, gSz);

    if (ret == 0) {
        /* Get private key if provided */
        if (priv_object != NULL) {
            priv = getByteArray(env, priv_object);
            privSz = getByteArrayLength(env, priv_object);
        }

        /* Get public key if provided */
        if (pub_object != NULL) {
            pub = getByteArray(env, pub_object);
            pubSz = getByteArrayLength(env, pub_object);
        }

        /* Import key pair using WOLFSSL_DH_EXTRA functions */
        if (priv != NULL || pub != NULL) {
            PRIVATE_KEY_UNLOCK();
            ret = wc_DhImportKeyPair(key, priv, privSz, pub, pubSz);
            PRIVATE_KEY_LOCK();
        }
    }

    releaseByteArray(env, p_object, p, JNI_ABORT);
    releaseByteArray(env, g_object, g, JNI_ABORT);
    if (priv_object != NULL) {
        releaseByteArray(env, priv_object, priv, JNI_ABORT);
    }
    if (pub_object != NULL) {
        releaseByteArray(env, pub_object, pub, JNI_ABORT);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_DhImportKeyPair(key=%p, priv, privSz, pub, pubSz) = %d\n",
        key, ret);
#else
    (void)priv_object;
    (void)pub_object;
    (void)p_object;
    (void)g_object;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jobjectArray JNICALL
Java_com_wolfssl_wolfcrypt_Dh_wc_1DhExportKeyPair(
    JNIEnv* env, jobject this)
{
    jobjectArray result = NULL;

#if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)
    int ret = 0;
    DhKey* key = NULL;
    byte* priv = NULL;
    byte* pub = NULL;
    word32 privSz = 0, pubSz = 0;
    jbyteArray privArray = NULL;
    jbyteArray pubArray = NULL;

    key = (DhKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception */
        return NULL;
    }

    if (key == NULL) {
        throwWolfCryptException(env, "Invalid DhKey object");
        return NULL;
    }

    /* Get sizes for private and public keys */
    ret = wc_DhExportKeyPair(key, NULL, &privSz, NULL, &pubSz);
    if (ret != LENGTH_ONLY_E && ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return NULL;
    }

    /* Allocate buffers */
    priv = (byte*)XMALLOC(privSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (priv == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate private key buffer");
        return NULL;
    }
    XMEMSET(priv, 0, privSz);

    pub = (byte*)XMALLOC(pubSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pub == NULL) {
        XMEMSET(priv, 0, privSz);
        XFREE(priv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        throwOutOfMemoryException(env, "Failed to allocate public key buffer");
        return NULL;
    }
    XMEMSET(pub, 0, pubSz);

    /* Export key pair */
    PRIVATE_KEY_UNLOCK();
    ret = wc_DhExportKeyPair(key, priv, &privSz, pub, &pubSz);
    PRIVATE_KEY_LOCK();

    if (ret == 0) {
        /* Create byte arrays */
        privArray = (*env)->NewByteArray(env, privSz);
        pubArray = (*env)->NewByteArray(env, pubSz);

        if (privArray != NULL && pubArray != NULL) {
            (*env)->SetByteArrayRegion(env, privArray, 0, privSz,
                (const jbyte*)priv);
            (*env)->SetByteArrayRegion(env, pubArray, 0, pubSz,
                (const jbyte*)pub);

            /* Create object array [priv, pub] */
            result = (*env)->NewObjectArray(env, 2,
                (*env)->FindClass(env, "[B"), NULL);

            if (result) {
                (*env)->SetObjectArrayElement(env, result, 0, privArray);
                (*env)->SetObjectArrayElement(env, result, 1, pubArray);
            }
            else {
                LogStr("Failed to allocate key pair array\n");
                ret = MEMORY_E;
            }
        }
        else {
            LogStr("Failed to allocate key pair byte arrays\n");
            ret = MEMORY_E;
        }
    }

    LogStr("wc_DhExportKeyPair(key=%p) = %d\n", key, ret);

    /* Clean up */
    if (priv != NULL) {
        XMEMSET(priv, 0, privSz);
        XFREE(priv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (pub != NULL) {
        XMEMSET(pub, 0, pubSz);
        XFREE(pub, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jobjectArray JNICALL
Java_com_wolfssl_wolfcrypt_Dh_wc_1DhExportParams(
    JNIEnv* env, jobject this)
{
    jobjectArray result = NULL;

#ifndef NO_DH
    int ret = 0;
    DhKey* key = NULL;
    byte* p = NULL;
    byte* g = NULL;
    byte* q = NULL;
    word32 pSz = 0, gSz = 0, qSz = 0;
    jbyteArray pArray = NULL;
    jbyteArray gArray = NULL;
    jbyteArray qArray = NULL;
    int hasQ = 0;

    key = (DhKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception */
        return NULL;
    }

    if (key == NULL) {
        throwWolfCryptException(env, "Invalid DhKey object");
        return NULL;
    }

    /* Get sizes - try with q first */
    ret = wc_DhExportParamsRaw(key, NULL, &pSz, NULL, &qSz, NULL, &gSz);
    if (ret != LENGTH_ONLY_E && ret != 0) {
        /* Try without q */
        ret = wc_DhExportParamsRaw(key, NULL, &pSz, NULL, NULL, NULL, &gSz);
        if (ret != LENGTH_ONLY_E && ret != 0) {
            throwWolfCryptExceptionFromError(env, ret);
            return NULL;
        }
        hasQ = 0;
    }
    else {
        hasQ = (qSz > 0);
    }

    /* Allocate buffers */
    p = (byte*)XMALLOC(pSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (p == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate p buffer");
        return NULL;
    }
    XMEMSET(p, 0, pSz);

    g = (byte*)XMALLOC(gSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (g == NULL) {
        XFREE(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        throwOutOfMemoryException(env, "Failed to allocate g buffer");
        return NULL;
    }
    XMEMSET(g, 0, gSz);

    if (hasQ) {
        q = (byte*)XMALLOC(qSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (q == NULL) {
            XFREE(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(g, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            throwOutOfMemoryException(env, "Failed to allocate q buffer");
            return NULL;
        }
        XMEMSET(q, 0, qSz);
    }

    /* Export parameters */
    ret = wc_DhExportParamsRaw(key, p, &pSz, q, hasQ ? &qSz : NULL, g, &gSz);

    if (ret == 0) {
        /* Create byte arrays */
        pArray = (*env)->NewByteArray(env, pSz);
        gArray = (*env)->NewByteArray(env, gSz);
        if (hasQ) {
            qArray = (*env)->NewByteArray(env, qSz);
        }

        if (pArray && gArray && (!hasQ || qArray)) {
            (*env)->SetByteArrayRegion(env, pArray, 0, pSz, (const jbyte*)p);
            (*env)->SetByteArrayRegion(env, gArray, 0, gSz, (const jbyte*)g);
            if (hasQ) {
                (*env)->SetByteArrayRegion(env, qArray, 0, qSz,
                    (const jbyte*)q);
            }

            /* Create object array [p, g] or [p, g, q] */
            result = (*env)->NewObjectArray(env, hasQ ? 3 : 2,
                (*env)->FindClass(env, "[B"), NULL);

            if (result) {
                (*env)->SetObjectArrayElement(env, result, 0, pArray);
                (*env)->SetObjectArrayElement(env, result, 1, gArray);
                if (hasQ) {
                    (*env)->SetObjectArrayElement(env, result, 2, qArray);
                }
            }
            else {
                LogStr("Failed to allocate params array\n");
                ret = MEMORY_E;
            }
        }
        else {
            LogStr("Failed to allocate param byte arrays\n");
            ret = MEMORY_E;
        }
    }

    LogStr("wc_DhExportParams(key=%p) = %d\n", key, ret);

    /* Clean up */
    if (p != NULL) {
        XFREE(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (g != NULL) {
        XFREE(g, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (q != NULL) {
        XFREE(q, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Dh_wc_1DhPrivateKeyDecode(
    JNIEnv* env, jobject this, jbyteArray pkcs8_object)
{
    jbyteArray result = NULL;

#ifndef NO_DH
    int ret = 0;
    DhKey* key = NULL;
    byte* pkcs8 = NULL;
    word32 pkcs8Sz = 0;
    word32 idx = 0;

    key = (DhKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception */
        return NULL;
    }

    if (key == NULL) {
        throwWolfCryptException(env, "Invalid DhKey object");
        return NULL;
    }

    pkcs8 = getByteArray(env, pkcs8_object);
    pkcs8Sz = getByteArrayLength(env, pkcs8_object);

    if (pkcs8 == NULL) {
        throwWolfCryptException(env, "PKCS#8 data cannot be null");
        return NULL;
    }

    /* Decode PKCS#8 private key */
    PRIVATE_KEY_UNLOCK();
    ret = wc_DhKeyDecode(pkcs8, &idx, key, pkcs8Sz);
    PRIVATE_KEY_LOCK();

    if (ret == 0) {
        /* Return the same DER data (validated) */
        result = (*env)->NewByteArray(env, pkcs8Sz);
        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, pkcs8Sz,
                (const jbyte*)pkcs8);
        }
        else {
            LogStr("Failed to allocate result array\n");
            ret = MEMORY_E;
        }
    }

    LogStr("wc_DhKeyDecode(pkcs8=%p, key=%p) = %d\n", pkcs8, key, ret);

    releaseByteArray(env, pkcs8_object, pkcs8, JNI_ABORT);

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }
#else
    (void)pkcs8_object;
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Dh_wc_1DhPrivateKeyEncode(
    JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;

#if !defined(NO_DH) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 5)))
    int ret = 0;
    DhKey* key = NULL;
    byte* der = NULL;
    word32 derSz = 0;

    key = (DhKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception */
        return NULL;
    }

    if (key == NULL) {
        throwWolfCryptException(env, "Invalid DhKey object");
        return NULL;
    }

    /* wc_DhPrivKeyToDer() returns LENGTH_ONLY_E when output buffer is NULL
     * and sets derSz to required size. */
    PRIVATE_KEY_UNLOCK();
    ret = wc_DhPrivKeyToDer(key, NULL, &derSz);
    PRIVATE_KEY_LOCK();

    if (ret != LENGTH_ONLY_E) {
        throwWolfCryptExceptionFromError(env, ret);
        return NULL;
    }

    /* Allocate buffer with exact size needed */
    der = (byte*)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (der == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate DER buffer");
        return NULL;
    }
    XMEMSET(der, 0, derSz);

    /* Encode PKCS#8 private key */
    PRIVATE_KEY_UNLOCK();
    ret = wc_DhPrivKeyToDer(key, der, &derSz);
    PRIVATE_KEY_LOCK();

    if (ret >= 0) {
        derSz = ret;  /* Actual size written */
        result = (*env)->NewByteArray(env, derSz);
        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, derSz,
                (const jbyte*)der);
        }
        else {
            LogStr("Failed to allocate result array\n");
            ret = MEMORY_E;
        }
    }

    LogStr("wc_DhPrivKeyToDer(key=%p) = %d\n", key, ret);

    /* Clean up */
    if (der != NULL) {
        XMEMSET(der, 0, derSz);
        XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Dh_wc_1DhPublicKeyDecode(
    JNIEnv* env, jobject this, jbyteArray x509_object)
{
    jbyteArray result = NULL;

#ifndef NO_DH
    int ret = 0;
    DhKey* key = NULL;
    byte* x509 = NULL;
    word32 x509Sz = 0;
    word32 idx = 0;

    key = (DhKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception */
        return NULL;
    }

    if (key == NULL) {
        throwWolfCryptException(env, "Invalid DhKey object");
        return NULL;
    }

    x509 = getByteArray(env, x509_object);
    x509Sz = getByteArrayLength(env, x509_object);

    if (x509 == NULL) {
        throwWolfCryptException(env, "X.509 data cannot be null");
        return NULL;
    }

    /* Decode X.509 public key */
    ret = wc_DhKeyDecode(x509, &idx, key, x509Sz);

    if (ret == 0) {
        /* Return the same DER data (validated) */
        result = (*env)->NewByteArray(env, x509Sz);
        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, x509Sz,
                (const jbyte*)x509);
        }
        else {
            LogStr("Failed to allocate result array\n");
            ret = MEMORY_E;
        }
    }

    LogStr("wc_DhKeyDecode(x509=%p, key=%p) = %d\n", x509, key, ret);

    releaseByteArray(env, x509_object, x509, JNI_ABORT);

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }
#else
    (void)x509_object;
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Dh_wc_1DhPublicKeyEncode(
    JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;

#if !defined(NO_DH) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 5)))
    int ret = 0;
    DhKey* key = NULL;
    byte* der = NULL;
    word32 derSz = 0;

    key = (DhKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception */
        return NULL;
    }

    if (key == NULL) {
        throwWolfCryptException(env, "Invalid DhKey object");
        return NULL;
    }

    /* wc_DhPubKeyToDer() returns LENGTH_ONLY_E when output buffer is NULL and
     * sets derSz to required size. */
    ret = wc_DhPubKeyToDer(key, NULL, &derSz);
    if (ret != LENGTH_ONLY_E) {
        throwWolfCryptExceptionFromError(env, ret);
        return NULL;
    }

    /* Allocate buffer with exact size needed */
    der = (byte*)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (der == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate DER buffer");
        return NULL;
    }
    XMEMSET(der, 0, derSz);

    /* Encode X.509 public key */
    ret = wc_DhPubKeyToDer(key, der, &derSz);

    if (ret >= 0) {
        derSz = ret;  /* Actual size written */
        result = (*env)->NewByteArray(env, derSz);
        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, derSz,
                (const jbyte*)der);
        }
        else {
            LogStr("Failed to allocate result array\n");
            ret = MEMORY_E;
        }
    }

    LogStr("wc_DhPubKeyToDer(key=%p) = %d\n", key, ret);

    /* Clean up */
    if (der != NULL) {
        XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

