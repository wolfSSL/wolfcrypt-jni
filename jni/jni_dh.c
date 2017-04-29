/* jni_dh.c
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef __ANDROID__
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/dh.h>

#include <com_wolfssl_wolfcrypt_Dh.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Dh_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    jlong ret = 0;

#ifndef NO_DH
    ret = (jlong) XMALLOC(sizeof(DhKey), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Dh object");

    LogStr("new Dh() = %p\n", (void*)ret);
#else
    throwNotCompiledInException(env);
#endif

    return ret;
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Dh_wc_1InitDhKey(
    JNIEnv* env, jobject this)
{
#ifndef NO_DH
    DhKey* key = (DhKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception */
        return;
    }

    wc_InitDhKey(key);

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
    DhKey* key = (DhKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception */
        return;
    }

    wc_FreeDhKey(key);

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

    ret = (!key || !p || !g)
        ? BAD_FUNC_ARG
        : wc_DhSetKey(key, p, pSz, g, gSz);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

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

    if (!key || !rng || (size < 0))
        ret = BAD_FUNC_ARG;

    if (ret == 0) {

        priv = XMALLOC(privSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (priv == NULL) {
            throwOutOfMemoryException(env,
                                      "Failed to allocate private key buffer");
            return;
        }

        pub = XMALLOC(pubSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (pub == NULL) {
            XFREE(priv, NULL, DYNAMIC_TYPE_TMP_BUFFER);

            throwOutOfMemoryException(env,
                                      "Failed to allocate public key buffer");
            return;
        }

        ret = wc_DhGenerateKeyPair(key, rng, priv, &privSz, pub, &pubSz);
    }

    if (ret == 0) {

        /* keys should be positive, if leading bit is set, add zero byte */
        if (priv[0] & 0x80)
            lBitPriv = 1;

        if (pub[0] & 0x80)
            lBitPub = 1;

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

    if (priv)
        XFREE(priv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pub)
        XFREE(pub, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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

    ret = (!key || !pub)
        ? BAD_FUNC_ARG
        : wc_DhCheckPubKey(key, pub, pubSz);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

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
    secretSz = pubSz;

    secret = XMALLOC(pubSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (secret == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate private key buffer");

        releaseByteArray(env, priv_object, priv, JNI_ABORT);
        releaseByteArray(env, pub_object, pub, JNI_ABORT);

        return result;
    }

    ret = (!key || !priv || !pub)
        ? BAD_FUNC_ARG
        : wc_DhAgree(key, secret, &secretSz, priv, privSz, pub, pubSz);

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

    XFREE(secret, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    releaseByteArray(env, priv_object, priv, JNI_ABORT);
    releaseByteArray(env, pub_object, pub, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif

    return result;
}
