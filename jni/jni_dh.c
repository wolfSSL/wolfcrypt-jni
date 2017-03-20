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
    DhKey* key = (DhKey*) getNativeStruct(env, this);
    byte* p = getByteArray(env, p_object);
    word32 pSz = getByteArrayLength(env, p_object);
    byte* g = getByteArray(env, g_object);
    word32 gSz = getByteArrayLength(env, g_object);

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
    DhKey* key = (DhKey*) getNativeStruct(env, this);
    RNG* rng = (RNG*) getNativeStruct(env, rng_object);
    byte* priv = NULL;
    word32 privSz = size;
    byte* pub = NULL;
    word32 pubSz = size;

    priv = XMALLOC(privSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (priv == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate private key buffer");
        return;
    }

    pub = XMALLOC(pubSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pub == NULL) {
        XFREE(priv, NULL, DYNAMIC_TYPE_TMP_BUFFER);

        throwOutOfMemoryException(env, "Failed to allocate public key buffer");
        return;
    }

    ret = (!key || !rng || !priv || !pub)
        ? BAD_FUNC_ARG
        : wc_DhGenerateKeyPair(key, rng, priv, &privSz, pub, &pubSz);

    if (ret == 0) {
        jbyteArray privateKey = (*env)->NewByteArray(env, privSz);
        jbyteArray publicKey = (*env)->NewByteArray(env, pubSz);

        if (privateKey) {
            (*env)->SetByteArrayRegion(env, privateKey, 0, privSz,
                                                            (const jbyte*)priv);
            setByteArrayMember(env, this, "privateKey", privateKey);
        } else {
            throwWolfCryptException(env, "Failed to allocate privateKey");
        }

        if (publicKey) {
            (*env)->SetByteArrayRegion(env, publicKey, 0, pubSz,
                                                             (const jbyte*)pub);
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

    XFREE(priv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
    DhKey* key = (DhKey*) getNativeStruct(env, this);
    byte* pub = getByteArray(env, pub_object);
    word32 pubSz = getByteArrayLength(env, pub_object);

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
    DhKey* key = (DhKey*) getNativeStruct(env, this);
    byte* priv = getByteArray(env, priv_object);
    word32 privSz = getByteArrayLength(env, priv_object);
    byte* pub = getByteArray(env, pub_object);
    word32 pubSz = getByteArrayLength(env, pub_object);
    byte* secret = NULL;
    word32 secretSz = pubSz;

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