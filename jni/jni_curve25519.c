/* jni_curve25519.c
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
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/asn.h>

#include <com_wolfssl_wolfcrypt_Curve25519.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

#define MAX_CURVE25519_PRIVATE_DER_SZ 128

JNIEXPORT jlong JNICALL
Java_com_wolfssl_wolfcrypt_Curve25519_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    void* ret = 0;

#ifdef HAVE_CURVE25519
    ret = XMALLOC(sizeof(curve25519_key), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (ret == NULL)
        throwOutOfMemoryException(env, "Failed to allocate Curve25519 object");

    LogStr("new Curve25519() = %p\n", (void*)ret);
#else
    throwNotCompiledInException(env);
#endif

    return (jlong) ret;
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Curve25519_wc_1curve25519_1init(
    JNIEnv* env, jobject this)
{
#ifdef HAVE_CURVE25519
    int ret = 0;
    curve25519_key* curve25519 = (curve25519_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    ret = (!curve25519)
        ? BAD_FUNC_ARG
        : wc_curve25519_init(curve25519);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("curve25519_init(curve25519=%p) = %d\n", curve25519, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Curve25519_wc_1curve25519_1free(
    JNIEnv* env, jobject this)
{
#ifdef HAVE_CURVE25519
    curve25519_key* curve25519 = (curve25519_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception */
        return;
    }

    if (curve25519)
        wc_curve25519_free(curve25519);

    LogStr("curve25519_free(curve25519=%p)\n", curve25519);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Curve25519_wc_1curve25519_1make_1key(
    JNIEnv* env, jobject this, jobject rng_object, jint size)
{
#ifdef HAVE_CURVE25519
    int ret = 0;
    curve25519_key* curve25519 = NULL;
    RNG* rng = NULL;

    curve25519 = (curve25519_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    rng = (RNG*) getNativeStruct(env, rng_object);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    ret = (!curve25519 || !rng)
        ? BAD_FUNC_ARG
        : wc_curve25519_make_key(rng, size, curve25519);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("curve25519_make_key(rng, size, curve25519=%p) = %d\n", curve25519, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Curve25519_wc_1curve25519_1import_1private
  (JNIEnv* env, jobject this, jbyteArray priv_object,
   jbyteArray pub_object)
{
#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_IMPORT)
    int ret = 0;
    curve25519_key* curve25519 = NULL;
    byte* priv   = NULL;
    byte* pub    = NULL;
    word32 privSz = 0, pubSz = 0;

    curve25519 = (curve25519_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }
    priv   = getByteArray(env, priv_object);
    privSz = getByteArrayLength(env, priv_object);
    pub    = getByteArray(env, pub_object);
    pubSz  = getByteArrayLength(env, pub_object);

    /* pub may be null if only importing private key */
    if (!curve25519 || !priv) {
        ret = BAD_FUNC_ARG;
    } else {
        /* detect, and later skip, leading zero byte */
        ret = wc_curve25519_import_private_raw(priv, privSz, pub,
                                               pubSz, curve25519);
    }

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_curve25519_import_private_key(curve25519=%p) = %d\n", curve25519, ret);

    releaseByteArray(env, priv_object, priv, JNI_ABORT);
    releaseByteArray(env, pub_object, pub, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

    JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Curve25519_wc_1curve25519_1import_1private_1only
  (JNIEnv* env, jobject this, jbyteArray priv_object)
{
#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_IMPORT)
    int ret = 0;
    curve25519_key* curve25519 = NULL;
    byte* priv   = NULL;
    word32 privSz = 0;

    curve25519 = (curve25519_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }
    priv   = getByteArray(env, priv_object);
    privSz = getByteArrayLength(env, priv_object);

    /* pub may be null if only importing private key */
    if (!curve25519 || !priv) {
        ret = BAD_FUNC_ARG;
    } else {
        /* detect, and later skip, leading zero byte */
        ret = wc_curve25519_import_private(priv, privSz, curve25519);
    }

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_curve25519_import_private_key(curve25519=%p) = %d\n", curve25519, ret);

    releaseByteArray(env, priv_object, priv, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}
    
JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Curve25519_wc_1curve25519_1import_1public
  (JNIEnv* env, jobject this, jbyteArray pub_object)
{
#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_IMPORT)
    int ret = 0;
    curve25519_key* curve25519 = NULL;
    byte* pub   = NULL;
    word32 pubSz = 0;

    curve25519 = (curve25519_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }
    pub   = getByteArray(env, pub_object);
    pubSz = getByteArrayLength(env, pub_object);

    if (!curve25519 || !pub) {
        ret = BAD_FUNC_ARG;
    } else {
        /* detect, and later skip, leading zero byte */
        ret = wc_curve25519_import_public(pub, pubSz, curve25519);
    }

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_curve25519_import_public(curve25519=%p) = %d\n", curve25519, ret);

    releaseByteArray(env, pub_object, pub, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Curve25519_wc_1curve25519_1export_1private(
    JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;

#ifdef HAVE_CURVE25519_KEY_EXPORT
    int ret = 0;
    curve25519_key* curve25519 = NULL;
    byte* output = NULL;
    word32 outputSz = 0;

    curve25519 = (curve25519_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    outputSz = wc_curve25519_size(curve25519);

    output = XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate key buffer");
        return result;
    }

    ret = (!curve25519)
        ? BAD_FUNC_ARG
        : wc_curve25519_export_private_raw(curve25519, output, &outputSz);

    if (ret == 0) {
        result = (*env)->NewByteArray(env, outputSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, outputSz,
                                                         (const jbyte*) output);
        } else {
            throwWolfCryptException(env, "Failed to allocate key");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_curve25519_export_private(curve25519, output=%p, outputSz) = %d\n", output, ret);
    LogStr("output[%u]: [%p]\n", (word32)outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Curve25519_wc_1curve25519_1export_1public (
    JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;

#ifdef HAVE_CURVE25519_KEY_EXPORT
    int ret = 0;
    curve25519_key* curve25519 = NULL;
    byte* output = NULL;
    word32 outputSz = 0;

    curve25519 = (curve25519_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    outputSz = wc_curve25519_size(curve25519);

    output = XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate key buffer");
        return result;
    }

    ret = (!curve25519)
        ? BAD_FUNC_ARG
        : wc_curve25519_export_public(curve25519, output, &outputSz);

    if (ret == 0) {
        result = (*env)->NewByteArray(env, outputSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, outputSz,
                                                         (const jbyte*) output);
        } else {
            throwWolfCryptException(env, "Failed to allocate key");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_curve25519_export_public(curve25519, output=%p, outputSz) = %d\n", output, ret);
    LogStr("output[%u]: [%p]\n", (word32)outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Curve25519_wc_1curve25519_1make_1shared_1secret(
    JNIEnv* env, jobject this, jobject pub_object)
{
    jbyteArray result = NULL;

#ifdef HAVE_CURVE25519_SHARED_SECRET
    int ret = 0;
    curve25519_key* curve25519 = NULL;
    curve25519_key* pub = NULL;
    byte* output = NULL;
    word32 outputSz = 0;

    curve25519 = (curve25519_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    pub = (curve25519_key*) getNativeStruct(env, pub_object);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    outputSz = wc_curve25519_size(curve25519);
    output = XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env,
                                     "Failed to allocate shared secret buffer");
        return result;
    }

    ret = (!curve25519 || !pub)
        ? BAD_FUNC_ARG
        : wc_curve25519_shared_secret(curve25519, pub, output, &outputSz);

    if (ret == 0) {
        result = (*env)->NewByteArray(env, outputSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, outputSz,
                                                         (const jbyte*) output);
        } else {
            throwWolfCryptException(env, "Failed to allocate shared secret");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_curve25519_shared_secret(priv, pub, output=%p, outputSz) = %d\n",
        output, ret);
    LogStr("output[%u]: [%p]\n", (word32)outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

