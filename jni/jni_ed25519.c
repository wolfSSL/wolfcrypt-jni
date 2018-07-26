/* jni_ed25519.c
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
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/asn.h>

#include <com_wolfssl_wolfcrypt_Ed25519.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

#define MAX_ED25519_PRIVATE_DER_SZ 128

JNIEXPORT jlong JNICALL
Java_com_wolfssl_wolfcrypt_Ed25519_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    void* ret = 0;

#ifdef HAVE_ED25519
    ret = XMALLOC(sizeof(ed25519_key), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (ret == NULL)
        throwOutOfMemoryException(env, "Failed to allocate Ed25519 object");

    LogStr("new Ed25519() = %p\n", (void*)ret);
#else
    throwNotCompiledInException(env);
#endif

    return (jlong) ret;
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1init(
    JNIEnv* env, jobject this)
{
#ifdef HAVE_ED25519
    int ret = 0;
    ed25519_key* ed25519 = (ed25519_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    ret = (!ed25519)
        ? BAD_FUNC_ARG
        : wc_ed25519_init(ed25519);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("ed25519_init(ed25519=%p) = %d\n", ed25519, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1free(
    JNIEnv* env, jobject this)
{
#ifdef HAVE_ED25519
    ed25519_key* ed25519 = (ed25519_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception */
        return;
    }

    if (ed25519)
        wc_ed25519_free(ed25519);

    LogStr("ed25519_free(ed25519=%p)\n", ed25519);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1make_1key(
    JNIEnv* env, jobject this, jobject rng_object, jint size)
{
#ifdef HAVE_ED25519
    int ret = 0;
    ed25519_key* ed25519 = NULL;
    RNG* rng = NULL;

    ed25519 = (ed25519_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    rng = (RNG*) getNativeStruct(env, rng_object);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    ret = (!ed25519 || !rng)
        ? BAD_FUNC_ARG
        : wc_ed25519_make_key(rng, size, ed25519);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("ed25519_make_key(rng, size, ed25519=%p) = %d\n", ed25519, ret);
#else
    throwNotCompiledInException(env);
#endif
}


JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1check_1key(
    JNIEnv* env, jobject this)
{
#ifdef HAVE_ED25519
    int ret = 0;
    ed25519_key* ed25519 = (ed25519_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    ret = (!ed25519)
        ? BAD_FUNC_ARG
        : wc_ed25519_check_key(ed25519);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_ed25519_check_key(ed25519=%p) = %d\n", ed25519, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1import_1private
  (JNIEnv* env, jobject this, jbyteArray priv_object, jbyteArray pub_object)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
    int ret = 0;
    ed25519_key* ed25519 = NULL;
    byte* priv   = NULL;
    byte* pub    = NULL;
    word32 privSz = 0, pubSz = 0;

    ed25519 = (ed25519_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }
    priv   = getByteArray(env, priv_object);
    privSz = getByteArrayLength(env, priv_object);
    pub    = getByteArray(env, pub_object);
    pubSz  = getByteArrayLength(env, pub_object);

    /* pub may be null if only importing private key */
    if (!ed25519 || !priv) {
        ret = BAD_FUNC_ARG;
    } else {
        /* detect, and later skip, leading zero byte */
        if (!pub)
            ret = wc_ed25519_import_private_only(priv, privSz, ed25519);
        else
            ret = wc_ed25519_import_private_key(priv, privSz, pub,
                pubSz, ed25519);
    }

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_ed25519_import_private_key(ed25519=%p) = %d\n", ed25519, ret);

    releaseByteArray(env, priv_object, priv, JNI_ABORT);
    releaseByteArray(env, pub_object, pub, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1import_1public
  (JNIEnv* env, jobject this, jbyteArray pub_object)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
    int ret = 0;
    ed25519_key* ed25519 = NULL;
    byte* pub   = NULL;
    word32 pubSz = 0;

    ed25519 = (ed25519_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }
    pub   = getByteArray(env, pub_object);
    pubSz = getByteArrayLength(env, pub_object);

    if (!ed25519 || !pub) {
        ret = BAD_FUNC_ARG;
    } else {
        ret = wc_ed25519_import_public(pub, pubSz, ed25519);
    }

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_ed25519_import_public(ed25519=%p) = %d\n", ed25519, ret);

    releaseByteArray(env, pub_object, pub, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1import_1private_1only
  (JNIEnv* env, jobject this, jbyteArray priv_object)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
    int ret = 0;
    ed25519_key* ed25519 = NULL;
    byte* priv   = NULL;
    word32 privSz = 0;

    ed25519 = (ed25519_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }
    priv   = getByteArray(env, priv_object);
    privSz = getByteArrayLength(env, priv_object);

    if (!ed25519 || !priv) {
        ret = BAD_FUNC_ARG;
    } else {
        /* detect, and later skip, leading zero byte */
        ret = wc_ed25519_import_private_only(priv, privSz, ed25519);
    }

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_ed25519_import_private_key(ed25519=%p) = %d\n", ed25519, ret);

    releaseByteArray(env, priv_object, priv, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1export_1private(
    JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;

#ifdef HAVE_ED25519_KEY_EXPORT
    int ret = 0;
    ed25519_key* ed25519 = NULL;
    byte* output = NULL;
    word32 outputSz = 0;

    ed25519 = (ed25519_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    outputSz = 2 * wc_ed25519_priv_size(ed25519); /* Export private + public */

    output = XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate key buffer");
        return result;
    }

    ret = (!ed25519)
        ? BAD_FUNC_ARG
        : wc_ed25519_export_private(ed25519, output, &outputSz);

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

    LogStr("wc_ed25519_export_x963(ed25519, output=%p, outputSz) = %d\n", output, ret);
    LogStr("output[%u]: [%p]\n", (word32)outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1export_1private_1only(
    JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;

#ifdef HAVE_ED25519_KEY_EXPORT
    int ret = 0;
    ed25519_key* ed25519 = NULL;
    byte* output = NULL;
    word32 outputSz = 0;

    ed25519 = (ed25519_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    outputSz = wc_ed25519_size(ed25519);

    output = XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate key buffer");
        return result;
    }

    ret = (!ed25519)
        ? BAD_FUNC_ARG
        : wc_ed25519_export_private_only(ed25519, output, &outputSz);

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

    LogStr("wc_ed25519_export_x963(ed25519, output=%p, outputSz) = %d\n", output, ret);
    LogStr("output[%u]: [%p]\n", (word32)outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1export_1public(
    JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;

#ifdef HAVE_ED25519_KEY_EXPORT
    int ret = 0;
    ed25519_key* ed25519 = NULL;
    byte* output = NULL;
    word32 outputSz = 0;

    ed25519 = (ed25519_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    outputSz = wc_ed25519_size(ed25519);

    output = XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate key buffer");
        return result;
    }

    ret = (!ed25519)
        ? BAD_FUNC_ARG
        : wc_ed25519_export_public(ed25519, output, &outputSz);

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

    LogStr("wc_ed25519_export_x963(ed25519, output=%p, outputSz) = %d\n", output, ret);
    LogStr("output[%u]: [%p]\n", (word32)outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    throwNotCompiledInException(env);
#endif

    return result;
}


JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1sign_1msg
  (JNIEnv* env, jobject this, jbyteArray msg_in)
{
    jbyteArray result = NULL;
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_SIGN)
    int ret = 0;
    word32 len = 0, outlen = ED25519_SIG_SIZE;
    ed25519_key* ed25519 = NULL;
    byte* msg   = NULL;
    byte* output = NULL;

    ed25519 = (ed25519_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }
    msg = getByteArray(env, msg_in);
    len = getByteArrayLength(env, msg_in);
    output = XMALLOC(outlen, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ed25519) {
        ret = BAD_FUNC_ARG;
    } else {
        ret = wc_ed25519_sign_msg(msg, len, output, &outlen, ed25519);
    }

    if (ret == 0) {
        result = (*env)->NewByteArray(env, outlen);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, outlen,
                                                         (const jbyte*) output);
        } else {
            throwWolfCryptException(env, "Failed to allocate key");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_ed25519_sign_msg(ed25519=%p) = %d\n", ed25519, ret);
    printf("wc_ed25519_sign_msg(ed25519=%p) = %d\n", ed25519, ret);
    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    releaseByteArray(env, msg_in, msg, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
    return result;
}


JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1verify_1msg
  (JNIEnv* env, jobject this, jbyteArray sig_in, jbyteArray msg_in)
{
    int result = -1;
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_SIGN)
    int ret = 0;
    word32 msglen, siglen;
    ed25519_key* ed25519 = NULL;
    byte* sig   = NULL;
    byte* msg   = NULL;


    ed25519 = (ed25519_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return result;
    }
    sig = getByteArray(env, sig_in);
    msg = getByteArray(env, msg_in);
    msglen = getByteArrayLength(env, msg_in);
    siglen = getByteArrayLength(env, msg_in);

    if (!ed25519) {
        ret = BAD_FUNC_ARG;
    } else {
        ret = wc_ed25519_verify_msg(sig, siglen, msg, msglen, &result, ed25519);
    }

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_ed25519_verify_msg(ed25519=%p) = %d\n", ed25519, ret);

    releaseByteArray(env, sig_in, sig, JNI_ABORT);
    releaseByteArray(env, msg_in, msg, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
    return result;
}

