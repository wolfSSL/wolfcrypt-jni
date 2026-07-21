/* jni_xmss.c
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
#include <wolfssl/wolfcrypt/types.h>

/* wc_XmssKey_ImportPubRaw_ex(), used below to import a raw XMSS/XMSS^MT
 * public key was added in wolfSSL 5.9.2. Gating on both WOLFSSL_HAVE_XMSS and
 * the wolfSSL version. */
#if defined(WOLFSSL_HAVE_XMSS) && (LIBWOLFSSL_VERSION_HEX >= 0x05009002)
    #define WC_JNI_XMSS_AVAILABLE
    #include <wolfssl/wolfcrypt/wc_xmss.h>
#endif
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>

#include <com_wolfssl_wolfcrypt_Xmss.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Xmss_mallocNativeStruct
  (JNIEnv* env, jobject this)
{
#ifdef WC_JNI_XMSS_AVAILABLE
    XmssKey* key = NULL;

    key = (XmssKey*)XMALLOC(sizeof(XmssKey), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (key == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate Xmss object");
        return (jlong)0;
    }
    else {
        XMEMSET(key, 0, sizeof(XmssKey));
    }

    LogStr("new Xmss() = %p\n", key);

    return (jlong)(uintptr_t)key;
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Xmss_wc_1XmssKey_1init
  (JNIEnv* env, jobject this)
{
#ifdef WC_JNI_XMSS_AVAILABLE
    int ret = 0;
    XmssKey* key = NULL;

    key = (XmssKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_XmssKey_Init(key, NULL, INVALID_DEVID);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_XmssKey_Init(key=%p) = %d\n", key, ret);
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Xmss_wc_1XmssKey_1free
  (JNIEnv* env, jobject this)
{
#ifdef WC_JNI_XMSS_AVAILABLE
    XmssKey* key = NULL;

    key = (XmssKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    if (key != NULL) {
        wc_XmssKey_Free(key);
    }

    LogStr("wc_XmssKey_Free(key=%p)\n", key);
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_wolfcrypt_Xmss_wc_1XmssKey_1get_1param_1str
  (JNIEnv* env, jobject this)
{
    jstring result = NULL;
#ifdef WC_JNI_XMSS_AVAILABLE
    int ret = 0;
    const char* str = NULL;
    XmssKey* key = NULL;

    key = (XmssKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    if (key == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    ret = wc_XmssKey_GetParamStr(key, &str);
    if (ret != 0 || str == NULL) {
        throwWolfCryptExceptionFromError(env, ret);
        return NULL;
    }

    result = (*env)->NewStringUTF(env, str);
    if (result == NULL) {
        /* NewStringUTF left an OutOfMemoryError pending; propagate it. */
        return NULL;
    }

    LogStr("wc_XmssKey_GetParamStr(key=%p) = %d (%s)\n", key, ret, str);
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
#endif
    return result;
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_Xmss_wc_1XmssKey_1verify
  (JNIEnv* env, jobject this, jbyteArray sig_object, jbyteArray msg_object)
{
    jboolean result = JNI_FALSE;
#ifdef WC_JNI_XMSS_AVAILABLE
    int ret = 0;
    XmssKey* key = NULL;
    byte* sig = NULL;
    byte* msg = NULL;
    word32 sigLen = 0;
    word32 msgLen = 0;

    key = (XmssKey*) getNativeStruct(env, this);
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

    if (msg_object != NULL) {
        msg = getByteArray(env, msg_object);
        msgLen = getByteArrayLength(env, msg_object);
    }

    if ((sig_object != NULL && sig == NULL) ||
        (msg_object != NULL && msg == NULL)) {

        if (sig != NULL) {
            releaseByteArray(env, sig_object, sig, JNI_ABORT);
        }
        if (msg != NULL) {
            releaseByteArray(env, msg_object, msg, JNI_ABORT);
        }
        return JNI_FALSE;
    }

    ret = wc_XmssKey_Verify(key, sig, sigLen, msg, (int)msgLen);

    if (ret == 0) {
        result = JNI_TRUE;
    }
    else if (ret != SIG_VERIFY_E && ret != BUFFER_E) {
        /* SIG_VERIFY_E is a failed verification. BUFFER_E is returned when
         * signature length does not match the parameter set's expected len.
         * Treating a wrong-length signature as a failed verification rather
         * than an error, matching the JCE Signature.verify() contract. Any
         * other return is an unexpected error. */
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_XmssKey_Verify(key=%p) = %d\n", key, ret);

    if (sig_object != NULL) {
        releaseByteArray(env, sig_object, sig, JNI_ABORT);
    }

    if (msg_object != NULL) {
        releaseByteArray(env, msg_object, msg, JNI_ABORT);
    }
#else
    (void)env;
    (void)this;
    (void)sig_object;
    (void)msg_object;
    throwNotCompiledInException(env);
#endif
    return result;
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Xmss_wc_1XmssKey_1import_1public
  (JNIEnv* env, jobject this, jbyteArray in_object, jboolean is_xmssmt)
{
#ifdef WC_JNI_XMSS_AVAILABLE
    int ret = 0;
    XmssKey* key = NULL;
    byte* in = NULL;
    word32 inLen = 0;

    key = (XmssKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    in = getByteArray(env, in_object);
    inLen = getByteArrayLength(env, in_object);

    /* getByteArray() can return NULL with a pending exception */
    if (in_object != NULL && in == NULL) {
        return;
    }

    if (key == NULL || in == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Use the _ex variant which derives the parameter set from the
         * 4-byte OID prefix of the raw public key. A raw XMSS public key
         * does not say whether it is single-tree XMSS or multi-tree
         * XMSS^MT (the two OID number spaces overlap), so the caller must
         * pass the family as is_xmssmt, normally taken from the X.509
         * AlgorithmIdentifier OID (RFC 9802 .34 vs .35). */
        ret = wc_XmssKey_ImportPubRaw_ex(key, in, inLen,
            (is_xmssmt == JNI_TRUE) ? 1 : 0);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_XmssKey_ImportPubRaw_ex(key=%p, mt=%d) = %d\n", key,
        (int)is_xmssmt, ret);

    releaseByteArray(env, in_object, in, JNI_ABORT);
#else
    (void)env;
    (void)this;
    (void)in_object;
    (void)is_xmssmt;
    throwNotCompiledInException(env);
#endif
}
