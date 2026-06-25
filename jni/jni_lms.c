/* jni_lms.c
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

/* LMS support in wolfCrypt JNI/JCE requires wolfSSL >= 5.9.2, the first
 * release to provide the wc_LmsKey_GetParameters_ex() hash-family API (and
 * which removed the deprecated liblms/libxmss integration). On older wolfSSL
 * the LMS JNI functions below compile as NOT_COMPILED_IN stubs. */
#if defined(WOLFSSL_HAVE_LMS) && (LIBWOLFSSL_VERSION_HEX >= 0x05009002)
    #define WC_JNI_LMS
    #include <wolfssl/wolfcrypt/wc_lms.h>
#endif
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>

#include <com_wolfssl_wolfcrypt_Lms.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Lms_mallocNativeStruct
  (JNIEnv* env, jobject this)
{
#ifdef WC_JNI_LMS
    LmsKey* key = NULL;

    key = (LmsKey*)XMALLOC(sizeof(LmsKey), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (key == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate Lms object");
        return (jlong)0;
    }
    else {
        XMEMSET(key, 0, sizeof(LmsKey));
    }

    LogStr("new Lms() = %p\n", key);

    return (jlong)(uintptr_t)key;
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Lms_wc_1LmsKey_1init
  (JNIEnv* env, jobject this)
{
#ifdef WC_JNI_LMS
    int ret = 0;
    LmsKey* key = NULL;

    key = (LmsKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_LmsKey_Init(key, NULL, INVALID_DEVID);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_LmsKey_Init(key=%p) = %d\n", key, ret);
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Lms_wc_1LmsKey_1free
  (JNIEnv* env, jobject this)
{
#ifdef WC_JNI_LMS
    LmsKey* key = NULL;

    key = (LmsKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    if (key != NULL) {
        wc_LmsKey_Free(key);
    }

    LogStr("wc_LmsKey_Free(key=%p)\n", key);
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jintArray JNICALL Java_com_wolfssl_wolfcrypt_Lms_wc_1LmsKey_1get_1parameters
  (JNIEnv* env, jobject this)
{
    jintArray result = NULL;
#ifdef WC_JNI_LMS
    int ret = 0;
    int levels = 0;
    int height = 0;
    int winternitz = 0;
    int hashType = 0;
    jint tmp[4];
    LmsKey* key = NULL;

    key = (LmsKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return NULL;
    }

    if (key == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    ret = wc_LmsKey_GetParameters_ex(key, &levels, &height, &winternitz,
        &hashType);
    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return NULL;
    }

    tmp[0] = (jint)levels;
    tmp[1] = (jint)height;
    tmp[2] = (jint)winternitz;
    tmp[3] = (jint)hashType;

    result = (*env)->NewIntArray(env, 4);
    if (result != NULL) {
        (*env)->SetIntArrayRegion(env, result, 0, 4, tmp);
    }
    else {
        throwWolfCryptException(env, "Failed to allocate parameters array");
        return NULL;
    }

    LogStr("wc_LmsKey_GetParameters_ex(key=%p) = %d\n", key, ret);
#else
    (void)env;
    (void)this;
    throwNotCompiledInException(env);
#endif
    return result;
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_Lms_wc_1LmsKey_1verify
  (JNIEnv* env, jobject this, jbyteArray sig_object, jbyteArray msg_object)
{
    jboolean result = JNI_FALSE;
#ifdef WC_JNI_LMS
    int ret = 0;
    LmsKey* key = NULL;
    byte* sig = NULL;
    byte* msg = NULL;
    word32 sigLen = 0;
    word32 msgLen = 0;

    key = (LmsKey*) getNativeStruct(env, this);
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

    ret = wc_LmsKey_Verify(key, sig, sigLen, msg, (int)msgLen);

    if (ret == 0) {
        result = JNI_TRUE;
    }
    else if (ret != SIG_VERIFY_E) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_LmsKey_Verify(key=%p) = %d\n", key, ret);

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

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Lms_wc_1LmsKey_1import_1public
  (JNIEnv* env, jobject this, jbyteArray in_object)
{
#ifdef WC_JNI_LMS
    int ret = 0;
    LmsKey* key = NULL;
    byte* in = NULL;
    word32 inLen = 0;

    key = (LmsKey*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }

    in = getByteArray(env, in_object);
    inLen = getByteArrayLength(env, in_object);

    /* getByteArray() returns NULL with OutOfMemoryError pending when
     * GetByteArrayElements fails. Return without overwriting it. */
    if (in_object != NULL && in == NULL) {
        return;
    }

    if (key == NULL || in == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_LmsKey_ImportPubRaw(key, in, inLen);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_LmsKey_ImportPubRaw(key=%p) = %d\n", key, ret);

    releaseByteArray(env, in_object, in, JNI_ABORT);
#else
    (void)env;
    (void)this;
    (void)in_object;
    throwNotCompiledInException(env);
#endif
}
