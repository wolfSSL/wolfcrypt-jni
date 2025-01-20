/* jni_wolfssl_cert_manager.c
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

#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <com_wolfssl_wolfcrypt_WolfSSLCertManager.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerNew
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;

    return (jlong)(uintptr_t)wolfSSL_CertManagerNew();
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerFree
  (JNIEnv* env, jclass jcl, jlong cmPtr)
{
    (void)env;
    (void)jcl;

    wolfSSL_CertManagerFree((WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerLoadCA
  (JNIEnv* env, jclass jcl, jlong cmPtr, jstring f, jstring d)
{
#ifndef NO_FILESYSTEM
    int ret;
    const char* certFile = NULL;
    const char* certPath = NULL;
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;

    if (env == NULL || cm == NULL) {
        return (jint)BAD_FUNC_ARG;
    }

    certFile = (*env)->GetStringUTFChars(env, f, 0);
    certPath = (*env)->GetStringUTFChars(env, d, 0);

    ret = wolfSSL_CertManagerLoadCA(cm, certFile, certPath);

    (*env)->ReleaseStringUTFChars(env, f, certFile);
    (*env)->ReleaseStringUTFChars(env, d, certPath);

    return (jint)ret;
#else
    (void)env;
    (void)jcl;
    (void)cmPtr;
    (void)f;
    (void)d;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerLoadCABuffer
  (JNIEnv* env, jclass jcl, jlong cmPtr, jbyteArray in, jlong sz, jint format)
{
    int ret = 0;
    word32 buffSz = 0;
    byte* buff = NULL;
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;

    if (env == NULL || in == NULL || (sz < 0)) {
        return BAD_FUNC_ARG;
    }

    buff = (byte*)(*env)->GetByteArrayElements(env, in, NULL);
    buffSz = (*env)->GetArrayLength(env, in);

    ret = wolfSSL_CertManagerLoadCABuffer(cm, buff, buffSz, format);

    (*env)->ReleaseByteArrayElements(env, in, (jbyte*)buff, JNI_ABORT);

    return (jint)ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerUnloadCAs
  (JNIEnv* env, jclass jcl, jlong cmPtr)
{
    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;

    if (env == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wolfSSL_CertManagerUnloadCAs(cm);

    return (jint)ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerVerifyBuffer
  (JNIEnv* env, jclass jcl, jlong cmPtr, jbyteArray in, jlong sz, jint format)
{
    int ret = 0;
    word32 buffSz = 0;
    byte* buff = NULL;
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;

    if (env == NULL || in == NULL || (sz < 0)) {
        return BAD_FUNC_ARG;
    }

    buff = (byte*)(*env)->GetByteArrayElements(env, in, NULL);
    buffSz = (*env)->GetArrayLength(env, in);

    ret = wolfSSL_CertManagerVerifyBuffer(cm, buff, buffSz, format);

    (*env)->ReleaseByteArrayElements(env, in, (jbyte*)buff, JNI_ABORT);

    return (jint)ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerEnableCRL
  (JNIEnv* env, jclass jcl, jlong cmPtr, jint options)
{
#ifdef HAVE_CRL
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;

    if (env == NULL || cm == NULL) {
        return BAD_FUNC_ARG;
    }

    return wolfSSL_CertManagerEnableCRL(cm, (int)options);

#else
    (void)env;
    (void)jcl;
    (void)cmPtr;
    (void)options;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerDisableCRL
  (JNIEnv* env, jclass jcl, jlong cmPtr)
{
#ifdef HAVE_CRL
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;

    if (env == NULL || cm == NULL) {
        return BAD_FUNC_ARG;
    }

    return wolfSSL_CertManagerDisableCRL(cm);

#else
    (void)env;
    (void)jcl;
    (void)cmPtr;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerLoadCRLBuffer
  (JNIEnv* env, jclass jcl, jlong cmPtr, jbyteArray in, jlong sz, jint type)
{
#ifdef HAVE_CRL
    int ret = 0;
    word32 buffSz = 0;
    byte* buff = NULL;
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;

    if (env == NULL || in == NULL || (sz < 0)) {
        return BAD_FUNC_ARG;
    }

    buff = (byte*)(*env)->GetByteArrayElements(env, in, NULL);
    buffSz = (*env)->GetArrayLength(env, in);

    ret = wolfSSL_CertManagerLoadCRLBuffer(cm, buff, buffSz, type);

    (*env)->ReleaseByteArrayElements(env, in, (jbyte*)buff, JNI_ABORT);

    return (jint)ret;
#else
    (void)env;
    (void)jcl;
    (void)cmPtr;
    (void)in;
    (void)sz;
    (void)type;
    return NOT_COMPILED_IN;
#endif
}

