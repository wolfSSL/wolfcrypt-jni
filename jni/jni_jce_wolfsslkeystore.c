/* jni_jce_wolfsslkeystore.c
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

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#elif !defined(__ANDROID__)
    #include <wolfssl/options.h>
#endif

#include <wolfssl/ssl.h>
#include <com_wolfssl_provider_jce_WolfSSLKeyStore.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jboolean JNICALL Java_com_wolfssl_provider_jce_WolfSSLKeyStore_X509CheckPrivateKey
  (JNIEnv* env, jobject class, jbyteArray certDerArr, jbyteArray pkcs8KeyDerArr)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && defined(OPENSSL_EXTRA)

    int ret = WOLFSSL_SUCCESS;
    int certDerSz = 0;
    int keyDerSz = 0;
    byte* certDer = NULL;
    byte* keyDer = NULL;
    byte* pkcs8KeyDer = NULL;
    WOLFSSL_X509* x509 = NULL;
    WOLFSSL_EVP_PKEY* key = NULL;
    WOLFSSL_PKCS8_PRIV_KEY_INFO* keyInfo = NULL;
    (void)class;

    if (env == NULL || certDerArr == NULL || pkcs8KeyDerArr == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return JNI_FALSE;
    }

    /* Get byte* and sizes from jbyteArrays */
    certDer = (byte*)(*env)->GetByteArrayElements(env, certDerArr, NULL);
    certDerSz = (*env)->GetArrayLength(env, certDerArr);

    keyDer = (byte*)(*env)->GetByteArrayElements(env, pkcs8KeyDerArr, NULL);
    keyDerSz = (*env)->GetArrayLength(env, pkcs8KeyDerArr);
    /* Keep original keyDer pointer for free later, wolfSSL_d2i_PKCS8_PKEY
     * will change/advance the pointer. */
    pkcs8KeyDer = keyDer;

    if (certDer == NULL || certDerSz <= 0 || keyDer == NULL || keyDerSz <= 0) {
        fprintf(stderr, "Native X509CheckPrivateKey() bad args");
        ret = BAD_FUNC_ARG;
    }

    if (ret == WOLFSSL_SUCCESS) {
        x509 = wolfSSL_X509_load_certificate_buffer(certDer, certDerSz,
                    WOLFSSL_FILETYPE_ASN1);
        if (x509 == NULL) {
            fprintf(stderr,
                    "Native wolfSSL_X509_load_certificate_buffer() failed");
            ret = WOLFSSL_FAILURE;
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        keyInfo = wolfSSL_d2i_PKCS8_PKEY(NULL, (const byte**)&pkcs8KeyDer,
                                         keyDerSz);
        if (keyInfo == NULL) {
            fprintf(stderr, "Native wolfSSL_d2i_PKCS8_PKEY() failed");
            ret = WOLFSSL_FAILURE;
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        key = wolfSSL_EVP_PKCS82PKEY(keyInfo);
        if (key == NULL) {
            fprintf(stderr, "Native wolfSSL_EVP_PKCS82PKEY() failed");
            ret = WOLFSSL_FAILURE;
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        PRIVATE_KEY_UNLOCK();
        ret = wolfSSL_X509_check_private_key(x509, key);
        PRIVATE_KEY_LOCK();
        if (ret != WOLFSSL_SUCCESS) {
            fprintf(stderr, "Native wolfSSL_X509_check_private_key() failed: %d", ret);
        }
    }

    if (key != NULL) {
        wolfSSL_EVP_PKEY_free(key);
    }
    if (x509 != NULL) {
        wolfSSL_X509_free(x509);
    }
    if (certDer != NULL) {
        (*env)->ReleaseByteArrayElements(env, certDerArr,
                                         (jbyte*)certDer, JNI_ABORT);
    }
    if (keyDer != NULL) {
        (*env)->ReleaseByteArrayElements(env, pkcs8KeyDerArr,
                                         (jbyte*)keyDer, JNI_ABORT);
    }

    if (ret == WOLFSSL_SUCCESS) {
        return JNI_TRUE;
    }
    else {
        return JNI_FALSE;
    }

#else
    (void)env;
    (void)class;
    (void)certDer;
    (void)pkcs8Der;
    throwWolfCryptExceptionFromError(env, NOT_COMPILED_IN);
    return JNI_FALSE;
#endif
}

