/* jni_pwdbased.c
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

#include <wolfssl/wolfcrypt/pwdbased.h>
#include <com_wolfssl_wolfcrypt_Pwdbased.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_Pwdbased_wc_1PKCS12_1PBKDF
  (JNIEnv* env, jclass jcl, jbyteArray passBuf, jint passBufLen,
   jbyteArray saltBuf, jint sBufLen, jint iterations, jint kLen,
   jint typeH, jint id)
{
#if !defined(NO_PWDBASED) && defined(WOLFSSL_PKCS12)
    int ret = 0;
    byte* pass = NULL;
    byte* salt = NULL;
    byte* outKey = NULL;
    jbyteArray result = NULL;
    (void)jcl;

    if (env == NULL || kLen == 0) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    outKey = (byte*)XMALLOC(kLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (outKey == NULL) {
        throwWolfCryptExceptionFromError(env, MEMORY_E);
        return NULL;
    }
    XMEMSET(outKey, 0, kLen);

    pass = (byte*)(*env)->GetByteArrayElements(env, passBuf, NULL);
    salt = (byte*)(*env)->GetByteArrayElements(env, saltBuf, NULL);

    ret = wc_PKCS12_PBKDF(outKey, pass, passBufLen, salt, sBufLen,
                          iterations, kLen, typeH, id);
    if (ret == 0) {
        result = (*env)->NewByteArray(env, kLen);
        if (result != NULL) {
            (*env)->SetByteArrayRegion(env, result, 0, kLen,
                                       (const jbyte*) outKey);
        } else {
            LogStr("NewByteArray failed in JNI PKCS12_PBKDF\n");
            ret = MEMORY_E;
        }
    }

    if (outKey != NULL) {
        XMEMSET(outKey, 0, kLen);
        XFREE(outKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    (*env)->ReleaseByteArrayElements(env, passBuf, (jbyte*)pass, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, saltBuf, (jbyte*)salt, JNI_ABORT);

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return NULL;
    }

    return result;
#else
    (void)env;
    (void)jcl;
    (void)passBuf;
    (void)passBufLen;
    (void)saltBuf;
    (void)sBufLen;
    (void)iterations;
    (void)kLen;
    (void)typeH;
    (void)id;
    throwWolfCryptExceptionFromError(env, NOT_COMPILED_IN);
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_Pwdbased_wc_1PBKDF2
  (JNIEnv* env, jclass jcl, jbyteArray passBuf, jint passBufLen,
   jbyteArray saltBuf, jint sBufLen, jint iterations, jint kLen, jint hashType)
{
#if !defined(NO_PWDBASED) && defined(HAVE_PBKDF2) && !defined(NO_HMAC)
    int ret = 0;
    byte* pass = NULL;
    byte* salt = NULL;
    byte* outKey = NULL;
    jbyteArray result = NULL;
    (void)jcl;

    if (env == NULL || kLen == 0) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    outKey = (byte*)XMALLOC(kLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (outKey == NULL) {
        throwWolfCryptExceptionFromError(env, MEMORY_E);
        return NULL;
    }
    XMEMSET(outKey, 0, kLen);

    if ((passBuf != NULL) && (passBufLen > 0)) {
        pass = (byte*)(*env)->GetByteArrayElements(env, passBuf, NULL);
    }

    salt = (byte*)(*env)->GetByteArrayElements(env, saltBuf, NULL);

    ret = wc_PBKDF2(outKey, pass, passBufLen, salt, sBufLen,
                    iterations, kLen, hashType);
    if (ret == 0) {
        result = (*env)->NewByteArray(env, kLen);
        if (result != NULL) {
            (*env)->SetByteArrayRegion(env, result, 0, kLen,
                                       (const jbyte*) outKey);
        } else {
            LogStr("NewByteArray failed in JNI PBKDF2\n");
            ret = MEMORY_E;
        }
    }

    if (outKey != NULL) {
        XMEMSET(outKey, 0, kLen);
        XFREE(outKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (pass != NULL) {
        (*env)->ReleaseByteArrayElements(env, passBuf, (jbyte*)pass, JNI_ABORT);
    }

    (*env)->ReleaseByteArrayElements(env, saltBuf, (jbyte*)salt, JNI_ABORT);

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return NULL;
    }

    return result;
#else
    (void)env;
    (void)jcl;
    (void)passBuf;
    (void)passBufLen;
    (void)salt;
    (void)sBufLen;
    (void)iterations;
    (void)kLen;
    (void)hashType;
    throwWolfCryptExceptionFromError(env, NOT_COMPILED_IN);
    return NULL;
#endif
}

