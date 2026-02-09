/* jni_wolfcrypt.c
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

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include <com_wolfssl_wolfcrypt_WolfCrypt.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1NONE
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_NONE;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1MD2
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_MD2;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1MD4
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_MD4;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1MD5
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_MD5;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1SHA
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_SHA;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1SHA224
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_SHA224;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1SHA256
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_SHA256;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1SHA384
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_SHA384;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1SHA512
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_SHA512;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1MD5_1SHA
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_MD5_SHA;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1SHA3_1224
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_SHA3_224;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1SHA3_1256
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_SHA3_256;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1SHA3_1384
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_SHA3_384;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1SHA3_1512
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_SHA3_512;
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_CrlEnabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;

#ifdef HAVE_CRL
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_OcspEnabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;

#ifdef HAVE_OCSP
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_Base16Enabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;

#ifdef WOLFSSL_BASE16
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_wcBase16Encode
    (JNIEnv* env, jclass jcl, jbyteArray inputArr)
{
#ifdef WOLFSSL_BASE16
    int ret = 0;
    jint inputSz = 0;
    word32 outLen = 0;
    byte* input = NULL;
    byte* output = NULL;
    jbyteArray outputArr = NULL;
    (void)jcl;

    if (env == NULL) {
        return NULL;
    }

    if (inputArr == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        inputSz = (*env)->GetArrayLength(env, inputArr);
        if (inputSz == 0) {
            /* Return empty array for empty input */
            return (*env)->NewByteArray(env, 0);
        }
    }

    /* Check for integer overflow: inputSz * 2 must fit in word32 */
    if (ret == 0) {
        if (inputSz < 0 || (word32)inputSz > (0xFFFFFFFFU / 2)) {
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        input = (byte*)(*env)->GetByteArrayElements(env, inputArr, NULL);
        if (input == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        /* Output size is 2x input size */
        outLen = (word32)(inputSz * 2);
        output = (byte*)XMALLOC(outLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (output == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        XMEMSET(output, 0, outLen);
        ret = Base16_Encode(input, (word32)inputSz, output, &outLen);
    }

    if (ret == 0) {
        outputArr = (*env)->NewByteArray(env, (jint)outLen);
        if (outputArr == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        (*env)->SetByteArrayRegion(env, outputArr, 0, (jint)outLen,
            (jbyte*)output);
        if ((*env)->ExceptionOccurred(env)) {
            (*env)->DeleteLocalRef(env, outputArr);
            outputArr = NULL;
        }
    }

    /* Cleanup */
    if (input != NULL) {
        (*env)->ReleaseByteArrayElements(env, inputArr, (jbyte*)input,
            JNI_ABORT);
    }
    if (output != NULL) {
        XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    return outputArr;

#else
    (void)env;
    (void)jcl;
    (void)inputArr;
    throwNotCompiledInException(env);
    return NULL;
#endif /* WOLFSSL_BASE16 */
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_wcBase16Decode
    (JNIEnv* env, jclass jcl, jbyteArray inputArr)
{
#ifdef WOLFSSL_BASE16
    int ret = 0;
    jint inputSz = 0;
    word32 outLen = 0;
    byte* input = NULL;
    byte* output = NULL;
    jbyteArray outputArr = NULL;
    (void)jcl;

    if (env == NULL) {
        return NULL;
    }

    if (inputArr == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        inputSz = (*env)->GetArrayLength(env, inputArr);
        if (inputSz == 0) {
            /* Return empty array for empty input */
            return (*env)->NewByteArray(env, 0);
        }
    }

    /* Hex string must have even length */
    if (ret == 0) {
        if (inputSz < 0 || inputSz % 2 != 0) {
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        input = (byte*)(*env)->GetByteArrayElements(env, inputArr, NULL);
        if (input == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        /* Output size is half of input size */
        outLen = (word32)(inputSz / 2);
        output = (byte*)XMALLOC(outLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (output == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        XMEMSET(output, 0, outLen);
        ret = Base16_Decode(input, (word32)inputSz, output, &outLen);
    }

    if (ret == 0) {
        outputArr = (*env)->NewByteArray(env, (jint)outLen);
        if (outputArr == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        (*env)->SetByteArrayRegion(env, outputArr, 0, (jint)outLen,
            (jbyte*)output);
        if ((*env)->ExceptionOccurred(env)) {
            (*env)->DeleteLocalRef(env, outputArr);
            outputArr = NULL;
        }
    }

    /* Cleanup */
    if (input != NULL) {
        (*env)->ReleaseByteArrayElements(env, inputArr, (jbyte*)input,
            JNI_ABORT);
    }
    if (output != NULL) {
        XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    return outputArr;

#else
    (void)env;
    (void)jcl;
    (void)inputArr;
    throwNotCompiledInException(env);
    return NULL;
#endif /* WOLFSSL_BASE16 */
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_wcKeyPemToDer
    (JNIEnv* env, jclass jcl, jbyteArray pemArr, jstring passwordStr)
{
#if !defined(NO_ASN) && !defined(WOLFSSL_NO_PEM) && !defined(NO_CODING)
    int ret = 0;
    int derSz = 0;
    jint pemSz = 0;
    byte* pem = NULL;
    byte* der = NULL;
    const char* password = NULL;
    jbyteArray derArr = NULL;
    (void)jcl;

    if (env == NULL) {
        return NULL;
    }

    if (pemArr == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        pem = (byte*)(*env)->GetByteArrayElements(env, pemArr, NULL);
        pemSz = (*env)->GetArrayLength(env, pemArr);
        if (pem == NULL || pemSz <= 0) {
            ret = BAD_FUNC_ARG;
        }
    }

    /* Get password if provided */
    if (ret == 0) {
        if (passwordStr != NULL) {
            password = (*env)->GetStringUTFChars(env, passwordStr, NULL);
            if (password == NULL) {
                ret = MEMORY_E;
            }
        }
    }

    /* Allocate buffer for DER output, PEM is always larger than DER */
    if (ret == 0) {
        der = (byte*)XMALLOC(pemSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (der == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        XMEMSET(der, 0, pemSz);
        ret = wc_KeyPemToDer(pem, pemSz, der, pemSz, password);
        if (ret > 0) {
            derSz = ret;
            ret = 0;
        }
    }

    /* Create result byte array with exact DER size */
    if (ret == 0) {
        derArr = (*env)->NewByteArray(env, derSz);
        if (derArr == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        (*env)->SetByteArrayRegion(env, derArr, 0, derSz, (jbyte*)der);
        if ((*env)->ExceptionOccurred(env)) {
            (*env)->DeleteLocalRef(env, derArr);
            derArr = NULL;
        }
    }

    if (pem != NULL) {
        (*env)->ReleaseByteArrayElements(env, pemArr, (jbyte*)pem, JNI_ABORT);
    }
    if (password != NULL) {
        (*env)->ReleaseStringUTFChars(env, passwordStr, password);
    }
    if (der != NULL) {
        XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    return derArr;

#else
    (void)env;
    (void)jcl;
    (void)pemArr;
    (void)passwordStr;
    throwNotCompiledInException(env);
    return NULL;
#endif /* !NO_ASN && !WOLFSSL_NO_PEM && !NO_CODING) */
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_wcCertPemToDer
    (JNIEnv* env, jclass jcl, jbyteArray pemArr)
{
#if !defined(NO_ASN) && !defined(WOLFSSL_NO_PEM) && !defined(NO_CODING)
    int ret = 0;
    int derSz = 0;
    jint pemSz = 0;
    byte* pem = NULL;
    byte* der = NULL;
    jbyteArray derArr = NULL;
    (void)jcl;

    if (env == NULL) {
        return NULL;
    }

    if (pemArr == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        pem = (byte*)(*env)->GetByteArrayElements(env, pemArr, NULL);
        pemSz = (*env)->GetArrayLength(env, pemArr);
        if (pem == NULL || pemSz <= 0) {
            ret = BAD_FUNC_ARG;
        }
    }

    /* Allocate buffer for DER output, PEM is always larger than DER */
    if (ret == 0) {
        der = (byte*)XMALLOC(pemSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (der == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        XMEMSET(der, 0, pemSz);
        ret = wc_CertPemToDer(pem, pemSz, der, pemSz, CERT_TYPE);
        if (ret > 0) {
            derSz = ret;
            ret = 0;
        }
    }

    /* Create result byte array with exact DER size */
    if (ret == 0) {
        derArr = (*env)->NewByteArray(env, derSz);
        if (derArr == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        (*env)->SetByteArrayRegion(env, derArr, 0, derSz, (jbyte*)der);
        if ((*env)->ExceptionOccurred(env)) {
            (*env)->DeleteLocalRef(env, derArr);
            derArr = NULL;
        }
    }

    if (pem != NULL) {
        (*env)->ReleaseByteArrayElements(env, pemArr, (jbyte*)pem, JNI_ABORT);
    }
    if (der != NULL) {
        XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    return derArr;

#else
    (void)env;
    (void)jcl;
    (void)pemArr;
    throwNotCompiledInException(env);
    return NULL;
#endif /* !NO_ASN && !WOLFSSL_NO_PEM && !NO_CODING) */
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_wcPubKeyPemToDer
    (JNIEnv* env, jclass jcl, jbyteArray pemArr)
{
#if !defined(NO_ASN) && !defined(WOLFSSL_NO_PEM) && !defined(NO_CODING)
    int ret = 0;
    int derSz = 0;
    jint pemSz = 0;
    byte* pem = NULL;
    byte* der = NULL;
    jbyteArray derArr = NULL;
    (void)jcl;

    if (env == NULL) {
        return NULL;
    }

    if (pemArr == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        pem = (byte*)(*env)->GetByteArrayElements(env, pemArr, NULL);
        pemSz = (*env)->GetArrayLength(env, pemArr);
        if (pem == NULL || pemSz <= 0) {
            ret = BAD_FUNC_ARG;
        }
    }

    /* Allocate buffer for DER output, PEM is always larger than DER */
    if (ret == 0) {
        der = (byte*)XMALLOC(pemSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (der == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        XMEMSET(der, 0, pemSz);
        ret = wc_PubKeyPemToDer(pem, pemSz, der, pemSz);
        if (ret > 0) {
            derSz = ret;
            ret = 0;
        }
    }

    /* Create result byte array with exact DER size */
    if (ret == 0) {
        derArr = (*env)->NewByteArray(env, derSz);
        if (derArr == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        (*env)->SetByteArrayRegion(env, derArr, 0, derSz, (jbyte*)der);
        if ((*env)->ExceptionOccurred(env)) {
            (*env)->DeleteLocalRef(env, derArr);
            derArr = NULL;
        }
    }

    if (pem != NULL) {
        (*env)->ReleaseByteArrayElements(env, pemArr, (jbyte*)pem, JNI_ABORT);
    }
    if (der != NULL) {
        XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    return derArr;

#else
    (void)env;
    (void)jcl;
    (void)pemArr;
    throwNotCompiledInException(env);
    return NULL;
#endif /* !NO_ASN && !WOLFSSL_NO_PEM && !NO_CODING) */
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_IoTimeoutEnabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;

#ifdef HAVE_IO_TIMEOUT
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_nativeSetIOTimeout
  (JNIEnv* env, jclass jcl, jint timeoutSec)
{
    (void)jcl;

#ifdef HAVE_IO_TIMEOUT
    wolfIO_SetTimeout(timeoutSec);
    (void)env;
#else
    (void)timeoutSec;
    throwNotCompiledInException(env);
#endif
}

