/* jni_ecc.c
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
#include <stdlib.h>

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#elif !defined(__ANDROID__)
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn.h>

#include <com_wolfssl_wolfcrypt_Ecc.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

#define MAX_ECC_PRIVATE_DER_SZ 128

#if !defined(WC_NO_RNG) && defined(NO_OLD_RNGNAME)
    #define RNG WC_RNG
#endif

/* FIPSv2 does not have ECC_CURVE_MAX. 28 is what this value would be
 * if it existed in the FIPSv2 wolfssl/wolfcrypt/ecc.h header. */
#if defined(HAVE_FIPS) && defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION == 2)
    #define ECC_CURVE_MAX 27
#endif

JNIEXPORT jlong JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
#ifdef HAVE_ECC
    ecc_key* ecc = NULL;

    ecc = (ecc_key*)XMALLOC(sizeof(ecc_key), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ecc == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate Ecc object");
    }
    else {
        XMEMSET(ecc, 0, sizeof(ecc_key));
    }

    LogStr("new Ecc() = %p\n", ecc);

    return (jlong)(uintptr_t)ecc;
#else
    throwNotCompiledInException(env);

    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1init(
    JNIEnv* env, jobject this)
{
#ifdef HAVE_ECC
    int ret = 0;
    ecc_key* ecc = (ecc_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    /* Checks ecc for NULL internally */
    ret = wc_ecc_init(ecc);
    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("ecc_init(ecc=%p) = %d\n", ecc, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1free(
    JNIEnv* env, jobject this)
{
#ifdef HAVE_ECC
    ecc_key* ecc = (ecc_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception */
        return;
    }

    /* Checks ecc for NULL internally */
    wc_ecc_free(ecc);

    LogStr("ecc_free(ecc=%p)\n", ecc);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1make_1key(
    JNIEnv* env, jobject this, jobject rng_object, jint size)
{
#ifdef HAVE_ECC
    int ret = 0;
    ecc_key* ecc = NULL;
    RNG* rng = NULL;

    ecc = (ecc_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    rng = (RNG*) getNativeStruct(env, rng_object);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    if (ecc == NULL || rng == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_ecc_make_key(rng, size, ecc);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("ecc_make_key(rng, size, ecc=%p) = %d\n", ecc, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1make_1key_1ex
  (JNIEnv* env, jobject this, jobject rng_object, jint size,
   jstring curveName)
{
#ifdef HAVE_ECC
    int ret = 0;
    ecc_key* ecc = NULL;
    RNG* rng = NULL;
    const char* name;

    ecc = (ecc_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    rng = (RNG*) getNativeStruct(env, rng_object);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    if (ecc == NULL || rng == NULL || curveName == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        name = (*env)->GetStringUTFChars(env, curveName, 0);
        if (name == NULL) {
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        ret = wc_ecc_get_curve_id_from_name(name);
        (*env)->ReleaseStringUTFChars(env, curveName, name);
    }

    if (ret < 0) {
        throwWolfCryptException(env, "ECC curve unsupported or not enabled");

    } else {
        ret = wc_ecc_make_key_ex(rng, size, ecc, ret);

        if (ret < 0) {
            throwWolfCryptExceptionFromError(env, ret);
        }
    }

    LogStr("ecc_make_key_ex(rng, size, ecc=%p) = %d\n", ecc, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1check_1key(
    JNIEnv* env, jobject this)
{
#ifdef HAVE_ECC
    int ret = 0;
    ecc_key* ecc = NULL;

    ecc = (ecc_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    if (ecc == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_ecc_check_key(ecc);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_ecc_check_key(ecc=%p) = %d\n", ecc, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1import_1private
  (JNIEnv* env, jobject this, jbyteArray priv_object,
   jbyteArray pub_object, jstring curveName)
{
#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_IMPORT)
    int ret = 0;
    word32 idx = 0;
    ecc_key* ecc = NULL;
    byte* priv   = NULL;
    byte* pub    = NULL;
    word32 privSz = 0, pubSz = 0;
    const char* name = NULL;

    ecc = (ecc_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    priv   = getByteArray(env, priv_object);
    privSz = getByteArrayLength(env, priv_object);
    pub    = getByteArray(env, pub_object);
    pubSz  = getByteArrayLength(env, pub_object);

    /* pub may be null if only importing private key */
    if (ecc == NULL || priv == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* detect, and later skip, leading zero byte */
        if ((privSz > 0) && (priv[0] == 0)) {
            idx = 1;
        }

        /* sanity check privSz is big enough to read to idx */
        if (privSz <= idx) {
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        if (curveName != NULL) {
            name = (*env)->GetStringUTFChars(env, curveName, 0);
            ret = wc_ecc_get_curve_id_from_name(name);
            (*env)->ReleaseStringUTFChars(env, curveName, name);

            if (ret > 0) {
                /* import with curve id, ret stores curve id */
                ret = wc_ecc_import_private_key_ex(priv + idx, privSz - idx,
                                                   pub, pubSz, ecc, ret);
            } else {
                /* unsupported curve name */
                ret = BAD_FUNC_ARG;
            }

        } else {
            ret = wc_ecc_import_private_key(priv + idx, privSz - idx, pub,
                                            pubSz, ecc);
        }
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_ecc_import_private_key(ecc=%p) = %d\n", ecc, ret);

    releaseByteArray(env, priv_object, priv, JNI_ABORT);
    releaseByteArray(env, pub_object, pub, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1export_1private(
    JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;

#ifdef HAVE_ECC_KEY_EXPORT
    int ret = 0;
    ecc_key* ecc = NULL;
    byte* output = NULL;
    word32 outputSz = 0;
    word32 outputBufSz = 0;

    ecc = (ecc_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    if (ecc == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        outputSz = wc_ecc_size(ecc);
        outputBufSz = outputSz;

        output = (byte*)XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (output == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(output, 0, outputSz);
        }
    }

    if (ret == 0) {
        PRIVATE_KEY_UNLOCK();
        ret = wc_ecc_export_private_only(ecc, output, &outputSz);
        PRIVATE_KEY_LOCK();
    }

    if (ret == 0) {
        result = (*env)->NewByteArray(env, outputSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, outputSz,
                                       (const jbyte*) output);
        } else {
            throwWolfCryptException(env, "Failed to allocate ECC key");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_ecc_export_private_only(ecc=%p, output=%p, outputSz) = %d\n",
            ecc, output, ret);
    LogStr("output[%u]: [%p]\n", (word32)outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    if (output != NULL) {
        XMEMSET(output, 0, outputBufSz);
        XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1import_1x963(
    JNIEnv* env, jobject this, jbyteArray key_object)
{
#ifdef HAVE_ECC_KEY_IMPORT
    int ret = 0;
    ecc_key* ecc = NULL;
    byte* key    = NULL;
    word32 keySz = 0;

    ecc = (ecc_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    key   = getByteArray(env, key_object);
    keySz = getByteArrayLength(env, key_object);

    if (ecc == NULL || key == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = wc_ecc_import_x963(key, keySz, ecc);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_ecc_import_x963(key=%p, keySz=%d, ecc=%p) = %d\n",
           key, (int)keySz, ecc, ret);

    releaseByteArray(env, key_object, key, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1export_1x963(
    JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;

#ifdef HAVE_ECC_KEY_EXPORT
    int ret = 0;
    ecc_key* ecc = NULL;
    byte* output = NULL;
    word32 outputSz = 0;

    ecc = (ecc_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    if (ecc == NULL) {
        ret = BAD_FUNC_ARG;
    }

    /* get size */
    if (ret == 0) {
        PRIVATE_KEY_UNLOCK();
        ret = wc_ecc_export_x963(ecc, NULL, &outputSz);
        PRIVATE_KEY_LOCK();
        if (ret == LENGTH_ONLY_E) {
            ret = 0;
        }
    }

    if (ret == 0) {
        output = (byte*)XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (output == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(output, 0, outputSz);
        }
    }

    if (ret == 0) {
        PRIVATE_KEY_UNLOCK();
        ret = wc_ecc_export_x963(ecc, output, &outputSz);
        PRIVATE_KEY_LOCK();
    }

    if (ret == 0) {
        result = (*env)->NewByteArray(env, outputSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, outputSz,
                                       (const jbyte*) output);
        } else {
            throwWolfCryptException(env, "Failed to create new ECC key array");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_ecc_export_x963(ecc=%p, output=%p, outputSz) = %d\n",
            ecc, output, ret);
    LogStr("output[%u]: [%p]\n", (word32)outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    if (output != NULL) {
        XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_wc_1EccPrivateKeyDecode(
    JNIEnv* env, jobject this, jbyteArray key_object)
{
#if defined(HAVE_ECC) && !defined(NO_ASN)
    int ret = 0;
    word32 idx = 0;
    ecc_key* ecc = NULL;
    byte*  key   = NULL;
    word32 keySz = 0;

    ecc = (ecc_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    key   = getByteArray(env, key_object);
    keySz = getByteArrayLength(env, key_object);

    if (ecc == NULL || key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_EccPrivateKeyDecode(key, &idx, ecc, keySz);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_EccPrivateKeyDecode(key=%p, keySz=%d, ecc=%p) = %d\n",
           key, (int)keySz, ecc, ret);

    releaseByteArray(env, key_object, key, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_wc_1EccKeyToDer(
    JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;

#if defined(HAVE_ECC) && !defined(NO_ASN) && defined(WOLFSSL_KEY_GEN)
    int ret = 0;
    ecc_key* ecc = NULL;
    byte* output = NULL;
    word32 outputSz = 256;
    word32 outputBufSz = 0;

    ecc = (ecc_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0 && ecc == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        output = (byte*)XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (output == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(output, 0, outputSz);
        }
    }

    if (ret == 0) {
        outputBufSz = outputSz;

        ret = wc_EccKeyToDer(ecc, output, outputSz);
        if (ret >= 0) {
            outputSz = ret;
            ret = 0;
        }
    }

    if (ret == 0) {
        result = (*env)->NewByteArray(env, outputSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, outputSz,
                                       (const jbyte*) output);
        } else {
            throwWolfCryptException(env, "Failed to allocate ECC key");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_EccKeyToDer(ecc = %p, output=%p, outputSz) = %d\n",
           ecc, output, ret);
    LogStr("output[%u]: [%p]\n", outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    if (output != NULL) {
        XMEMSET(output, 0, outputBufSz);
        XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_wc_1EccPublicKeyDecode(
    JNIEnv* env, jobject this, jbyteArray key_object)
{
#if defined(HAVE_ECC) && !defined(NO_ASN)
    int ret = 0;
    word32 idx = 0;
    ecc_key* ecc = NULL;
    byte*  key   = NULL;
    word32 keySz = 0;

    ecc = (ecc_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    key   = getByteArray(env, key_object);
    keySz = getByteArrayLength(env, key_object);

    if (ecc == NULL || key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_EccPublicKeyDecode(key, &idx, ecc, keySz);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_EccPublicKeyDecode(key = %p, keySz = %d, ecc = %p) = %d\n",
           key, (int)keySz, ecc, ret);

    releaseByteArray(env, key_object, key, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_wc_1EccPublicKeyToDer(
    JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;

#if !defined(NO_ASN) && (defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_KEY_GEN))
    int ret = 0;
    ecc_key* ecc = NULL;
    byte* output = NULL;
    word32 outputSz = 0;

    ecc = (ecc_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0 && ecc == NULL) {
        ret = BAD_FUNC_ARG;
    }

    /* Calculate ECC DER size */
    if (ret == 0) {
        ret = wc_EccPublicKeyDerSize(ecc, 1);
        if (ret > 0) {
            outputSz = ret;
            ret = 0;
        }
    }

    if (ret == 0) {
        output = (byte*)XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (output == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(output, 0, outputSz);
        }
    }

    if (ret == 0) {
        ret = wc_EccPublicKeyToDer(ecc, output, outputSz, 1);
        if (ret > 0) {
            outputSz = ret;
            ret = 0;
        }
    }

    if (ret == 0) {
        result = (*env)->NewByteArray(env, outputSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, outputSz,
                                       (const jbyte*) output);
        } else {
            throwWolfCryptException(env, "Failed to allocate ECC DER key");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_EccPublicKeyToDer(ecc = %p, output = %p, outputSz = %d) = %d\n",
           ecc, output, (int)outputSz, ret);
    LogStr("output[%u]: [%p]\n", outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    if (output != NULL) {
        XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1shared_1secret(
    JNIEnv* env, jobject this, jobject pub_object, jobject rng_object)
{
    jbyteArray result = NULL;

#ifdef HAVE_ECC_DHE
    int ret = 0;
    RNG* rng = NULL;
    ecc_key* ecc = NULL;
    ecc_key* pub = NULL;
    byte* output = NULL;
    word32 outputSz = 0;
    word32 outputBufSz = 0;

    ecc = (ecc_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    rng = (RNG*) getNativeStruct(env, rng_object);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    pub = (ecc_key*) getNativeStruct(env, pub_object);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    if (ecc == NULL || rng == NULL || pub == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        outputSz = wc_ecc_size(ecc);
        outputBufSz = outputSz;
        output = (byte*)XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (output == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(output, 0, outputSz);
        }
    }

#if defined(ECC_TIMING_RESISTANT) && (!defined(HAVE_FIPS) || \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION != 2))) && \
    !defined(HAVE_SELFTEST)
    if (ret == 0) {
        ret = wc_ecc_set_rng(ecc, rng);
    }
#else
    (void)rng;
#endif

    if (ret == 0) {
        PRIVATE_KEY_UNLOCK();
        ret = wc_ecc_shared_secret(ecc, pub, output, &outputSz);
        PRIVATE_KEY_LOCK();
    }

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

    LogStr("wc_ecc_shared_secret(priv, pub, output=%p, outputSz) = %d\n",
        output, ret);
    LogStr("output[%u]: [%p]\n", (word32)outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    if (output != NULL) {
        XMEMSET(output, 0, outputBufSz);
        XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1sign_1hash(
    JNIEnv* env, jobject this, jbyteArray hash_object, jobject rng_object)
{
    jbyteArray result = NULL;

#ifdef HAVE_ECC_SIGN
    int ret = 0;
    ecc_key* ecc = NULL;
    RNG*  rng    = NULL;
    byte* hash   = NULL;
    byte* signature = NULL;
    word32 hashSz = 0;
    word32 expectedSigSz = 0;
    word32 signatureSz = 0;
    word32 signatureBufSz = 0;

    ecc = (ecc_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    rng = (RNG*) getNativeStruct(env, rng_object);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    hash   = getByteArray(env, hash_object);
    hashSz = getByteArrayLength(env, hash_object);

    if (ecc == NULL || rng == NULL || hash == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        expectedSigSz = wc_ecc_sig_size(ecc);
        signatureSz = expectedSigSz;
        signatureBufSz = signatureSz;

        signature = (byte*)XMALLOC(signatureSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (signature == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(signature, 0, signatureSz);
        }
    }

    if (ret == 0) {
        ret = wc_ecc_sign_hash(hash, hashSz, signature, &signatureSz, rng, ecc);
    }

    if (ret == 0) {
        /* Sanity check on wc_ecc_sig_size() and actual length */
        if (expectedSigSz < signatureSz) {
            ret = BUFFER_E;
            throwWolfCryptException(env,
                "wc_ecc_sig_size() less than actual sig size");
        }
    }

    if (ret == 0) {
        result = (*env)->NewByteArray(env, signatureSz);

        if (result != NULL) {
            (*env)->SetByteArrayRegion(env, result, 0, signatureSz,
                                       (const jbyte*)signature);
        } else {
            releaseByteArray(env, hash_object, hash, JNI_ABORT);
            throwWolfCryptException(env, "Failed to allocate signature");
            return NULL;
        }
    } else {
        releaseByteArray(env, hash_object, hash, JNI_ABORT);
        throwWolfCryptExceptionFromError(env, ret);
        return NULL;
    }

    LogStr("wc_ecc_sign_hash(input, inSz, output, &outSz, rng, ecc) = %d\n",
        ret);

    if (signature != NULL) {
        LogStr("signature[%u]: [%p]\n", (word32)signatureSz, signature);
        LogHex((byte*) signature, 0, signatureSz);

        XMEMSET(signature, 0, signatureBufSz);
        XFREE(signature, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    releaseByteArray(env, hash_object, hash, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jboolean JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1verify_1hash(
    JNIEnv* env, jobject this, jbyteArray hash_object,
    jbyteArray signature_object)
{
#ifdef HAVE_ECC_VERIFY
    int ret = 0;
    int status = 0;
    ecc_key* ecc    = NULL;
    byte* hash      = NULL;
    byte* signature = NULL;
    word32 hashSz = 0, signatureSz = 0;

    ecc = (ecc_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return JNI_FALSE;
    }

    hash   = getByteArray(env, hash_object);
    hashSz = getByteArrayLength(env, hash_object);

    signature   = getByteArray(env, signature_object);
    signatureSz = getByteArrayLength(env, signature_object);

    if (ecc == NULL || hash == NULL || signature == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_ecc_verify_hash(signature, signatureSz, hash,
            hashSz, &status, ecc);
    }

    releaseByteArray(env, hash_object, hash, JNI_ABORT);
    releaseByteArray(env, signature_object, signature, JNI_ABORT);

    LogStr(
        "wc_ecc_verify_hash(sig, sigSz, hash, hashSz, &status, ecc); = %d\n",
        ret);

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    if (status == 1) {
        return JNI_TRUE;
    } else {
        return JNI_FALSE;
    }
#else
    throwNotCompiledInException(env);
    return JNI_FALSE;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1get_1curve_1size_1from_1name
  (JNIEnv* env, jobject this, jstring curveName)
{
    jint ret = 0;
#ifdef HAVE_ECC
    const char* name;

    if (curveName == NULL) {
        ret = BAD_FUNC_ARG;
    } else {
        name = (*env)->GetStringUTFChars(env, curveName, 0);
        ret = wc_ecc_get_curve_size_from_name(name);
        (*env)->ReleaseStringUTFChars(env, curveName, name);
    }

#else
    throwNotCompiledInException(env);
#endif
    return ret;
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1get_1curve_1name_1from_1id
  (JNIEnv* env, jclass this, jint curve_id)
{
    jstring name = NULL;
#ifdef HAVE_ECC
    const char* tmp = NULL;

    tmp = wc_ecc_get_curve_name_from_id(curve_id);
    if (tmp != NULL) {
        name = (*env)->NewStringUTF(env, tmp);
    }

#else
    throwNotCompiledInException(env);
#endif

    return name;
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1private_1key_1to_1pkcs8
  (JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;

#if defined(HAVE_ECC) && defined(WOLFSSL_KEY_GEN)
    int ret = 0;
    ecc_key* ecc = NULL;
    byte* derKey = NULL;
    byte* pkcs8  = NULL;
    word32 derKeySz = MAX_ECC_PRIVATE_DER_SZ;
    word32 pkcs8Sz  = 0;
    word32 derKeyBufSz = 0;

    int algoID   = ECDSAk;
    word32 oidSz = 0;
    const byte* curveOID = NULL;

    ecc = (ecc_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0 && ecc == NULL) {
        ret = BAD_FUNC_ARG;
    }

    /* Calculate length of private key DER */
    if (ret == 0) {
        ret = wc_EccKeyDerSize(ecc, 0);
        if (ret > 0) {
            derKeySz = ret;
            ret = 0;
        }
    }

    if (ret == 0) {
        derKeyBufSz = derKeySz;
        derKey = (byte*)XMALLOC(derKeySz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (derKey == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(derKey, 0, derKeySz);
        }
    }

    if (ret == 0) {
        PRIVATE_KEY_UNLOCK();
        ret = wc_EccPrivateKeyToDer(ecc, derKey, derKeySz);
        PRIVATE_KEY_LOCK();
        if (ret >= 0) {
            derKeySz = ret;
            ret = 0;
        }
    }

    if (ret == 0) {
        ret = wc_ecc_get_oid(ecc->dp->oidSum, &curveOID, &oidSz);
        if (ret > 0) {
            /* reset ret, returns oid as well as setting curveOID */
            ret = 0;
        }
    }

    if (ret == 0) {
        /* get pkcs8 output size, into pkcs8Sz */
        ret = wc_CreatePKCS8Key(NULL, &pkcs8Sz, derKey, derKeySz, algoID,
                                curveOID, oidSz);
        if (ret == LENGTH_ONLY_E) {
            ret = 0;
        }

        pkcs8 = (byte*)XMALLOC(pkcs8Sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (pkcs8 == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(pkcs8, 0, pkcs8Sz);
        }
    }

    if (ret == 0) {
        ret = wc_CreatePKCS8Key(pkcs8, &pkcs8Sz, derKey, derKeySz,
                                algoID, curveOID, oidSz);
        if (ret > 0) {
            /* reset ret, PKCS#8 size stored in pkcs8Sz */
            ret = 0;
        }
    }

    if (ret == 0) {
        result = (*env)->NewByteArray(env, pkcs8Sz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, pkcs8Sz,
                                       (const jbyte*) pkcs8);
        }
    }

    if (derKey != NULL) {
        XMEMSET(derKey, 0, derKeyBufSz);
        XFREE(derKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (pkcs8 != NULL) {
        XMEMSET(pkcs8, 0, pkcs8Sz);
        XFREE(pkcs8,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (ret < 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1get_1curve_1id_1from_1params
  (JNIEnv* env, jclass this, jint fieldSz, jbyteArray prime_object,
   jbyteArray af_object, jbyteArray bf_object, jbyteArray order_object,
   jbyteArray gx_object, jbyteArray gy_object, jint cofactor)
{
    int ret = 0;
#ifdef HAVE_ECC
    byte*  prime = getByteArray(env, prime_object);
    word32 primeSz = getByteArrayLength(env, prime_object);
    byte*  Af = getByteArray(env, af_object);
    word32 AfSz = getByteArrayLength(env, af_object);
    byte*  Bf = getByteArray(env, bf_object);
    word32 BfSz = getByteArrayLength(env, bf_object);
    byte*  order = getByteArray(env, order_object);
    word32 orderSz = getByteArrayLength(env, order_object);
    byte*  Gx = getByteArray(env, gx_object);
    word32 GxSz = getByteArrayLength(env, gx_object);
    byte*  Gy = getByteArray(env, gy_object);
    word32 GySz = getByteArrayLength(env, gy_object);

    if (prime == NULL || Af == NULL || Bf == NULL || order == NULL ||
        Gx == NULL || Gy == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_ecc_get_curve_id_from_params(fieldSz, prime, primeSz,
            Af, AfSz, Bf, BfSz, order, orderSz, Gx, GxSz, Gy, GySz, cofactor);
    }

    LogStr("wc_ecc_get_curve_id_from_params() = %d\n", ret);
#else
    throwNotCompiledInException(env);
#endif

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1export_1private_1raw
  (JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;

#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT)
    int ret = 0;
    ecc_key* ecc = NULL;
    byte* output = NULL;
    word32 outputSz = 0;

    ecc = (ecc_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    if (ecc == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        outputSz = wc_ecc_size(ecc);
        output = (byte*)XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (output == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(output, 0, outputSz);
        }
    }

    if (ret == 0) {
        PRIVATE_KEY_UNLOCK();
        ret = wc_ecc_export_private_only(ecc, output, &outputSz);
        PRIVATE_KEY_LOCK();
    }

    if (ret == 0) {
        result = (*env)->NewByteArray(env, outputSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, outputSz,
                (const jbyte*) output);
        } else {
            throwWolfCryptException(env, "Failed to allocate raw private key");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_ecc_export_private_raw(ecc=%p, output=%p, outputSz) = %d\n",
        ecc, output, ret);

    if (output != NULL) {
        XMEMSET(output, 0, outputSz);
        XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jobjectArray JNICALL Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1export_1public_1raw
  (JNIEnv* env, jobject this)
{
    jobjectArray result = NULL;

#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT)
    int ret = 0;
    ecc_key* ecc = NULL;
    byte* x = NULL;
    byte* y = NULL;
    word32 xSz = 0;
    word32 ySz = 0;
    jbyteArray xArray = NULL;
    jbyteArray yArray = NULL;
    jclass byteArrayClass = NULL;

    ecc = (ecc_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    if (ecc == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        xSz = wc_ecc_size(ecc);
        ySz = xSz;
        x = (byte*)XMALLOC(xSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        y = (byte*)XMALLOC(ySz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (x == NULL || y == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(x, 0, xSz);
            XMEMSET(y, 0, ySz);
        }
    }

    if (ret == 0) {
        ret = wc_ecc_export_public_raw(ecc, x, &xSz, y, &ySz);
    }

    if (ret == 0) {
        byteArrayClass = (*env)->FindClass(env, "[B");
        if (byteArrayClass == NULL) {
            ret = MEMORY_E;
        } else {
            result = (*env)->NewObjectArray(env, 2, byteArrayClass, NULL);
        }
    }

    if (ret == 0 && result != NULL) {
        xArray = (*env)->NewByteArray(env, xSz);
        yArray = (*env)->NewByteArray(env, ySz);

        if (xArray != NULL && yArray != NULL) {
            (*env)->SetByteArrayRegion(env, xArray, 0, xSz, (const jbyte*)x);
            (*env)->SetByteArrayRegion(env, yArray, 0, ySz, (const jbyte*)y);
            (*env)->SetObjectArrayElement(env, result, 0, xArray);
            (*env)->SetObjectArrayElement(env, result, 1, yArray);
        } else {
            throwWolfCryptException(env,
                "Failed to allocate coordinate arrays");
            ret = -1;
        }
    }

    if (ret != 0) {
        /* If error, free any array we may have created */
        if (xArray != NULL) {
            (*env)->DeleteLocalRef(env, xArray);
        }
        if (yArray != NULL) {
            (*env)->DeleteLocalRef(env, yArray);
        }
        if (result != NULL) {
            (*env)->DeleteLocalRef(env, result);
            result = NULL;
        }
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_ecc_export_public_raw(ecc=%p, x=%p, y=%p) = %d\n",
        ecc, x, y, ret);

    if (x != NULL) {
        XMEMSET(x, 0, xSz);
        XFREE(x, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (y != NULL) {
        XMEMSET(y, 0, ySz);
        XFREE(y, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1import_1private_1raw
  (JNIEnv* env, jobject this, jbyteArray priv_object, jstring curveName)
{
#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_IMPORT)
    int ret = 0;
    ecc_key* ecc = NULL;
    byte* privKey = NULL;
    word32 privKeySz = 0;
    const char* name = NULL;
    int curveId = 0;

    ecc = (ecc_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    privKey = getByteArray(env, priv_object);
    privKeySz = getByteArrayLength(env, priv_object);

    if (ecc == NULL || privKey == NULL || curveName == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        name = (*env)->GetStringUTFChars(env, curveName, 0);
        if (name == NULL) {
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        curveId = wc_ecc_get_curve_id_from_name(name);
        (*env)->ReleaseStringUTFChars(env, curveName, name);

        if (curveId < 0) {
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        /* Initialize ECC key structure */
        ret = wc_ecc_init(ecc);
    }

    if (ret == 0) {
        ret = wc_ecc_import_private_key(privKey, privKeySz, NULL, 0, ecc);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_ecc_import_unsigned(ecc=%p, privKey=%p) = %d\n",
           ecc, privKey, ret);

    releaseByteArray(env, priv_object, privKey, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1import_1public_1raw
  (JNIEnv* env, jobject this, jbyteArray x_object, jbyteArray y_object,
   jstring curveName)
{
#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_IMPORT)
    int ret = 0;
    ecc_key* ecc = NULL;
    byte* x = NULL;
    byte* y = NULL;
    word32 xSz = 0;
    word32 ySz = 0;
    const char* name = NULL;
    int curveId = 0;
    word32 expectedSz = 0;

    ecc = (ecc_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    x = getByteArray(env, x_object);
    xSz = getByteArrayLength(env, x_object);
    y = getByteArray(env, y_object);
    ySz = getByteArrayLength(env, y_object);

    if (ecc == NULL || x == NULL || y == NULL || curveName == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        name = (*env)->GetStringUTFChars(env, curveName, 0);
        if (name == NULL) {
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        curveId = wc_ecc_get_curve_id_from_name(name);
        /* Get expected size for curve */
        expectedSz = wc_ecc_get_curve_size_from_id(curveId);
        (*env)->ReleaseStringUTFChars(env, curveName, name);

        if (curveId < 0 || expectedSz <= 0) {
            ret = BAD_FUNC_ARG;
        }
    }

    if (xSz != expectedSz || ySz != expectedSz) {
        LogStr("ECC x or y size does not match expected size for curve\n");
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = wc_ecc_init(ecc);
    }

    if (ret == 0) {
        ret = wc_ecc_import_unsigned(ecc, x, y, NULL, curveId);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_ecc_import_unsigned(ecc=%p, x=%p, y=%p, expectedSz=%d) = %d\n",
           ecc, x, y, expectedSz, ret);

    releaseByteArray(env, x_object, x, JNI_ABORT);
    releaseByteArray(env, y_object, y, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1get_1curve_1id
  (JNIEnv* env, jobject this)
{
    jint result = 0;
#ifdef HAVE_ECC
    ecc_key* ecc = NULL;

    ecc = (ecc_key*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return -1;
    }

    if (ecc == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return -1;
    }

    if (ecc->dp != NULL) {
        result = ecc->dp->id;

    } else {
        throwWolfCryptException(env, "No curve parameters available");
        return -1;
    }

    LogStr("ecc->dp->id = %d\n", result);
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

/*
 * Returns String[] with curve parameters in the following order, based on
 * provided input curve name:
 *
 * [0] prime - field prime as hex string
 * [1] a - curve coefficient a as hex string
 * [2] b - curve coefficient b as hex string
 * [3] order - curve order as hex string
 * [4] gx - generator point x coordinate as hex string
 * [5] gy - generator point y coordinate as hex string
 * [6] cofactor - cofactor as decimal string
 *
 * Returns NULL on error, otherwise valid String[].
 */
JNIEXPORT jobjectArray JNICALL Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1get_1curve_1params_1from_1name
  (JNIEnv* env, jclass this, jstring curveName)
{
    jobjectArray result = NULL;
#ifdef HAVE_ECC
    int i;
    int ret;
    const char* name = NULL;
    int curveIdx = 0;
    const ecc_set_type* dp = NULL;
    jstring paramStrings[7] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL };
    char cofactorStr[32];
#if defined(HAVE_FIPS) && \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION == 2))
    int curveId = 0;
    ecc_key tempKey;
#endif

    if (curveName == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    name = (*env)->GetStringUTFChars(env, curveName, 0);
    if (name == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }

    /* Get curve index from name */
    curveIdx = wc_ecc_get_curve_idx_from_name(name);
    if (curveIdx < 0) {
        LogStr("wc_ecc_get_curve_idx_from_name failed, idx: %d\n", curveIdx);
        throwWolfCryptExceptionFromError(env, curveIdx);
        return NULL;
    }

    LogStr("wc_ecc_get_curve_idx_from_name(name=%s) = %d\n", name, curveIdx);

#if defined(HAVE_FIPS) && \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION == 2))
    /* Get curve parameters by creating a temporary ECC key with the curve.
     * wc_ecc_get_curve_params() exists in current wolfSSL but not older
     * FIPSv2 bundles. */
    curveId = wc_ecc_get_curve_id_from_name(name);
    (*env)->ReleaseStringUTFChars(env, curveName, name);

    if (curveId < 0) {
        throwWolfCryptExceptionFromError(env, curveId);
        return NULL;
    }

    ret = wc_ecc_init(&tempKey);
    if (ret == 0) {
        ret = wc_ecc_set_curve(&tempKey, 0, curveId);
        if ((ret == 0) && (tempKey.dp != NULL)) {
            dp = tempKey.dp;
            LogStr("tempKey.dp = %p (id=%d)\n", dp, dp->id);
        }
        wc_ecc_free(&tempKey);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return NULL;
    }
#else
    /* Get curve parameters directly */
    dp = wc_ecc_get_curve_params(curveIdx);
    (*env)->ReleaseStringUTFChars(env, curveName, name);
#endif /* HAVE_FIPS & HAVE_FIPS_VERSION */

    if (dp == NULL) {
        throwWolfCryptExceptionFromError(env, ECC_CURVE_OID_E);
        return NULL;
    }

    /* Create Java String[7], freed by Java when method returns if we
     * return in an error state since this is a local reference. */
    result = (*env)->NewObjectArray(env, 7,
        (*env)->FindClass(env, "java/lang/String"), NULL);
    if (result == NULL) {
        throwWolfCryptExceptionFromError(env, MEMORY_E);
        return NULL;
    }

    /* Convert curve parameters to Java strings:
     *     dp->prime = field prime
     *     dp->Af = curve coefficient a
     *     dp->Bf = curve coefficient b
     *     dp->order = curve order
     *     dp->Gx = generator x
     *     dp->Gy = generator y
     */
    paramStrings[0] = (*env)->NewStringUTF(env, dp->prime);
    paramStrings[1] = (*env)->NewStringUTF(env, dp->Af);
    paramStrings[2] = (*env)->NewStringUTF(env, dp->Bf);
    paramStrings[3] = (*env)->NewStringUTF(env, dp->order);
    paramStrings[4] = (*env)->NewStringUTF(env, dp->Gx);
    paramStrings[5] = (*env)->NewStringUTF(env, dp->Gy);

    /* Convert cofactor to string */
    ret = XSNPRINTF(cofactorStr, sizeof(cofactorStr), "%d", dp->cofactor);
    if (ret < 0 || ret >= (int)sizeof(cofactorStr)) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        return NULL;
    }
    paramStrings[6] = (*env)->NewStringUTF(env, cofactorStr);

    /* Set array elements */
    for (i = 0; i < 7; i++) {
        if (paramStrings[i] == NULL) {
            return NULL;
        }
        (*env)->SetObjectArrayElement(env, result, i, paramStrings[i]);
        (*env)->DeleteLocalRef(env, paramStrings[i]);
    }

    LogStr("wc_ecc_get_curve_params_from_name(curveName=%s) = success\n",
        dp->name);

#else
    throwNotCompiledInException(env);
#endif

    return result;
}

/*
 * Get all curve names supported by the compiled wolfCrypt library.
 *
 * Return String[] containing all available curve names, or NULL on error.
 */
JNIEXPORT jobjectArray JNICALL Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1get_1all_1curve_1names
  (JNIEnv* env, jclass this)
{
    jobjectArray result = NULL;
#ifdef HAVE_ECC
    jstring* curveNames = NULL;
    int curveCount = 0;
    int i;
    int j;
    int maxIdx = 0;

    /* First pass: find maximum valid curve index by testing consecutive
     * indices until we find an invalid one */
    for (i = 0; i < ECC_CURVE_MAX; i++) {
        if (wc_ecc_is_valid_idx(i)) {
            maxIdx = i;
        }
    }

    if (maxIdx == 0) {
        throwWolfCryptExceptionFromError(env, ECC_CURVE_OID_E);
        return NULL;
    }

    /* Second pass: count valid curves with names */
    for (i = 0; i <= maxIdx; i++) {
        if (wc_ecc_is_valid_idx(i)) {
            const char* name = wc_ecc_get_name(wc_ecc_get_curve_id(i));
            if (name != NULL) {
                curveCount++;
            }
        }
    }

    if (curveCount == 0) {
        throwWolfCryptExceptionFromError(env, ECC_CURVE_OID_E);
        return NULL;
    }

    /* Dynamically allocate array based on counted curves */
    curveNames = (jstring*)XMALLOC(curveCount * sizeof(jstring), NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (curveNames == NULL) {
        throwWolfCryptExceptionFromError(env, MEMORY_E);
        return NULL;
    }

    /* Third pass: collect curve names */
    curveCount = 0;
    for (i = 0; i <= maxIdx; i++) {
        if (wc_ecc_is_valid_idx(i)) {
            const char* name = wc_ecc_get_name(wc_ecc_get_curve_id(i));
            if (name != NULL) {
                curveNames[curveCount] = (*env)->NewStringUTF(env, name);
                if (curveNames[curveCount] == NULL) {
                    /* Clean up any previously created strings */
                    for (j = 0; j < curveCount; j++) {
                        (*env)->DeleteLocalRef(env, curveNames[j]);
                    }
                    XFREE(curveNames, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    throwWolfCryptExceptionFromError(env, MEMORY_E);
                    return NULL;
                }
                curveCount++;
            }
        }
    }

    if (curveCount == 0) {
        XFREE(curveNames, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        throwWolfCryptExceptionFromError(env, ECC_CURVE_OID_E);
        return NULL;
    }

    /* Create Java String array with actual count */
    result = (*env)->NewObjectArray(env, curveCount,
        (*env)->FindClass(env, "java/lang/String"), NULL);
    if (result == NULL) {
        /* Clean up curve name strings */
        for (i = 0; i < curveCount; i++) {
            (*env)->DeleteLocalRef(env, curveNames[i]);
        }
        XFREE(curveNames, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        throwWolfCryptExceptionFromError(env, MEMORY_E);
        return NULL;
    }

    /* Fill array with collected curve names */
    for (i = 0; i < curveCount; i++) {
        (*env)->SetObjectArrayElement(env, result, i, curveNames[i]);
        (*env)->DeleteLocalRef(env, curveNames[i]);
    }

    /* Clean up dynamic array */
    XFREE(curveNames, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    LogStr("wc_ecc_get_all_curve_names() found %d curves (maxIdx: %d)\n",
        curveCount, maxIdx);

#else
    throwNotCompiledInException(env);
#endif

    return result;
}

