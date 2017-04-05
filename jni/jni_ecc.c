/* jni_ecc.c
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
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn.h>

#include <com_wolfssl_wolfcrypt_Ecc.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

#define MAX_ECC_PRIVATE_DER_SZ 128

JNIEXPORT jlong JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    void* ret = 0;

#ifdef HAVE_ECC
    ret = XMALLOC(sizeof(ecc_key), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (ret == NULL)
        throwOutOfMemoryException(env, "Failed to allocate Ecc object");

    LogStr("new Ecc() = %p\n", (void*)ret);
#else
    throwNotCompiledInException(env);
#endif

    return (jlong) ret;
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1init(
    JNIEnv* env, jobject this)
{
#ifdef HAVE_ECC
    int ret = 0;
    ecc_key* ecc = (ecc_key*) getNativeStruct(env, this);

    ret = (!ecc)
        ? BAD_FUNC_ARG
        : wc_ecc_init(ecc);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

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

    if (ecc)
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
    ecc_key* ecc = (ecc_key*) getNativeStruct(env, this);
    RNG* rng = (RNG*) getNativeStruct(env, rng_object);

    ret = (!ecc || !rng)
        ? BAD_FUNC_ARG
        : wc_ecc_make_key(rng, size, ecc);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

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
    ecc_key* ecc = (ecc_key*) getNativeStruct(env, this);
    RNG* rng = (RNG*) getNativeStruct(env, rng_object);
    const char* name = (*env)->GetStringUTFChars(env, curveName, 0);

    ret = (!ecc || !rng || !curveName || !name)
        ? BAD_FUNC_ARG
        : wc_ecc_get_curve_id_from_name(name);

    (*env)->ReleaseStringUTFChars(env, curveName, name);

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
    ecc_key* ecc = (ecc_key*) getNativeStruct(env, this);

    ret = (!ecc)
        ? BAD_FUNC_ARG
        : wc_ecc_check_key(ecc);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

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
    ecc_key* ecc = (ecc_key*) getNativeStruct(env, this);
    byte* priv = getByteArray(env, priv_object);
    word32 privSz = getByteArrayLength(env, priv_object);
    byte* pub = getByteArray(env, pub_object);
    word32 pubSz = getByteArrayLength(env, pub_object);
    const char* name = NULL;

    /* pub may be null if only importing private key */
    if (!ecc || !priv) {
        ret = BAD_FUNC_ARG;

    } else {
        /* detect, and later skip, leading zero byte */
        if (priv[0] == 0)
            idx = 1;

        if (curveName != NULL) {
            name = (*env)->GetStringUTFChars(env, curveName, 0);
            ret = wc_ecc_get_curve_id_from_name(name);
            (*env)->ReleaseStringUTFChars(env, curveName, name);

            /* import with curve id, ret stores curve id */
            ret = wc_ecc_import_private_key_ex(priv + idx, privSz - idx, pub,
                                               pubSz, ecc, ret);
        } else {
            ret = wc_ecc_import_private_key(priv + idx, privSz - idx, pub,
                                               pubSz, ecc);
        }
    }

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

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
    ecc_key* ecc = (ecc_key*) getNativeStruct(env, this);
    byte* output = NULL;
    word32 outputSz = wc_ecc_size(ecc);

    output = XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate key buffer");
        return result;
    }

    ret = (!ecc)
        ? BAD_FUNC_ARG
        : wc_ecc_export_private_only(ecc, output, &outputSz);

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

    LogStr("wc_ecc_export_x963(ecc, output=%p, outputSz) = %d\n", output, ret);
    LogStr("output[%u]: [%p]\n", (word32)outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
    ecc_key* ecc = (ecc_key*) getNativeStruct(env, this);
    byte* key = getByteArray(env, key_object);
    word32 keySz = getByteArrayLength(env, key_object);

    ret = (!ecc || !key)
        ? BAD_FUNC_ARG
        : wc_ecc_import_x963(key, keySz, ecc);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("ecc_import_x963(key, keySz, ecc=%p) = %d\n", ecc, ret);

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
    ecc_key* ecc = (ecc_key*) getNativeStruct(env, this);
    byte* output = NULL;
    word32 outputSz = 0;

    /* get size */
    wc_ecc_export_x963(ecc, NULL, &outputSz);

    output = XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate key buffer");
        return result;
    }

    ret = (!ecc)
        ? BAD_FUNC_ARG
        : wc_ecc_export_x963(ecc, output, &outputSz);

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

    LogStr("wc_ecc_export_x963(ecc, output=%p, outputSz) = %d\n", output, ret);
    LogStr("output[%u]: [%p]\n", (word32)outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
    ecc_key* ecc = (ecc_key*) getNativeStruct(env, this);
    byte* key = getByteArray(env, key_object);
    word32 keySz = getByteArrayLength(env, key_object);

    ret = (!ecc || !key)
        ? BAD_FUNC_ARG
        : wc_EccPrivateKeyDecode(key, &idx, ecc, keySz);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_EccPrivateKeyDecode(key, keySz, ecc=%p) = %d\n", ecc, ret);

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
    ecc_key* ecc = (ecc_key*) getNativeStruct(env, this);
    byte* output = NULL;
    word32 outputSz = 256;

    output = XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate key buffer");
        return result;
    }

    ret = (!ecc)
        ? BAD_FUNC_ARG
        : wc_EccKeyToDer(ecc, output, outputSz);

    if (ret >= 0) {
        outputSz = ret;
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

    LogStr("wc_EccKeyToDer(ecc, output=%p, outputSz) = %d\n", output, ret);
    LogStr("output[%u]: [%p]\n", outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
    ecc_key* ecc = (ecc_key*) getNativeStruct(env, this);
    byte* key = getByteArray(env, key_object);
    word32 keySz = getByteArrayLength(env, key_object);

    ret = (!ecc || !key)
        ? BAD_FUNC_ARG
        : wc_EccPublicKeyDecode(key, &idx, ecc, keySz);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_EccPublicKeyDecode(key, keySz, ecc=%p) = %d\n", ecc, ret);

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
    ecc_key* ecc = (ecc_key*) getNativeStruct(env, this);
    byte* output = NULL;
    word32 outputSz = 256;

    output = XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate key buffer");
        return result;
    }

    ret = (!ecc)
        ? BAD_FUNC_ARG
        : wc_EccPublicKeyToDer(ecc, output, outputSz, 1);

    if (ret >= 0) {
        outputSz = ret;
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

    LogStr("wc_EccPublicKeyToDer(ecc, out=%p, outSz) = %d\n", output, ret);
    LogStr("output[%u]: [%p]\n", outputSz, output);
    LogHex((byte*) output, 0, outputSz);

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1shared_1secret(
    JNIEnv* env, jobject this, jobject pub_object)
{
    jbyteArray result = NULL;

#ifdef HAVE_ECC_DHE
    int ret = 0;
    ecc_key* ecc = (ecc_key*) getNativeStruct(env, this);
    ecc_key* pub = (ecc_key*) getNativeStruct(env, pub_object);
    byte* output = NULL;
    word32 outputSz = wc_ecc_size(ecc);

    output = XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env,
                                     "Failed to allocate shared secret buffer");
        return result;
    }

    ret = (!ecc || !pub)
        ? BAD_FUNC_ARG
        : wc_ecc_shared_secret(ecc, pub, output, &outputSz);

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

    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
    ecc_key* ecc = (ecc_key*) getNativeStruct(env, this);
    RNG* rng = (RNG*) getNativeStruct(env, rng_object);
    byte* hash = getByteArray(env, hash_object);
    word32 hashSz = getByteArrayLength(env, hash_object);
    byte* signature = NULL;
    word32 signatureSz = wc_ecc_sig_size(ecc);

    signature = XMALLOC(signatureSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (signature == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate signature buffer");

        releaseByteArray(env, hash_object, hash, JNI_ABORT);

        return result;
    }

    ret = (!ecc || !rng || !hash)
        ? BAD_FUNC_ARG
        : wc_ecc_sign_hash(hash, hashSz, signature, &signatureSz, rng, ecc);

    if (ret == 0) {
        result = (*env)->NewByteArray(env, signatureSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, signatureSz,
                                                       (const jbyte*)signature);
        } else {
            throwWolfCryptException(env, "Failed to allocate signature");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_ecc_sign_hash(input, inSz, output, &outSz, rng, ecc) = %d\n",
        ret);
    LogStr("signature[%u]: [%p]\n", (word32)signatureSz, signature);
    LogHex((byte*) signature, 0, signatureSz);

    XFREE(signature, NULL, DYNAMIC_TYPE_TMP_BUFFER);

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
    jlong ret = 0;

#ifdef HAVE_ECC_VERIFY
    int status = 0;
    ecc_key* ecc = (ecc_key*) getNativeStruct(env, this);
    byte* hash = getByteArray(env, hash_object);
    word32 hashSz = getByteArrayLength(env, hash_object);
    byte* signature = getByteArray(env, signature_object);
    word32 signatureSz = getByteArrayLength(env, signature_object);

    ret = (!ecc || !hash || !signature)
        ? BAD_FUNC_ARG
        : wc_ecc_verify_hash(signature, signatureSz, hash,hashSz, &status, ecc);

    if (ret == 0) {
        ret = status;
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr(
        "wc_ecc_verify_hash(sig, sigSz, hash, hashSz, &status, ecc); = %lu\n",
        ret);

    releaseByteArray(env, hash_object, hash, JNI_ABORT);
    releaseByteArray(env, signature_object, signature, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif

    return ret;
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

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1private_1key_1to_1pkcs8
  (JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;

#ifdef HAVE_ECC
    int ret = 0;
    ecc_key* ecc = (ecc_key*) getNativeStruct(env, this);
    byte* derKey = NULL;
    byte* pkcs8  = NULL;
    word32 derKeySz = MAX_ECC_PRIVATE_DER_SZ;
    word32 pkcs8Sz  = 0;

    int algoID   = 0;
    word32 oidSz = 0;
    const byte* curveOID = NULL;

    derKey = XMALLOC(derKeySz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (derKey == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate DER key buffer");
        return result;
    }

    /* get pkcs8 output size, into pkcs8Sz */
    ret = wc_CreatePKCS8Key(NULL, &pkcs8Sz, derKey, derKeySz, algoID,
                            curveOID, oidSz);

    pkcs8 = XMALLOC(pkcs8Sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pkcs8 == NULL) {
        XFREE(derKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        throwOutOfMemoryException(env, "Failed to allocate PKCS8 key buffer");
        return result;
    }

    ret = (!ecc)
        ? BAD_FUNC_ARG
        : wc_EccPrivateKeyToDer(ecc, derKey, derKeySz);

    if (ret >= 0) {
        derKeySz = ret;
        algoID = ECDSAk;
        ret = wc_ecc_get_oid(ecc->dp->oidSum, &curveOID, &oidSz);
    }

    if (ret >= 0) {
        ret = wc_CreatePKCS8Key(pkcs8, &pkcs8Sz, derKey, derKeySz,
                                algoID, curveOID, oidSz);
    }

    if (ret >= 0) {
        result = (*env)->NewByteArray(env, ret);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, ret,
                                       (const jbyte*) pkcs8);
        }
    }

    XFREE(derKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pkcs8,  NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (ret < 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

