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

#define WOLFCRYPT_JNI_DEBUG_ON
#include <wolfcrypt_jni_debug.h>

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

    ret = wc_ecc_init(ecc);
    if (ret != 0)
        throwWolfCryptException(env, "Failed to initialize Ecc object");

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

    ret = wc_ecc_make_key(rng, size, ecc);
    if (ret != 0)
        throwWolfCryptException(env, "Failed to generate Ecc key");

    LogStr("ecc_make_key(rng, size, ecc=%p) = %d\n", ecc, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1import_1x963(
    JNIEnv* env, jobject this, jbyteArray key_object)
{
#ifdef HAVE_ECC
    int ret = 0;
    ecc_key* ecc = (ecc_key*) getNativeStruct(env, this);
    byte* key = getByteArray(env, key_object);
    word32 keySz = getByteArrayLength(env, key_object);

    ret = wc_ecc_import_x963(key, keySz, ecc);
    if (ret != 0)
        throwWolfCryptException(env, "Failed to import X9.63 key");

    LogStr("ecc_import_x963(key, keySz, ecc=%p) = %d\n", ecc, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1export_1x963(
    JNIEnv* env, jobject this)
{
    return NULL;
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_wc_1EccPrivateKeyDecode(
    JNIEnv* env, jobject this, jbyteArray key_object)
{
#ifdef HAVE_ECC
    int ret = 0;
    word32 idx = 0;
    ecc_key* ecc = (ecc_key*) getNativeStruct(env, this);
    byte* key = getByteArray(env, key_object);
    word32 keySz = getByteArrayLength(env, key_object);

    ret = wc_EccPrivateKeyDecode(key, &idx, ecc, keySz);
    if (ret != 0)
        throwWolfCryptException(env, "Failed to decode private key");

    LogStr("wc_EccPrivateKeyDecode(key, keySz, ecc=%p) = %d\n", ecc, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_wc_1EccKeyToDer(
    JNIEnv* env, jobject this)
{
    return NULL;
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_wc_1EccPublicKeyDecode(
    JNIEnv* env, jobject this, jbyteArray key_object)
{
#ifdef HAVE_ECC
    int ret = 0;
    word32 idx = 0;
    ecc_key* ecc = (ecc_key*) getNativeStruct(env, this);
    byte* key = getByteArray(env, key_object);
    word32 keySz = getByteArrayLength(env, key_object);

    ret = wc_EccPublicKeyDecode(key, &idx, ecc, keySz);
    if (ret != 0)
        throwWolfCryptException(env, "Failed to decode public key");

    LogStr("wc_EccPublicKeyDecode(key, keySz, ecc=%p) = %d\n", ecc, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_wc_1EccPublicKeyToDer(
    JNIEnv* env, jobject this)
{
    return NULL;
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Ecc_wc_1ecc_1shared_1secret(
    JNIEnv* env, jobject this, jobject pub_object)
{
    jbyteArray result = NULL;

#ifdef HAVE_ECC
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

    ret = wc_ecc_shared_secret(ecc, pub, output, &outputSz);
    if (ret == 0) {
        result = (*env)->NewByteArray(env, outputSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, outputSz,
                                                         (const jbyte*) output);
        } else {
            throwWolfCryptException(env, "Failed to allocate shared secret");
        }
    } else {
        throwWolfCryptException(env, "Failed to generate shared secret");
    }

    LogStr("wc_ecc_shared_secret(priv, pub, output=%p, outputSz) = %d\n",
        output, ret);
    LogStr("output[%u]: [%p]\n", (word32)outputSz, output);
    LogHex((byte*) output, outputSz);

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

#ifdef HAVE_ECC
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
        return result;
    }

    ret = wc_ecc_sign_hash(hash, hashSz, signature, &signatureSz, rng, ecc);
    if (ret == 0) {
        result = (*env)->NewByteArray(env, signatureSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, signatureSz,
                                                       (const jbyte*)signature);
        } else {
            throwWolfCryptException(env, "Failed to allocate signature");
        }
    } else {
        throwWolfCryptException(env, "Failed to generate signature");
    }

    LogStr("wc_ecc_sign_hash(input, inSz, output, &outSz, rng, ecc) = %d\n",
        ret);
    LogStr("signature[%u]: [%p]\n", (word32)signatureSz, signature);
    LogHex((byte*) signature, signatureSz);

    XFREE(signature, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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

#ifdef HAVE_ECC
    int status = 0;
    ecc_key* ecc = (ecc_key*) getNativeStruct(env, this);
    byte* hash = getByteArray(env, hash_object);
    word32 hashSz = getByteArrayLength(env, hash_object);
    byte* signature = getByteArray(env, signature_object);
    word32 signatureSz = getByteArrayLength(env, signature_object);

    ret = wc_ecc_verify_hash(signature, signatureSz, hash,hashSz, &status, ecc);
    if (ret == 0) {
        ret = status;
    } else {
        throwWolfCryptException(env, "Failed to verify signature");
    }

    LogStr(
        "wc_ecc_verify_hash(sig, sigSz, hash, hashSz, &status, ecc); = %lu\n",
        ret);
#else
    throwNotCompiledInException(env);
#endif

    return ret;
}

