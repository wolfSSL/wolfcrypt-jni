/* jni_asn.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <com_wolfssl_wolfcrypt_Asn.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Asn_encodeSignature__Ljava_nio_ByteBuffer_2Ljava_nio_ByteBuffer_2JI(
    JNIEnv* env, jclass class, jobject encoded_object, jobject hash_object,
    jlong hashSize, jint hashOID)
{
    byte* encoded = getDirectBufferAddress(env, encoded_object);
    byte* hash = getDirectBufferAddress(env, hash_object);

    if (encoded == NULL || hash == NULL) {
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
    }
    else {
        setDirectBufferLimit(env, encoded_object,
            wc_EncodeSignature(encoded, hash, (word32)hashSize, hashOID));
    }
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Asn_encodeSignature___3B_3BJI(
    JNIEnv* env, jclass class, jbyteArray encoded_object,
    jbyteArray hash_object, jlong hashSize, jint hashOID)
{
    byte* encoded = getByteArray(env, encoded_object);
    byte* hash = getByteArray(env, hash_object);
    jlong ret = 0;

    if (encoded == NULL || hash == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_EncodeSignature(encoded, hash, (word32)hashSize, hashOID);
    }

    releaseByteArray(env, encoded_object, encoded, ret < 0);
    releaseByteArray(env, hash_object, hash, ret < 0);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getCTC_1HashOID(
    JNIEnv* env, jclass class, jint type)
{
    return wc_GetCTC_HashOID(type);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getPkcs8AlgoID
  (JNIEnv* env, jclass class, jbyteArray pkcs8Der)
{
#if !defined(NO_ASN) && !defined(NO_PWDBASED) && defined(HAVE_PKCS8)
    int ret = 0;
    word32 algoId = 0;
    byte* p8 = NULL;
    byte* p8Copy = NULL;
    word32 p8Len = 0;

    if (pkcs8Der != NULL) {
        p8 = (byte*)(*env)->GetByteArrayElements(env, pkcs8Der, NULL);
        p8Len = (*env)->GetArrayLength(env, pkcs8Der);
    }

    if (p8 == NULL || p8Len == 0) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        p8Copy = (byte*)XMALLOC(p8Len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (p8Copy == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        /* Copy array since ToTraditional modifies source buffer */
        XMEMSET(p8Copy, 0, p8Len);
        XMEMCPY(p8Copy, p8, p8Len);

        ret = ToTraditional_ex(p8Copy, p8Len, &algoId);
        if (ret > 0) {
            /* returns length of header, but not needed here */
            ret = 0;
        }
    }

    if (p8Copy != NULL) {
        XMEMSET(p8Copy, 0, p8Len);
        XFREE(p8Copy, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (pkcs8Der != NULL) {
        (*env)->ReleaseByteArrayElements(env, pkcs8Der, (jbyte*)p8, JNI_ABORT);
    }

    if (ret == 0) {
        ret = (int)algoId;
    }

    return (jint)ret;

#else
    (void)env;
    (void)class;
    (void)pkcs8Der;
    return (jint)NOT_COMPILED_IN;
#endif
}

