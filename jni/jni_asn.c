/* jni_asn.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

    if (!encoded || !hash)
        throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
    else
        setDirectBufferLimit(env, encoded_object,
            wc_EncodeSignature(encoded, hash, hashSize, hashOID));
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Asn_encodeSignature___3B_3BJI(
    JNIEnv* env, jclass class, jbyteArray encoded_object,
    jbyteArray hash_object, jlong hashSize, jint hashOID)
{
    byte* encoded = getByteArray(env, encoded_object);
    byte* hash = getByteArray(env, hash_object);
    jlong ret = 0;

    ret = (!encoded || !hash)
        ? BAD_FUNC_ARG
        : wc_EncodeSignature(encoded, hash, hashSize, hashOID);

    releaseByteArray(env, encoded_object, encoded, ret < 0);
    releaseByteArray(env, hash_object, hash, ret < 0);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getCTC_1HashOID(
    JNIEnv* env, jclass class, jint type)
{
    return wc_GetCTC_HashOID(type);
}
