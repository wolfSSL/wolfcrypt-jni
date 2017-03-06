/* jni_des3.c
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
#include <wolfssl/wolfcrypt/des3.h>

#include <com_wolfssl_wolfcrypt_Des3.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Des3_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    jlong ret = 0;

#ifndef NO_DES3
    ret = (jlong) XMALLOC(sizeof(Des3), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Des3 object");

    LogStr("new Des3() = %p\n", (void*)ret);
#else
    throwNotCompiledInException(env);
#endif

    return ret;
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Des3_native_1set_1key(
    JNIEnv* env, jobject this, jbyteArray key_object, jbyteArray iv_object,
    jint opmode)
{
#ifndef NO_Des3
    int ret = 0;
    Des3* des = (Des3*) getNativeStruct(env, this);
    byte* key = getByteArray(env, key_object);
    byte* iv = getByteArray(env, iv_object);

    ret = wc_Des3_SetKey(des, key, iv, opmode);
    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_Des3SetKey(Des3=%p, key, iv, opmode) = %d\n", des, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jint JNICALL
Java_com_wolfssl_wolfcrypt_Des3_native_1update__I_3BII_3BI(
    JNIEnv* env, jobject this, jint opmode,
    jbyteArray input_object, jint offset, jint length,
    jbyteArray output_object, jint outputOffset)
{
#ifndef NO_Des3
    int ret = 0;
    Des3* des = (Des3*) getNativeStruct(env, this);
    byte* input = getByteArray(env, input_object);
    byte* output = getByteArray(env, output_object);

    if (opmode == DES_ENCRYPTION) {
        ret = wc_Des3_CbcEncrypt(des, output+outputOffset,input+offset, length);
        LogStr("wc_Des3CbcEncrypt(des=%p, out, in, inSz) = %d\n", des, ret);
    }
    else {
        ret = wc_Des3_CbcDecrypt(des, output+outputOffset,input+offset, length);
        LogStr("wc_Des3CbcDecrypt(des=%p, out, in, inSz) = %d\n", des, ret);
    }

    releaseByteArray(env, output_object, output, ret);

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        ret = 0; /* 0 bytes stored in output */
    }
    else {
        ret = length;
    }

    LogStr("input[%u]: [%p]\n", (word32)length, input + offset);
    LogHex((byte*) input + offset, length);
    LogStr("output[%u]: [%p]\n", (word32)length, output + outputOffset);
    LogHex((byte*) output + outputOffset, length);
#else
    throwNotCompiledInException(env);
#endif

    return ret;
}

JNIEXPORT jint JNICALL
Java_com_wolfssl_wolfcrypt_Des3_native_1update__ILjava_nio_ByteBuffer_2IILjava_nio_ByteBuffer_2(
    JNIEnv* env, jobject this, jint opmode,
    jobject input_object, jint offset, jint length,
    jobject output_object)
{
    int ret = 0;

#ifndef NO_Des3
    Des3* des = (Des3*) getNativeStruct(env, this);
    byte* input = getDirectBufferAddress(env, input_object);
    byte* output = getDirectBufferAddress(env, output_object);

    if (opmode == DES_ENCRYPTION) {
        ret = wc_Des3_CbcEncrypt(des, output, input + offset, length);
        LogStr("wc_Des3CbcEncrypt(des=%p, out, in, inSz) = %d\n", des, ret);
    }
    else {
        ret = wc_Des3_CbcDecrypt(des, output, input + offset, length);
        LogStr("wc_Des3CbcDecrypt(des=%p, out, in, inSz) = %d\n", des, ret);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        ret = 0; /* 0 bytes stored in output */
    }
    else {
        ret = length;
    }

    LogStr("input[%u]: [%p]\n", (word32)length, input + offset);
    LogHex((byte*) input + offset, length);
    LogStr("output[%u]: [%p]\n", (word32)length, output);
    LogHex((byte*) output, length);
#else
    throwNotCompiledInException(env);
#endif

    return ret;
}
