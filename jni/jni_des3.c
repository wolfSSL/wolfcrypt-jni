/* jni_des3.c
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
#include <wolfssl/wolfcrypt/des3.h>

#include <com_wolfssl_wolfcrypt_Des3.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Des3_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
#ifndef NO_DES3
    Des3* des = NULL;

    des = (Des3*) XMALLOC(sizeof(Des3), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (des == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate Des3 object");
    }
    else {
        XMEMSET(des, 0, sizeof(Des3));
    }

    LogStr("new Des3() = %p\n", des);

    return (jlong)(uintptr_t)des;
#else
    throwNotCompiledInException(env);

    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Des3_native_1set_1key_1internal(
    JNIEnv* env, jobject this, jbyteArray key_object, jbyteArray iv_object,
    jint opmode)
{
#ifndef NO_DES3
    int ret = 0;
    Des3* des = NULL;
    byte* key = NULL;
    byte* iv  = NULL;

    des = (Des3*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    key = getByteArray(env, key_object);
    iv  = getByteArray(env, iv_object);

    ret = (!des || !key) /* iv is optional */
        ? BAD_FUNC_ARG
        : wc_Des3_SetKey(des, key, iv, opmode);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_Des3SetKey(Des3=%p, key, iv, opmode) = %d\n", des, ret);

    releaseByteArray(env, key_object, key, JNI_ABORT);
    releaseByteArray(env, iv_object, iv, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jint JNICALL
Java_com_wolfssl_wolfcrypt_Des3_native_1update_1internal__I_3BII_3BI(
    JNIEnv* env, jobject this, jint opmode,
    jbyteArray input_object, jint offset, jint length,
    jbyteArray output_object, jint outputOffset)
{
    int ret = 0;

#ifndef NO_DES3
    Des3* des    = NULL;
    byte* input  = NULL;
    byte* output = NULL;

    des = (Des3*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return 0;
    }

    input  = getByteArray(env, input_object);
    output = getByteArray(env, output_object);

    if (!des || !input || !output) {
        ret = BAD_FUNC_ARG; /* NULL sanitizers */
    }
    else if (offset < 0 || length < 0 || outputOffset < 0) {
        ret = BAD_FUNC_ARG; /* signed sanizizers */
    }
    else if ((word32)(offset + length) >
             getByteArrayLength(env, input_object)) {
        ret = BUFFER_E; /* buffer overflow check */
    }
    else if ((word32)(outputOffset + length) >
             getByteArrayLength(env, output_object)) {
        ret = BUFFER_E; /* buffer overflow check */
    }
    else if (opmode == DES_ENCRYPTION) {
        ret = wc_Des3_CbcEncrypt(des, output+outputOffset,input+offset, length);
        LogStr("wc_Des3CbcEncrypt(des=%p, out, in, inSz) = %d\n", des, ret);
    }
    else {
        ret = wc_Des3_CbcDecrypt(des, output+outputOffset,input+offset, length);
        LogStr("wc_Des3CbcDecrypt(des=%p, out, in, inSz) = %d\n", des, ret);
    }

    LogStr("input[%u]: [%p]\n", (word32)length, input + offset);
    LogHex((byte*) input, offset, length);
    LogStr("output[%u]: [%p]\n", (word32)length, output + outputOffset);
    LogHex((byte*) output, outputOffset, length);

    releaseByteArray(env, input_object, input, JNI_ABORT);
    releaseByteArray(env, output_object, output, ret);

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        ret = 0; /* 0 bytes stored in output */
    }
    else {
        ret = length;
    }
#else
    throwNotCompiledInException(env);
#endif

    return ret;
}

JNIEXPORT jint JNICALL
Java_com_wolfssl_wolfcrypt_Des3_native_1update_1internal__ILjava_nio_ByteBuffer_2IILjava_nio_ByteBuffer_2I(
    JNIEnv* env, jobject this, jint opmode,
    jobject input_object, jint offset, jint length,
    jobject output_object, jint outputOffset)
{
    int ret = 0;

#ifndef NO_DES3
    Des3* des    = NULL;
    byte* input  = NULL;
    byte* output = NULL;

    des = (Des3*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return 0;
    }

    input  = getDirectBufferAddress(env, input_object);
    output = getDirectBufferAddress(env, output_object);

    if (!des || !input || !output) {
        ret = BAD_FUNC_ARG; /* NULL sanitizers */
    }
    else if (offset < 0 || length < 0) {
        ret = BAD_FUNC_ARG; /* signed sanizizers */
    }
    else if ((word32)(offset + length) >
             getDirectBufferLimit(env, input_object)) {
        ret = BUFFER_E; /* buffer overflow check */
    }
    else if ((word32)(outputOffset + length) >
             getDirectBufferLimit(env, output_object)) {
        ret = BUFFER_E; /* buffer overflow check */
    }
    else if (opmode == DES_ENCRYPTION) {
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
    LogHex((byte*) input, offset, length);
    LogStr("output[%u]: [%p]\n", (word32)length, output);
    LogHex((byte*) output, 0, length);
#else
    throwNotCompiledInException(env);
#endif

    return ret;
}
