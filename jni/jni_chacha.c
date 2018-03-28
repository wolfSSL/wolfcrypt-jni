/* jni_Chacha.c
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
#include <wolfssl/wolfcrypt/chacha.h>
#include <wolfssl/wolfcrypt/asn.h>

#include <com_wolfssl_wolfcrypt_Chacha.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>


JNIEXPORT jlong JNICALL
Java_com_wolfssl_wolfcrypt_Chacha_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    void* ret = 0;

#ifdef HAVE_CHACHA
    ret = XMALLOC(sizeof(ChaCha), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (ret == NULL)
        throwOutOfMemoryException(env, "Failed to allocate ChaCha object");

    LogStr("new ChaCha() = %p\n", (void*)ret);
#else
    throwNotCompiledInException(env);
#endif

    return (jlong) ret;
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Chacha_wc_1Chacha_1init(
    JNIEnv* env, jobject this)
{
#ifdef HAVE_CHACHA
    int ret = 0;
    ChaCha* chacha = (ChaCha*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    ret = (!chacha)
        ? BAD_FUNC_ARG
        : 0;

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("Chacha_init(ChaCha=%p) = %d\n", chacha, ret);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Chacha_wc_1Chacha_1free(
    JNIEnv* env, jobject this)
{
#ifdef HAVE_CHACHA
    ChaCha* chacha = (ChaCha*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception */
        return;
    }

    if (chacha)
        XFREE(chacha, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    LogStr("Chacha_free(chacha=%p)\n", chacha);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Chacha_wc_1Chacha_1setIV
  (JNIEnv* env, jobject this, jbyteArray iv_object)
{
#if defined(HAVE_CHACHA)
    int ret = 0;
    ChaCha* chacha = NULL;
    byte* iv   = NULL;
    word32 ivSz = 0;

    chacha = (ChaCha*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }
    iv   = getByteArray(env, iv_object);
    ivSz = getByteArrayLength(env, iv_object);

    if (!chacha || !iv) {
        ret = BAD_FUNC_ARG;
    } else {
        ret = wc_Chacha_SetIV(chacha, iv, ivSz);
    }

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_Chacha_SetIV(chacha=%p) = %d\n", chacha, ret);

    releaseByteArray(env, iv_object, iv, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}
    
JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Chacha_wc_1Chacha_1setKey
  (JNIEnv* env, jobject this, jbyteArray key_object)
{
#if defined(HAVE_CHACHA)
    int ret = 0;
    ChaCha* chacha = NULL;
    byte* key   = NULL;
    word32 keySz = 0;

    chacha = (ChaCha*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }
    key   = getByteArray(env, key_object);
    keySz = getByteArrayLength(env, key_object);

    if (!chacha || !key) {
        ret = BAD_FUNC_ARG;
    } else {
        ret = wc_Chacha_SetKey(chacha, key, keySz);
    }

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_Chacha_SetKey(chacha=%p) = %d\n", chacha, ret);

    releaseByteArray(env, key_object, key, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Chacha_wc_1Chacha_1process(
    JNIEnv* env, jobject this, jbyteArray input_obj)
{
    jbyteArray result = NULL;

#ifdef HAVE_CHACHA
    int ret = 0;
    ChaCha* chacha = NULL;
    byte* input  = NULL;
    int inputSz = 0;
    byte* output = NULL;

    chacha = (ChaCha*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }
    
    input = getByteArray(env, input_obj);
    inputSz = getByteArrayLength(env, input_obj);

    if (input == NULL) {
        return NULL;
    }

    output = XMALLOC(inputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate key buffer");
        return result;
    }

    ret = (!chacha)
        ? BAD_FUNC_ARG
        : wc_Chacha_Process(chacha, output, input, inputSz);

    if (ret == 0) {
        result = (*env)->NewByteArray(env, inputSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, inputSz,
                                                         (const jbyte*) output);
        } else {
            throwWolfCryptException(env, "Failed to allocate memory for Chacha_process");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_Chacha_Process() = %d\n", output, ret);
    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    throwNotCompiledInException(env);
#endif
    return result;
}
