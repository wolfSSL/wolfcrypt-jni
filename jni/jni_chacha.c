/* jni_Chacha.c
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
#ifdef HAVE_CHACHA
    ChaCha* chacha = NULL;

    chacha = (ChaCha*)XMALLOC(sizeof(ChaCha), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (chacha == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate ChaCha object");
    }
    else {
        XMEMSET(chacha, 0, sizeof(ChaCha));
    }

    LogStr("new ChaCha object allocated = %p\n", chacha);

    return (jlong)(uintptr_t)chacha;

#else
    throwNotCompiledInException(env);

    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Chacha_wc_1Chacha_1setIV
  (JNIEnv* env, jobject this, jbyteArray iv_object)
{
#if defined(HAVE_CHACHA)
    int ret = 0;
    ChaCha* chacha = NULL;
    byte* iv   = NULL;

    chacha = (ChaCha*)(uintptr_t)getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }
    iv = getByteArray(env, iv_object);

    if (chacha == NULL || iv == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = wc_Chacha_SetIV(chacha, iv, 0);
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

    chacha = (ChaCha*)(uintptr_t)getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }
    key   = getByteArray(env, key_object);
    keySz = getByteArrayLength(env, key_object);

    if (chacha == NULL || key == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
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

    chacha = (ChaCha*)(uintptr_t)getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    input = getByteArray(env, input_obj);
    inputSz = getByteArrayLength(env, input_obj);

    if (chacha == NULL || input == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        output = (byte*)XMALLOC(inputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (output == NULL) {
            throwOutOfMemoryException(env, "Failed to allocate key buffer");
            return result;
        }
    }

    if (ret == 0) {
        XMEMSET(output, 0, inputSz);

        ret = wc_Chacha_Process(chacha, output, input, inputSz);
    }

    if (ret == 0) {
        result = (*env)->NewByteArray(env, inputSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, inputSz,
                                       (const jbyte*) output);
        } else {
            throwWolfCryptException(env,
                "Failed to allocate memory for Chacha_process");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_Chacha_Process(): output = %p, ret = %d\n", output, ret);
    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    throwNotCompiledInException(env);
#endif
    return result;
}
