/* jni_aescmac.c
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

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#elif !defined(__ANDROID__)
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/cmac.h>

#include <com_wolfssl_wolfcrypt_AesCmac.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_AesCmac_mallocNativeStruct_1internal(
    JNIEnv* env, jobject this)
{
#ifdef WOLFSSL_CMAC
    Cmac* cmac = NULL;

    cmac = (Cmac*)XMALLOC(sizeof(Cmac), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (cmac == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate Cmac object");
        return (jlong)0;
    }

    /* Initialize the CMAC structure to a known clean state */
    XMEMSET(cmac, 0, sizeof(Cmac));

    LogStr("new Cmac() = %p\n", cmac);

    return (jlong)(uintptr_t)cmac;
#else
    throwNotCompiledInException(env);
    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesCmac_native_1init(
    JNIEnv* env, jobject this)
{
#ifdef WOLFSSL_CMAC
    Cmac* cmac = (Cmac*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    /* CMAC struct is already zero-initialized in mallocNativeStruct_internal */
    /* Actual initialization happens in wc_CmacSetKey when we have the key */

    LogStr("native_init(cmac=%p)\n", cmac);
    (void)cmac; /* suppress unused variable warning */
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesCmac_native_1free(
    JNIEnv* env, jobject this)
{
#ifdef WOLFSSL_CMAC
    Cmac* cmac = (Cmac*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    LogStr("free Cmac %p\n", cmac);

    if (cmac) {
        /* Only clear the CMAC struct - do NOT free the memory here.
         * The base class NativeStruct.xfree() will handle the actual
         * memory deallocation to avoid double-free. */
        XMEMSET(cmac, 0, sizeof(Cmac));
    }
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesCmac_wc_1CmacSetKey(
    JNIEnv* env, jobject this, jbyteArray key_object)
{
#ifdef WOLFSSL_CMAC
    int ret = 0;
    Cmac* cmac = NULL;
    byte* key  = NULL;
    word32 keySz = 0;

    cmac = (Cmac*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    key   = getByteArray(env, key_object);
    keySz = getByteArrayLength(env, key_object);

    if (!cmac || !key) {
        ret = BAD_FUNC_ARG;
    } else {
        /* Initialize CMAC with the provided key */
        ret = wc_InitCmac(cmac, key, keySz, WC_CMAC_AES, NULL);
    }

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_InitCmac(cmac=%p, key, %d) = %d\n", cmac, keySz, ret);

    releaseByteArray(env, key_object, key, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesCmac_wc_1CmacUpdate__B(
    JNIEnv* env, jobject this, jbyte data)
{
#ifdef WOLFSSL_CMAC
    int ret = 0;
    Cmac* cmac = (Cmac*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    ret = (!cmac)
        ? BAD_FUNC_ARG
        : wc_CmacUpdate(cmac, (const byte*)&data, 1);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_CmacUpdate(cmac=%p, data, 1) = %d\n", cmac, ret);
    LogStr("data: %02x\n", data);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesCmac_wc_1CmacUpdate___3BII(
    JNIEnv* env, jobject this, jbyteArray data_object, jint offset, jint length)
{
#ifdef WOLFSSL_CMAC
    int ret = 0;
    Cmac* cmac = NULL;
    byte* data = NULL;
    word32 dataSz = 0;

    cmac = (Cmac*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    data = getByteArray(env, data_object);
    dataSz = getByteArrayLength(env, data_object);

    /* Validate bounds to prevent buffer overflow */
    if (!cmac || !data || offset < 0 || length < 0 ||
        (word32)(offset + length) > dataSz) {
        ret = BAD_FUNC_ARG;
    } else {
        ret = wc_CmacUpdate(cmac, data + offset, length);
    }

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_CmacUpdate(cmac=%p, data, length) = %d\n", cmac, ret);
    LogStr("data[%u]: [%p]\n", (word32)length, data + offset);
    LogHex((byte*) data, offset, length);

    releaseByteArray(env, data_object, data, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesCmac_wc_1CmacUpdate__Ljava_nio_ByteBuffer_2II(
    JNIEnv* env, jobject this, jobject data_object, jint offset, jint length)
{
#ifdef WOLFSSL_CMAC
    int ret = 0;
    Cmac* cmac = NULL;
    byte* data = NULL;
    word32 bufferLimit = 0;

    cmac = (Cmac*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    data = getDirectBufferAddress(env, data_object);
    bufferLimit = getDirectBufferLimit(env, data_object);

    /* Validate bounds to prevent buffer overflow */
    if (!cmac || !data || offset < 0 || length < 0 ||
        (word32)(offset + length) > bufferLimit) {
        ret = BAD_FUNC_ARG;
    } else {
        ret = wc_CmacUpdate(cmac, data + offset, length);
    }

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_CmacUpdate(cmac=%p, data, length) = %d\n", cmac, ret);
    LogStr("data[%u]: [%p]\n", (word32)length, data + offset);
    LogHex((byte*) data, offset, length);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_AesCmac_wc_1CmacFinal(
    JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;
#ifdef WOLFSSL_CMAC
    int ret = 0;
    word32 macSz = AES_BLOCK_SIZE;
    Cmac* cmac = NULL;
    byte tmp[AES_BLOCK_SIZE];

    cmac = (Cmac*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    ret = (!cmac)
        ? BAD_FUNC_ARG
        : wc_CmacFinal(cmac, tmp, &macSz);

    if (ret == 0) {
        result = (*env)->NewByteArray(env, macSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, macSz,
                (const jbyte*) tmp);
        } else {
            throwWolfCryptException(env, "Failed to allocate cmac");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_CmacFinal(cmac=%p, result) = %d\n", cmac, ret);
    LogStr("result[%u]: [%p]\n", (word32)macSz, tmp);
    LogHex(tmp, 0, macSz);
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_AesCmac_wc_1AesCmacGenerate(
    JNIEnv* env, jobject this, jbyteArray data_object, jint dataSz,
    jbyteArray key_object, jint keySz, jbyteArray mac_object, jint macSz)
{
#ifdef WOLFSSL_CMAC
    int ret = 0;
    byte* data = NULL;
    byte* key = NULL;
    byte* mac = NULL;
    word32 actualDataSz, actualKeySz, actualMacArraySz;

    data = getByteArray(env, data_object);
    key = getByteArray(env, key_object);
    mac = getByteArray(env, mac_object);

    if (data == NULL || key == NULL || mac == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Validate size parameters against actual array sizes */
        actualDataSz = getByteArrayLength(env, data_object);
        actualKeySz = getByteArrayLength(env, key_object);
        actualMacArraySz = getByteArrayLength(env, mac_object);

        if (dataSz < 0 || keySz < 0 || macSz < 0 ||
            (word32)dataSz > actualDataSz ||
            (word32)keySz > actualKeySz ||
            (word32)macSz > actualMacArraySz) {
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0 ) {
        /* Use a local buffer for the MAC result to avoid corrupting
         * Java memory */
        byte tmp[AES_BLOCK_SIZE];
        word32 tmpSz = AES_BLOCK_SIZE;

        ret = wc_AesCmacGenerate(tmp, &tmpSz, data, dataSz, key, keySz);

        if (ret == 0) {
            /* Copy result back to Java byte array, ensuring we don't exceed
             * the original buffer size */
            word32 copySize =
                (tmpSz <= (word32)macSz) ? tmpSz : (word32)macSz;
            (*env)->SetByteArrayRegion(env, mac_object, 0, copySize,
                (const jbyte*) tmp);
        }
    }

    LogStr("wc_AesCmacGenerate(data=%p, dataSz=%d, key=%p, keySz=%d) = %d\n",
           data, dataSz, key, keySz, ret);

    releaseByteArray(env, data_object, data, JNI_ABORT);
    releaseByteArray(env, key_object, key, JNI_ABORT);
    releaseByteArray(env, mac_object, mac, JNI_ABORT);

    return ret;
#else
    throwNotCompiledInException(env);
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_AesCmac_wc_1AesCmacVerify(
    JNIEnv* env, jobject this, jbyteArray mac_object, jint macSz,
    jbyteArray data_object, jint dataSz, jbyteArray key_object, jint keySz)
{
#ifdef WOLFSSL_CMAC
    int ret = 0;
    byte* mac = NULL;
    byte* data = NULL;
    byte* key = NULL;
    word32 actualMacSz, actualDataSz, actualKeySz;

    mac = getByteArray(env, mac_object);
    data = getByteArray(env, data_object);
    key = getByteArray(env, key_object);

    if (mac == NULL || data == NULL || key == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Validate size parameters against actual array sizes */
        actualMacSz = getByteArrayLength(env, mac_object);
        actualDataSz = getByteArrayLength(env, data_object);
        actualKeySz = getByteArrayLength(env, key_object);

        if (macSz < 0 || dataSz < 0 || keySz < 0 ||
            (word32)macSz > actualMacSz ||
            (word32)dataSz > actualDataSz ||
            (word32)keySz > actualKeySz) {
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        ret = wc_AesCmacVerify(mac, macSz, data, dataSz, key, keySz);
    }

    LogStr("wc_AesCmacVerify(mac=%p, macSz=%d, data=%p, dataSz=%d, "
        "key=%p, keySz=%d) = %d\n", mac, macSz, data, dataSz, key, keySz, ret);
    LogHex(mac, 0, macSz);

    releaseByteArray(env, mac_object, mac, JNI_ABORT);
    releaseByteArray(env, data_object, data, JNI_ABORT);
    releaseByteArray(env, key_object, key, JNI_ABORT);

    return ret;
#else
    throwNotCompiledInException(env);
    return NOT_COMPILED_IN;
#endif
}

