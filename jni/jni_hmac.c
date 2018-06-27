/* jni_hmac.c
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
#include <wolfssl/wolfcrypt/hmac.h>

#include <com_wolfssl_wolfcrypt_Hmac.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

/* copy from cyassl/hmac.c */
static INLINE int GetHashSizeByType(int type)
{
    if (!(type == WC_MD5 || type == WC_SHA    || type == WC_SHA256 || type == WC_SHA384
                      || type == WC_SHA512 || type == BLAKE2B_ID))
        return BAD_FUNC_ARG;

    switch (type) {
        #ifndef NO_MD5
        case WC_MD5:
            return MD5_DIGEST_SIZE;
        break;
        #endif

        #ifndef NO_SHA
        case WC_SHA:
            return SHA_DIGEST_SIZE;
        break;
        #endif
        
        #ifndef NO_SHA256
        case WC_SHA256:
            return SHA256_DIGEST_SIZE;
        break;
        #endif
        
        #if defined(CYASSL_SHA384) || defined(WOLFSSL_SHA384)
        case WC_SHA384:
            return SHA384_DIGEST_SIZE;
        break;
        #endif
        
        #if defined(CYASSL_SHA512) || defined(WOLFSSL_SHA512)
        case WC_SHA512:
            return SHA512_DIGEST_SIZE;
        break;
        #endif
        
        #ifdef HAVE_BLAKE2 
        case BLAKE2B_ID:
            return BLAKE2B_OUTBYTES;
        break;
        #endif
        
        default:
            return BAD_FUNC_ARG;
        break;
    }
}

JNIEXPORT jlong JNICALL
Java_com_wolfssl_wolfcrypt_Hmac_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    jlong ret = 0;

#ifndef NO_HMAC
    ret = (jlong) XMALLOC(sizeof(Hmac), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Hmac object");

    LogStr("new Hmac() = %p\n", (void*)ret);
#else
    throwNotCompiledInException(env);
#endif

    return ret;
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Hmac_wc_1HmacSetKey(
    JNIEnv* env, jobject this, jint type, jbyteArray key_object)
{
#ifndef NO_HMAC
    int ret = 0;
    Hmac* hmac = NULL;
    byte* key  = NULL;
    word32 keySz = 0;

    hmac = (Hmac*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    key   = getByteArray(env, key_object);
    keySz = getByteArrayLength(env, key_object);

    ret = (!hmac || !key)
        ? BAD_FUNC_ARG
        : wc_HmacSetKey(hmac, type, key, keySz);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("HmacInit(hmac=%p) = %d\n", hmac, ret);

    releaseByteArray(env, key_object, key, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Hmac_wc_1HmacUpdate__B(
    JNIEnv* env, jobject this, jbyte data)
{
#ifndef NO_HMAC
    int ret = 0;
    Hmac* hmac = (Hmac*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    ret = (!hmac)
        ? BAD_FUNC_ARG
        : wc_HmacUpdate(hmac, (const byte*)&data, 1);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_HmacUpdate(hmac=%p, data, 1) = %d\n", hmac, ret);
    LogStr("data: %02x\n", data);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Hmac_wc_1HmacUpdate___3BII(
    JNIEnv* env, jobject this, jbyteArray data_object, jint offset, jint length)
{
#ifndef NO_HMAC
    int ret = 0;
    Hmac* hmac = NULL;
    byte* data = NULL;

    hmac = (Hmac*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    data = getByteArray(env, data_object);

    ret = (!hmac || !data)
        ? BAD_FUNC_ARG
        : wc_HmacUpdate(hmac, data + offset, length);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_HmacUpdate(hmac=%p, data, length) = %d\n", hmac, ret);
    LogStr("data[%u]: [%p]\n", (word32)length, data + offset);
    LogHex((byte*) data, offset, length);

    releaseByteArray(env, data_object, data, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL
Java_com_wolfssl_wolfcrypt_Hmac_wc_1HmacUpdate__Ljava_nio_ByteBuffer_2II(
    JNIEnv* env, jobject this, jobject data_object, jint offset, jint length)
{
#ifndef NO_HMAC
    int ret = 0;
    Hmac* hmac = NULL;
    byte* data = NULL;

    hmac = (Hmac*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    data = getDirectBufferAddress(env, data_object);

    ret = (!hmac || !data)
        ? BAD_FUNC_ARG
        : wc_HmacUpdate(hmac, data + offset, length);

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_HmacUpdate(hmac=%p, data, length) = %d\n", hmac, ret);
    LogStr("data[%u]: [%p]\n", (word32)length, data + offset);
    LogHex((byte*) data, offset, length);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_wolfcrypt_Hmac_wc_1HmacFinal(
    JNIEnv* env, jobject this)
{
    jbyteArray result = NULL;

#ifndef NO_HMAC
    int ret = 0;
    Hmac* hmac = NULL;
    int   hmacSz = 0;
    byte tmp[MAX_DIGEST_SIZE];

    hmac = (Hmac*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }
    hmacSz = GetHashSizeByType(hmac->macType);

    if (hmacSz < 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return result;
    }

    ret = (!hmac)
        ? BAD_FUNC_ARG
        : wc_HmacFinal(hmac, tmp);

    if (ret == 0) {
        result = (*env)->NewByteArray(env, hmacSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, hmacSz,
                                                            (const jbyte*) tmp);
        } else {
            throwWolfCryptException(env, "Failed to allocate hmac");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_HmacFinal(hmac=%p, result) = %d\n", hmac, ret);
    LogStr("result[%u]: [%p]\n", (word32)hmacSz, tmp);
    LogHex(tmp, 0, hmacSz);
#else
    throwNotCompiledInException(env);
#endif

    return result;
}

JNIEXPORT jint JNICALL
Java_com_wolfssl_wolfcrypt_Hmac_wc_1HmacSizeByType(
    JNIEnv* env, jobject this, jint type)
{
    jint result = 0;

#ifndef NO_HMAC
    int ret = GetHashSizeByType(type);

    if (ret < 0)
        throwWolfCryptExceptionFromError(env, ret);
    else
        result = ret;

    LogStr("wc_HmacSizeByType(type=%d) = %d\n", type, ret);
#else
    throwNotCompiledInException(env);
#endif

    return result;
}
