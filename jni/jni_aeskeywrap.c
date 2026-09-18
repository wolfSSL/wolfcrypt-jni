/* jni_aeskeywrap.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <com_wolfssl_wolfcrypt_AesKeyWrap.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

#if !defined(NO_AES) && defined(HAVE_AES_KEYWRAP)
    #define WC_JNI_HAVE_AES_KEYWRAP
#endif

#ifdef WC_JNI_HAVE_AES_KEYWRAP

/* Argument checks shared by wrap and unwrap, jlong math avoids overflow.
 * minIn is the minimum input length, outLen the bytes written to output.
 * Returns 0, BAD_FUNC_ARG, or BUFFER_E */
static int AesKeyWrapCheckArgs(JNIEnv* env, Aes* aes, jbyteArray in_object,
    jint inOffset, jint inLen, jbyteArray out_object, jint outOffset,
    jlong outLen, jbyteArray iv_object, jint minIn)
{
    jlong inArrSz  = 0;
    jlong outArrSz = 0;
    jlong ivSz     = 0;

    if (aes == NULL || in_object == NULL || out_object == NULL) {
        return BAD_FUNC_ARG;
    }

    if (inOffset < 0 || inLen < 0 || outOffset < 0) {
        return BAD_FUNC_ARG;
    }

    if (inLen < minIn ||
        (inLen % com_wolfssl_wolfcrypt_AesKeyWrap_KEYWRAP_BLOCK_SIZE) != 0) {
        return BAD_FUNC_ARG;
    }

    if (iv_object != NULL) {
        ivSz = (jlong)getByteArrayLength(env, iv_object);
        if (ivSz != com_wolfssl_wolfcrypt_AesKeyWrap_IV_SIZE) {
            return BAD_FUNC_ARG;
        }
    }

    inArrSz  = (jlong)getByteArrayLength(env, in_object);
    outArrSz = (jlong)getByteArrayLength(env, out_object);

    if (((jlong)inOffset + (jlong)inLen) > inArrSz) {
        return BUFFER_E; /* input overflow check */
    }

    if (((jlong)outOffset + outLen) > outArrSz) {
        return BUFFER_E; /* output overflow check */
    }

    return 0;
}

#endif /* WC_JNI_HAVE_AES_KEYWRAP */

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_AesKeyWrap_mallocNativeStruct_1internal
  (JNIEnv* env, jobject this)
{
#ifdef WC_JNI_HAVE_AES_KEYWRAP
    Aes* aes = NULL;
    (void)this;

    aes = (Aes*)XMALLOC(sizeof(Aes), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (aes == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate Aes object");
    }
    else {
        XMEMSET(aes, 0, sizeof(Aes));
    }

    LogStr("new AesKeyWrap() = %p\n", aes);

    return (jlong)(uintptr_t)aes;
#else
    (void)this;
    throwNotCompiledInException(env);
    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesKeyWrap_wc_1AesInit
  (JNIEnv* env, jobject this)
{
#ifdef WC_JNI_HAVE_AES_KEYWRAP
    int ret = 0;
    Aes* aes = NULL;

    aes = (Aes*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, if so stop and return */
        return;
    }

    if (aes == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    }

    LogStr("wc_AesInit(aes=%p) = %d\n", aes, ret);

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }
#else
    (void)this;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesKeyWrap_wc_1AesFree
  (JNIEnv* env, jobject this)
{
#ifdef WC_JNI_HAVE_AES_KEYWRAP
    Aes* aes = NULL;

    aes = (Aes*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, if so stop and return */
        return;
    }

    if (aes != NULL) {
        wc_AesFree(aes);
    }

    LogStr("wc_AesFree(aes=%p)\n", aes);
#else
    (void)this;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesKeyWrap_wc_1AesSetKey
  (JNIEnv* env, jobject this, jbyteArray key_object, jint opmode)
{
#ifdef WC_JNI_HAVE_AES_KEYWRAP
    int ret = 0;
    int dir = 0;
    Aes* aes = NULL;
    byte* key = NULL;
    word32 keySz = 0;
    jboolean keyIsCopy = JNI_FALSE;

    aes = (Aes*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, if so stop and return */
        return;
    }

    key   = getByteArrayIsCopy(env, key_object, &keyIsCopy);
    keySz = getByteArrayLength(env, key_object);

    if (aes == NULL || key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else if (opmode == com_wolfssl_wolfcrypt_AesKeyWrap_ENCRYPT_MODE) {
        dir = AES_ENCRYPTION;
    }
    else if (opmode == com_wolfssl_wolfcrypt_AesKeyWrap_DECRYPT_MODE) {
        dir = AES_DECRYPTION;
    }
    else {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = wc_AesSetKey(aes, key, keySz, NULL, dir);
    }

    LogStr("wc_AesSetKey(aes=%p, keySz=%u, opmode=%d) = %d\n",
        aes, keySz, (int)opmode, ret);

    zeroizeByteArrayCopy(key, keySz, keyIsCopy);
    releaseByteArray(env, key_object, key, JNI_ABORT);

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }
#else
    (void)this;
    (void)key_object;
    (void)opmode;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_AesKeyWrap_wc_1AesKeyWrap_1ex
  (JNIEnv* env, jobject this, jbyteArray in_object, jint inOffset,
   jint inLen, jbyteArray out_object, jint outOffset, jbyteArray iv_object)
{
    int ret = 0;
#ifdef WC_JNI_HAVE_AES_KEYWRAP
    Aes* aes  = NULL;
    byte* in  = NULL;
    byte* iv  = NULL;
    byte* tmp = NULL;
    word32 inArrSz = 0;
    word32 tmpSz   = 0;
    jboolean inIsCopy = JNI_FALSE;

    aes = (Aes*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, if so stop and return */
        return 0;
    }

    ret = AesKeyWrapCheckArgs(env, aes, in_object, inOffset, inLen,
        out_object, outOffset,
        (jlong)inLen + com_wolfssl_wolfcrypt_AesKeyWrap_KEYWRAP_BLOCK_SIZE,
        iv_object, com_wolfssl_wolfcrypt_AesKeyWrap_MIN_WRAP_INPUT_SIZE);

    if (ret == 0) {
        in      = getByteArrayIsCopy(env, in_object, &inIsCopy);
        inArrSz = getByteArrayLength(env, in_object);
        iv      = getByteArray(env, iv_object); /* NULL = default IV */

        if (in == NULL || (iv_object != NULL && iv == NULL)) {
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        tmpSz = (word32)inLen +
            com_wolfssl_wolfcrypt_AesKeyWrap_KEYWRAP_BLOCK_SIZE;
        tmp = (byte*)XMALLOC(tmpSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (tmp == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(tmp, 0, tmpSz);
        }
    }

    if (ret == 0) {
        ret = wc_AesKeyWrap_ex(aes, in + inOffset, (word32)inLen, tmp,
            tmpSz, iv);
        LogStr("wc_AesKeyWrap_ex(aes=%p, inLen=%d, iv=%p) = %d\n",
            aes, (int)inLen, iv, ret);

        if (ret > 0 && (word32)ret != tmpSz) {
            /* must be inSz + 8 */
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret > 0) {
        (*env)->SetByteArrayRegion(env, out_object, outOffset, ret,
            (jbyte*)tmp);
        if ((*env)->ExceptionOccurred(env)) {
            /* leave JNI exception pending */
            ret = 0;
        }
    }

    zeroizeByteArrayCopy(in, inArrSz, inIsCopy);
    releaseByteArray(env, in_object, in, JNI_ABORT);
    releaseByteArray(env, iv_object, iv, JNI_ABORT);

    if (tmp != NULL) {
    #if (LIBWOLFSSL_VERSION_HEX >= 0x05008004) && \
        !defined(WOLFSSL_NO_FORCE_ZERO)
        wc_ForceZero(tmp, tmpSz);
    #else
        XMEMSET(tmp, 0, tmpSz);
    #endif
        XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (ret < 0) {
        throwWolfCryptExceptionFromError(env, ret);
        ret = 0; /* 0 bytes stored in output */
    }
#else
    (void)this;
    (void)in_object;
    (void)inOffset;
    (void)inLen;
    (void)out_object;
    (void)outOffset;
    (void)iv_object;
    throwNotCompiledInException(env);
#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_AesKeyWrap_wc_1AesKeyUnWrap_1ex
  (JNIEnv* env, jobject this, jbyteArray in_object, jint inOffset,
   jint inLen, jbyteArray out_object, jint outOffset, jbyteArray iv_object)
{
    int ret = 0;
#ifdef WC_JNI_HAVE_AES_KEYWRAP
    Aes* aes  = NULL;
    byte* in  = NULL;
    byte* iv  = NULL;
    byte* tmp = NULL;
    word32 tmpSz = 0;

    aes = (Aes*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, if so stop and return */
        return 0;
    }

    ret = AesKeyWrapCheckArgs(env, aes, in_object, inOffset, inLen,
        out_object, outOffset,
        (jlong)inLen - com_wolfssl_wolfcrypt_AesKeyWrap_KEYWRAP_BLOCK_SIZE,
        iv_object, com_wolfssl_wolfcrypt_AesKeyWrap_MIN_UNWRAP_INPUT_SIZE);

    if (ret == 0) {
        in = getByteArray(env, in_object);
        iv = getByteArray(env, iv_object); /* NULL = default IV */

        if (in == NULL || (iv_object != NULL && iv == NULL)) {
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        tmpSz = (word32)inLen -
            com_wolfssl_wolfcrypt_AesKeyWrap_KEYWRAP_BLOCK_SIZE;
        tmp = (byte*)XMALLOC(tmpSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (tmp == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(tmp, 0, tmpSz);
        }
    }

    if (ret == 0) {
        ret = wc_AesKeyUnWrap_ex(aes, in + inOffset, (word32)inLen,
            tmp, tmpSz, iv);
        LogStr("wc_AesKeyUnWrap_ex(aes=%p, inLen=%d, iv=%p) = %d\n",
            aes, (int)inLen, iv, ret);

        if (ret > 0 && (word32)ret != tmpSz) {
            /* must be inSz - 8 */
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret > 0) {
        (*env)->SetByteArrayRegion(env, out_object, outOffset, ret,
            (jbyte*)tmp);
        if ((*env)->ExceptionOccurred(env)) {
            /* leave JNI exception pending */
            ret = 0;
        }
    }

    releaseByteArray(env, in_object, in, JNI_ABORT);
    releaseByteArray(env, iv_object, iv, JNI_ABORT);

    if (tmp != NULL) {
    #if (LIBWOLFSSL_VERSION_HEX >= 0x05008004) && \
        !defined(WOLFSSL_NO_FORCE_ZERO)
        wc_ForceZero(tmp, tmpSz);
    #else
        XMEMSET(tmp, 0, tmpSz);
    #endif
        XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (ret < 0) {
        throwWolfCryptExceptionFromError(env, ret);
        ret = 0; /* 0 bytes stored in output */
    }
#else
    (void)this;
    (void)in_object;
    (void)inOffset;
    (void)inLen;
    (void)out_object;
    (void)outOffset;
    (void)iv_object;
    throwNotCompiledInException(env);
#endif

    return ret;
}

