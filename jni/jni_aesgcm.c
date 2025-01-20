/* jni_aesgcm.c
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
#include <wolfssl/wolfcrypt/aes.h>

#include <com_wolfssl_wolfcrypt_AesGcm.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_AesGcm_mallocNativeStruct_1internal
  (JNIEnv* env, jobject this)
{
#ifndef NO_AES
    Aes* aes = NULL;
    (void)this;

    aes = (Aes*)XMALLOC(sizeof(Aes), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (aes == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate Aes object");
    }
    else {
        XMEMSET(aes, 0, sizeof(Aes));
    }

    LogStr("new AesGcm() = %p\n", aes);

    return (jlong)(uintptr_t)aes;
#else
    (void)this;
    throwNotCompiledInException(env);
    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesGcm_wc_1AesInit
  (JNIEnv* env, jobject this)
{
#ifndef NO_AES
    int ret = 0;
    Aes* aes = NULL;
    (void)this;
    
    aes = (Aes*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, if so stop and return */
        return;
    }

    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_AesInit(aes=%p)\n", aes);
#else
    (void)this;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesGcm_wc_1AesFree
  (JNIEnv* env, jobject this)
{
#ifndef NO_AES
    Aes* aes = NULL;
    (void)this;
    
    aes = (Aes*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, if so stop and return */
        return;
    }

    wc_AesFree(aes);

    LogStr("wc_AesFree(aes=%p)\n", aes);
#else
    (void)this;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesGcm_wc_1AesGcmSetKey
  (JNIEnv* env, jobject this, jbyteArray keyArr)
{
#if !defined(NO_AES) && defined(HAVE_AESGCM)
    int ret = 0;
    Aes* aes = NULL;
    const byte* key = NULL;
    word32 keyLen = 0;

    aes = (Aes*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, if so stop and return */
        return;
    }

    if (keyArr != NULL) {
        key = (const byte*)(*env)->GetByteArrayElements(env, keyArr, NULL);
        keyLen = (*env)->GetArrayLength(env, keyArr);
    }

    if (key == NULL || keyLen == 0) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = wc_AesGcmSetKey(aes, key, keyLen);
    }

    if (keyArr != NULL) {
        (*env)->ReleaseByteArrayElements(env, keyArr, (jbyte*)key, JNI_ABORT);
    }

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_AesGcmSetKey(aes = %p, keylen = %d)\n", aes, keyLen);
#else
    (void)this;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_AesGcm_wc_1AesGcmEncrypt
  (JNIEnv* env, jobject this, jbyteArray inputArr, jbyteArray ivArr, jbyteArray authTagArr, jbyteArray authInArr)
{
#if !defined(NO_AES) && defined(HAVE_AESGCM)
    int ret = 0;
    Aes* aes = NULL;
    const byte* in = NULL;
    const byte* iv = NULL;
    byte* authTag = NULL;
    const byte* authIn = NULL;
    word32 inLen = 0;
    word32 ivSz = 0;
    word32 authTagSz = 0;
    word32 authInSz = 0;

    byte* out = NULL;
    jbyteArray outArr = NULL;

    aes = (Aes*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, if so stop and return */
        return NULL;
    }

    if (inputArr != NULL) {
        in = (const byte*)(*env)->GetByteArrayElements(env, inputArr, NULL);
        inLen = (*env)->GetArrayLength(env, inputArr);
    }
    if (ivArr != NULL) {
        iv = (byte*)(*env)->GetByteArrayElements(env, ivArr, NULL);
        ivSz = (*env)->GetArrayLength(env, ivArr);
    }
    if (authTagArr != NULL) {
        authTag = (byte*)(*env)->GetByteArrayElements(env, authTagArr, NULL);
        authTagSz = (*env)->GetArrayLength(env, authTagArr);
    }
    if (authInArr != NULL) {
        authIn = (byte*)(*env)->GetByteArrayElements(env, authInArr, NULL);
        authInSz = (*env)->GetArrayLength(env, authInArr);
    }

    /* authIn can be null */
    if (in == NULL || inLen == 0 || iv == NULL || ivSz == 0 ||
        authTag == NULL || authTagSz == 0) {
        ret = BAD_FUNC_ARG;
    }

    /* Allocate new buffer to hold ciphertext */
    if (ret == 0) {
        out = (byte*)XMALLOC(inLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (out == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(out, 0, inLen);
        }
    }

    if (ret == 0) {
        ret = wc_AesGcmEncrypt(aes, out, in, inLen, iv, ivSz,
            authTag, authTagSz, authIn, authInSz);
    }

    /* Create new jbyteArray to return output */
    if (ret == 0) {
        outArr = (*env)->NewByteArray(env, inLen);
        if (outArr == NULL) {
            ret = MEMORY_E; 
        }
        else {
            (*env)->SetByteArrayRegion(env, outArr, 0, inLen, (jbyte*)out);
            if ((*env)->ExceptionOccurred(env)) {
                (*env)->ExceptionDescribe(env);
                (*env)->ExceptionClear(env);
                (*env)->DeleteLocalRef(env, outArr);
                outArr = NULL;
                ret = -1;
            }
        }
    }

    /* Commit authTag changes back to original Java array on success */
    if (authTagArr != NULL) {
        if (ret == 0) {
            (*env)->ReleaseByteArrayElements(env, authTagArr,
                (jbyte*)authTag, JNI_COMMIT);
        }
        else {
            (*env)->ReleaseByteArrayElements(env, authTagArr,
                (jbyte*)authTag, JNI_ABORT);
        }
    }

    /* Release all other byte arrays without changing original arrays */
    if (inputArr != NULL) {
        (*env)->ReleaseByteArrayElements(env, inputArr, (jbyte*)in,
            JNI_ABORT);
    }
    if (ivArr != NULL) {
        (*env)->ReleaseByteArrayElements(env, ivArr, (jbyte*)iv,
            JNI_ABORT);
    }
    if (authInArr != NULL) {
        (*env)->ReleaseByteArrayElements(env, authInArr, (jbyte*)authIn,
            JNI_ABORT);
    }

    if (out != NULL) {
        XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    LogStr("wc_AesGcmEncrypt(aes = %p, inLen = %d, ivSz = %d, "
            "authTagSz = %d, authInSz = %d)\n", aes, inLen, ivSz,
            authTagSz, authInSz);

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
        return NULL;
    }

    return outArr;

#else
    (void)this;
    (void)input;
    (void)iv;
    (void)authTag;
    (void)authIn;
    throwNotCompiledInException(env);
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_AesGcm_wc_1AesGcmDecrypt
  (JNIEnv* env, jobject this, jbyteArray inputArr, jbyteArray ivArr, jbyteArray authTagArr, jbyteArray authInArr)
{
#if !defined(NO_AES) && defined(HAVE_AESGCM)
    int ret = 0;
    Aes* aes = NULL;
    const byte* in = NULL;
    const byte* iv = NULL;
    const byte* authTag = NULL;
    const byte* authIn = NULL;
    word32 inLen = 0;
    word32 ivSz = 0;
    word32 authTagSz = 0;
    word32 authInSz = 0;

    byte* out = NULL;
    jbyteArray outArr = NULL;

    aes = (Aes*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, if so stop and return */
        return NULL;
    }

    if (inputArr != NULL) {
        in = (byte*)(*env)->GetByteArrayElements(env, inputArr, NULL);
        inLen = (*env)->GetArrayLength(env, inputArr);
    }
    if (ivArr != NULL) {
        iv = (byte*)(*env)->GetByteArrayElements(env, ivArr, NULL);
        ivSz = (*env)->GetArrayLength(env, ivArr);
    }
    if (authTagArr != NULL) {
        authTag = (byte*)(*env)->GetByteArrayElements(env, authTagArr, NULL);
        authTagSz = (*env)->GetArrayLength(env, authTagArr);
    }
    if (authInArr != NULL) {
        authIn = (byte*)(*env)->GetByteArrayElements(env, authInArr, NULL);
        authInSz = (*env)->GetArrayLength(env, authInArr);
    }

    if (in == NULL || inLen == 0 || iv == NULL || ivSz == 0 ||
        authTag == NULL || authTagSz == 0) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        out = (byte*)XMALLOC(inLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (out == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(out, 0, inLen);
        }
    }

    if (ret == 0) {
        ret = wc_AesGcmDecrypt(aes, out, in, inLen, iv, ivSz,
            authTag, authTagSz, authIn, authInSz);
    }

    /* Create new jbyteArray to return output */
    if (ret == 0) {
        outArr = (*env)->NewByteArray(env, inLen);
        if (outArr == NULL) {
            ret = MEMORY_E; 
        }
        else {
            (*env)->SetByteArrayRegion(env, outArr, 0, inLen, (jbyte*)out);
            if ((*env)->ExceptionOccurred(env)) {
                (*env)->ExceptionDescribe(env);
                (*env)->ExceptionClear(env);
                (*env)->DeleteLocalRef(env, outArr);
                outArr = NULL;
                ret = -1;
            }
        }
    }

    /* Release all byte arrays without changing original arrays */
    if (inputArr != NULL) {
        (*env)->ReleaseByteArrayElements(env, inputArr, (jbyte*)in,
            JNI_ABORT);
    }
    if (ivArr != NULL) {
        (*env)->ReleaseByteArrayElements(env, ivArr, (jbyte*)iv,
            JNI_ABORT);
    }
    if (authInArr != NULL) {
        (*env)->ReleaseByteArrayElements(env, authInArr, (jbyte*)authIn,
            JNI_ABORT);
    }
    if (authTagArr != NULL) {
        (*env)->ReleaseByteArrayElements(env, authTagArr, (jbyte*)authTag,
            JNI_ABORT);
    }

    if (out != NULL) {
        XMEMSET(out, 0, inLen);
        XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    LogStr("wc_AesGcmDecrypt(aes = %p, inLen = %d, ivSz = %d, "
            "authTagSz = %d, authInSz = %d)\n", aes, inLen, ivSz,
            authTagSz, authInSz);

    if (ret != 0) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    return outArr;

#else
    (void)this;
    (void)input;
    (void)iv;
    (void)authTag;
    (void)authIn;
    throwNotCompiledInException(env);
    return NULL;
#endif
}

