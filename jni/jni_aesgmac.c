/* jni_aesgmac.c
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
#include <wolfssl/wolfcrypt/aes.h>

#include <com_wolfssl_wolfcrypt_AesGmac.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_AesGmac_mallocNativeStruct_1internal(
    JNIEnv* env, jobject this)
{
#ifdef HAVE_AESGCM
    Gmac* gmac = NULL;

    gmac = (Gmac*)XMALLOC(sizeof(Gmac), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (gmac == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate Gmac object");
        return (jlong)0;
    }

    /* Initialize the GMAC structure to a known clean state */
    XMEMSET(gmac, 0, sizeof(Gmac));

    LogStr("new Gmac() = %p\n", gmac);

    return (jlong)(uintptr_t)gmac;
#else
    throwNotCompiledInException(env);
    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesGmac_native_1init(
    JNIEnv* env, jobject this)
{
#ifdef HAVE_AESGCM
    Gmac* gmac = (Gmac*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    /* GMAC struct is already zero-initialized in mallocNativeStruct_internal */
    /* Actual initialization happens in wc_GmacSetKey when we have the key */

    LogStr("native_init(gmac=%p)\n", gmac);
    (void)gmac; /* suppress unused variable warning */
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesGmac_native_1free(
    JNIEnv* env, jobject this)
{
#ifdef HAVE_AESGCM
    Gmac* gmac = (Gmac*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    LogStr("free Gmac %p\n", gmac);

    if (gmac) {
        /* Only clear the GMAC struct - do NOT free the memory here.
         * The base class NativeStruct.xfree() will handle the actual
         * memory deallocation to avoid double-free. */
        XMEMSET(gmac, 0, sizeof(Gmac));
    }
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesGmac_wc_1GmacSetKey(
    JNIEnv* env, jobject this, jbyteArray key_object)
{
#ifdef HAVE_AESGCM
    int ret = 0;
    Gmac* gmac = NULL;
    byte* key  = NULL;
    word32 keySz = 0;

    gmac = (Gmac*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    key   = getByteArray(env, key_object);
    keySz = getByteArrayLength(env, key_object);

    if (!gmac || !key) {
        ret = BAD_FUNC_ARG;
    } else {
        /* Initialize GMAC with the provided key */
        ret = wc_GmacSetKey(gmac, key, keySz);
    }

    if (ret != 0)
        throwWolfCryptExceptionFromError(env, ret);

    LogStr("wc_GmacSetKey(gmac=%p, key, %d) = %d\n", gmac, keySz, ret);

    releaseByteArray(env, key_object, key, JNI_ABORT);
#else
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_AesGmac_wc_1GmacUpdate(
    JNIEnv* env, jobject this, jbyteArray iv_object, jbyteArray authIn_object,
    jint authTagSz)
{
#ifdef HAVE_AESGCM
    int ret = 0;
    jbyteArray result = NULL;
    Gmac* gmac = NULL;
    byte* iv = NULL;
    byte* authIn = NULL;
    word32 ivSz = 0;
    word32 authInSz = 0;
    byte* authTag = NULL;

    gmac = (Gmac*) getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }

    iv = getByteArray(env, iv_object);
    ivSz = getByteArrayLength(env, iv_object);

    authIn = getByteArray(env, authIn_object);
    authInSz = getByteArrayLength(env, authIn_object);

    if (!gmac || !iv || !authIn || authTagSz <= 0) {
        ret = BAD_FUNC_ARG;
    } else {
        /* Allocate buffer for authentication tag */
        authTag = (byte*)XMALLOC(authTagSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (authTag == NULL) {
            ret = MEMORY_E;
        } else {
            ret = wc_GmacUpdate(gmac, iv, ivSz, authIn, authInSz,
                                authTag, authTagSz);
        }
    }

    if (ret == 0) {
        result = (*env)->NewByteArray(env, authTagSz);

        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, authTagSz,
                (const jbyte*) authTag);
        } else {
            throwWolfCryptException(env, "Failed to allocate gmac");
        }
    } else {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_GmacUpdate(gmac=%p, iv, %d, authIn, %d, authTag, %d) = %d\n",
           gmac, ivSz, authInSz, authTagSz, ret);

    if (authTag) {
        XFREE(authTag, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    releaseByteArray(env, iv_object, iv, JNI_ABORT);
    releaseByteArray(env, authIn_object, authIn, JNI_ABORT);

    return result;
#else
    throwNotCompiledInException(env);
    return NULL;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_AesGmac_wc_1Gmac(
    JNIEnv* env, jobject this, jbyteArray key_object, jbyteArray iv_object,
    jbyteArray authIn_object, jbyteArray authTag_object)
{
#ifdef HAVE_AESGCM
    int ret = 0;
    Gmac gmac;
    byte* key = NULL;
    byte* iv = NULL;
    byte* authIn = NULL;
    byte* authTag = NULL;
    word32 keySz, ivSz, authInSz, authTagSz;

    key = getByteArray(env, key_object);
    iv = getByteArray(env, iv_object);
    authIn = getByteArray(env, authIn_object);
    authTag = getByteArray(env, authTag_object);

    if (key == NULL || iv == NULL || authIn == NULL || authTag == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        keySz = getByteArrayLength(env, key_object);
        ivSz = getByteArrayLength(env, iv_object);
        authInSz = getByteArrayLength(env, authIn_object);
        authTagSz = getByteArrayLength(env, authTag_object);

        /* Initialize GMAC structure */
        XMEMSET(&gmac, 0, sizeof(Gmac));

        /* Set the key */
        ret = wc_GmacSetKey(&gmac, key, keySz);

        if (ret == 0) {
            /* Use a local buffer for the auth tag result to avoid
             * corrupting Java memory */
            byte* tmp = (byte*)XMALLOC(authTagSz, NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (tmp == NULL) {
                ret = MEMORY_E;
            } else {
                /* Perform GMAC operation */
                ret = wc_GmacUpdate(&gmac, iv, ivSz, authIn, authInSz,
                                  tmp, authTagSz);

                if (ret == 0) {
                    /* Copy result back to Java byte array */
                    (*env)->SetByteArrayRegion(env, authTag_object, 0,
                        authTagSz, (const jbyte*) tmp);
                }

                XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            }
        }
    }

    LogStr("GMAC operation: key=%p, keySz=%d, iv=%p, ivSz=%d, authIn=%p, "
           "authInSz=%d, authTag=%p, authTagSz=%d, ret=%d\n",
           key, keySz, iv, ivSz, authIn, authInSz, authTag, authTagSz, ret);

    releaseByteArray(env, key_object, key, JNI_ABORT);
    releaseByteArray(env, iv_object, iv, JNI_ABORT);
    releaseByteArray(env, authIn_object, authIn, JNI_ABORT);
    releaseByteArray(env, authTag_object, authTag, JNI_ABORT);

    return ret;
#else
    throwNotCompiledInException(env);
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_AesGmac_wc_1GmacVerify(
    JNIEnv* env, jobject this, jbyteArray key_object, jbyteArray iv_object,
    jbyteArray authIn_object, jbyteArray authTag_object)
{
#ifdef HAVE_AESGCM
    int ret = 0;
    Gmac gmac;
    byte* key = NULL;
    byte* iv = NULL;
    byte* authIn = NULL;
    byte* authTag = NULL;
    word32 keySz, ivSz, authInSz, authTagSz;

    key = getByteArray(env, key_object);
    iv = getByteArray(env, iv_object);
    authIn = getByteArray(env, authIn_object);
    authTag = getByteArray(env, authTag_object);

    if (key == NULL || iv == NULL || authIn == NULL || authTag == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        keySz = getByteArrayLength(env, key_object);
        ivSz = getByteArrayLength(env, iv_object);
        authInSz = getByteArrayLength(env, authIn_object);
        authTagSz = getByteArrayLength(env, authTag_object);

        /* Initialize GMAC structure */
        XMEMSET(&gmac, 0, sizeof(Gmac));

        /* Set the key */
        ret = wc_GmacSetKey(&gmac, key, keySz);

        if (ret == 0) {
            /* Generate the expected tag and compare */
            byte* computedTag = (byte*)XMALLOC(authTagSz, NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (computedTag == NULL) {
                ret = MEMORY_E;
            } else {
                ret = wc_GmacUpdate(&gmac, iv, ivSz, authIn, authInSz,
                                  computedTag, authTagSz);

                if (ret == 0) {
                    /* Compare the computed tag with the provided tag */
                    if (XMEMCMP(computedTag, authTag, authTagSz) != 0) {
                        ret = AES_GCM_AUTH_E; /* Authentication failure */
                    }
                }

                XFREE(computedTag, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            }
        }
    }

    LogStr("GMAC verify: key=%p, keySz=%d, iv=%p, ivSz=%d, authIn=%p, "
           "authInSz=%d, authTag=%p, authTagSz=%d, ret=%d\n",
           key, keySz, iv, ivSz, authIn, authInSz, authTag, authTagSz, ret);

    releaseByteArray(env, key_object, key, JNI_ABORT);
    releaseByteArray(env, iv_object, iv, JNI_ABORT);
    releaseByteArray(env, authIn_object, authIn, JNI_ABORT);
    releaseByteArray(env, authTag_object, authTag, JNI_ABORT);

    return ret;
#else
    throwNotCompiledInException(env);
    return NOT_COMPILED_IN;
#endif
}
