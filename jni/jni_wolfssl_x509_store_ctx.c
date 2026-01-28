/* jni_wolfssl_x509_store_ctx.c
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
#include <limits.h>
#include <stdio.h>

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#elif !defined(__ANDROID__)
    #include <wolfssl/options.h>
#endif

#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <com_wolfssl_wolfcrypt_WolfSSLX509StoreCtx.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

/* Check if CertPathBuilder feature is available.
 * CertPathBuilder requires wolfSSL >= 5.8.0 for proper X509_STORE chain
 * building support. Older versions have issues with reference counting
 * and chain building. */
static int isCertPathBuilderAvailable(void)
{
#if defined(OPENSSL_EXTRA) && \
    (LIBWOLFSSL_VERSION_HEX >= 0x05008000)
    return 1;
#else
    return 0;
#endif
}

/* Native method to check if CertPathBuilder is supported */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLX509StoreCtx_isCertPathBuilderSupported
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;

    if (isCertPathBuilderAvailable()) {
        return 1;
    }

    return 0;
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLX509StoreCtx_wolfSSL_1X509_1STORE_1new
  (JNIEnv* env, jclass jcl)
{
    WOLFSSL_X509_STORE* store = NULL;

    (void)env;
    (void)jcl;

    if (!isCertPathBuilderAvailable()) {
        LogStr("CertPathBuilder requires wolfSSL >= 5.8.0\n");
        return 0;
    }

#ifdef OPENSSL_EXTRA
    store = wolfSSL_X509_STORE_new();
    if (store == NULL) {
        LogStr("wolfSSL_X509_STORE_new() failed\n");
    }
#endif

    return (jlong)(uintptr_t)store;
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLX509StoreCtx_wolfSSL_1X509_1STORE_1free
  (JNIEnv* env, jclass jcl, jlong storePtr)
{
    WOLFSSL_X509_STORE* store = (WOLFSSL_X509_STORE*)(uintptr_t)storePtr;

    (void)env;
    (void)jcl;

#ifdef OPENSSL_EXTRA
    if (store != NULL) {
        wolfSSL_X509_STORE_free(store);
    }
#else
    (void)store;
#endif
}

/* Add DER-encoded certificate to X509_STORE. Self-signed certs go to trusted
 * CAs, others go to intermediates. */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLX509StoreCtx_wolfSSL_1X509_1STORE_1add_1cert
  (JNIEnv* env, jclass jcl, jlong storePtr, jbyteArray certDer)
{
    int ret = 0;
#ifdef OPENSSL_EXTRA
    WOLFSSL_X509_STORE* store = (WOLFSSL_X509_STORE*)(uintptr_t)storePtr;
    WOLFSSL_X509* x509 = NULL;
    jbyte* certBuf = NULL;
    jsize certLen = 0;
    const unsigned char* p = NULL;

    (void)jcl;

    if (store == NULL) {
        return BAD_FUNC_ARG;
    }

    if (certDer == NULL) {
        return BAD_FUNC_ARG;
    }

    certLen = (*env)->GetArrayLength(env, certDer);
    if (certLen <= 0) {
        return BAD_FUNC_ARG;
    }

    certBuf = (*env)->GetByteArrayElements(env, certDer, NULL);
    if (certBuf == NULL) {
        return MEMORY_E;
    }

    /* Convert DER to X509 */
    p = (const unsigned char*)certBuf;
    x509 = wolfSSL_d2i_X509(NULL, &p, (long)certLen);

    (*env)->ReleaseByteArrayElements(env, certDer, certBuf, JNI_ABORT);

    if (x509 == NULL) {
        LogStr("wolfSSL_d2i_X509() failed\n");
        return ASN_PARSE_E;
    }

    /* Add to store - wolfSSL_X509_STORE_add_cert handles routing:
     * - Self-signed -> trusted CAs (cm + store->trusted)
     * - Non-self-signed -> intermediates (store->certs)
     *
     * wolfSSL_X509_STORE_add_cert() calls wolfSSL_X509_up_ref() internally,
     * so the store holds its own reference. We must free our reference. */
    ret = wolfSSL_X509_STORE_add_cert(store, x509);
    if (ret != WOLFSSL_SUCCESS) {
        LogStr("wolfSSL_X509_STORE_add_cert() failed: %d\n", ret);
        wolfSSL_X509_free(x509);
        return ret;
    }
    ret = 0;

    /* Free our reference, store has its own via up_ref */
    wolfSSL_X509_free(x509);

#else
    (void)env;
    (void)jcl;
    (void)storePtr;
    (void)certDer;
    ret = NOT_COMPILED_IN;
#endif

    return ret;
}

/* Helper to throw WolfCryptException with verification error details */
static void throwVerifyException(JNIEnv* env, const char* prefix,
    int errorCode)
{
    char msgBuf[256];
    const char* errStr = NULL;

#ifdef OPENSSL_EXTRA
    errStr = wolfSSL_X509_verify_cert_error_string((long)errorCode);
#endif
    if (errStr == NULL) {
        errStr = "Unknown error";
    }

    snprintf(msgBuf, sizeof(msgBuf), "%s: %s (error %d)", prefix, errStr,
        errorCode);

    throwWolfCryptException(env, msgBuf);
}

JNIEXPORT jobjectArray JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLX509StoreCtx_wolfSSL_1X509_1verify_1cert_1and_1get_1chain
  (JNIEnv* env, jclass jcl, jlong storePtr, jbyteArray targetCertDer,
   jobjectArray intermediateCertsDer, jint maxPathLength)
{
    jobjectArray result = NULL;
#ifdef OPENSSL_EXTRA
    WOLFSSL_X509_STORE* store = (WOLFSSL_X509_STORE*)(uintptr_t)storePtr;
    WOLFSSL_X509_STORE_CTX* ctx = NULL;
    WOLFSSL_X509* targetX509 = NULL;
    WOLF_STACK_OF(WOLFSSL_X509)* intermediates = NULL;
    WOLF_STACK_OF(WOLFSSL_X509)* chain = NULL;
    jbyte* certBuf = NULL;
    jsize certLen = 0;
    const unsigned char* p = NULL;
    int ret = 0;
    int i = 0;
    int chainLen = 0;
    jclass byteArrayClass = NULL;

    (void)jcl;

    if (store == NULL || targetCertDer == NULL) {
        throwWolfCryptException(env, "Invalid store or target certificate");
        return NULL;
    }

    /* Convert target cert DER to WOLFSSL_X509 */
    certLen = (*env)->GetArrayLength(env, targetCertDer);
    if (certLen <= 0) {
        throwWolfCryptException(env, "Invalid target certificate length");
        return NULL;
    }

    certBuf = (*env)->GetByteArrayElements(env, targetCertDer, NULL);
    if (certBuf == NULL) {
        throwWolfCryptException(env, "Memory allocation failed");
        return NULL;
    }

    p = (const unsigned char*)certBuf;
    targetX509 = wolfSSL_d2i_X509(NULL, &p, (long)certLen);
    (*env)->ReleaseByteArrayElements(env, targetCertDer, certBuf, JNI_ABORT);

    if (targetX509 == NULL) {
        LogStr("Failed to parse target certificate\n");
        throwWolfCryptException(env, "Failed to parse target certificate");
        return NULL;
    }

    /* Create intermediate cert stack if provided */
    if (intermediateCertsDer != NULL) {
        jsize numCerts = (*env)->GetArrayLength(env, intermediateCertsDer);

        if (numCerts > 0) {
            intermediates = wolfSSL_sk_X509_new_null();
            if (intermediates == NULL) {
                wolfSSL_X509_free(targetX509);
                throwWolfCryptException(env,
                    "wolfSSL_sk_X509_new_null() failed");
                return NULL;
            }

            for (i = 0; i < numCerts; i++) {
                WOLFSSL_X509* interX509 = NULL;
                jbyteArray certDer = NULL;

                certDer = (jbyteArray)(*env)->GetObjectArrayElement(
                    env, intermediateCertsDer, i);
                if (certDer == NULL) {
                    continue;
                }

                certLen = (*env)->GetArrayLength(env, certDer);
                if (certLen <= 0) {
                    (*env)->DeleteLocalRef(env, certDer);
                    continue;
                }

                certBuf = (*env)->GetByteArrayElements(env, certDer, NULL);
                if (certBuf == NULL) {
                    (*env)->DeleteLocalRef(env, certDer);
                    continue;
                }

                p = (const unsigned char*)certBuf;
                interX509 = wolfSSL_d2i_X509(NULL, &p, (long)certLen);
                (*env)->ReleaseByteArrayElements(env, certDer, certBuf,
                    JNI_ABORT);
                (*env)->DeleteLocalRef(env, certDer);

                if (interX509 != NULL) {
                    if (wolfSSL_sk_X509_push(intermediates, interX509) <= 0) {
                        /* If push fails, free WOLFSSL_X509 */
                        wolfSSL_X509_free(interX509);
                    }
                }
            }
        }
    }

    /* Create and init WOLFSSL_X509_STORE_CTX */
    ctx = wolfSSL_X509_STORE_CTX_new();
    if (ctx == NULL) {
        wolfSSL_X509_free(targetX509);
        if (intermediates != NULL) {
            wolfSSL_sk_X509_pop_free(intermediates, wolfSSL_X509_free);
        }
        throwWolfCryptException(env, "Failed to create X509_STORE_CTX");
        return NULL;
    }

    ret = wolfSSL_X509_STORE_CTX_init(ctx, store, targetX509, intermediates);
    if (ret != WOLFSSL_SUCCESS) {
        LogStr("wolfSSL_X509_STORE_CTX_init() failed: %d\n", ret);
        wolfSSL_X509_STORE_CTX_free(ctx);
        wolfSSL_X509_free(targetX509);
        if (intermediates != NULL) {
            wolfSSL_sk_X509_pop_free(intermediates, wolfSSL_X509_free);
        }
        throwWolfCryptException(env, "Failed to initialize X509_STORE_CTX");
        return NULL;
    }

    /* Set max path length if specified.
     * Depth = max intermediates + 1 for root CA.
     * Check for overflow when adding 1 to maxPathLength. */
    if (maxPathLength >= 0 && maxPathLength < (INT_MAX - 1)) {
        wolfSSL_X509_STORE_CTX_set_depth(ctx, maxPathLength + 1);
    }

    /* Verify certificate chain */
    ret = wolfSSL_X509_verify_cert(ctx);
    if (ret != WOLFSSL_SUCCESS) {
        int verifyError = wolfSSL_X509_STORE_CTX_get_error(ctx);
        LogStr("wolfSSL_X509_verify_cert() failed, error: %d\n", verifyError);
        wolfSSL_X509_STORE_CTX_free(ctx);
        wolfSSL_X509_free(targetX509);
        if (intermediates != NULL) {
            wolfSSL_sk_X509_pop_free(intermediates, wolfSSL_X509_free);
        }
        throwVerifyException(env,
            "Certificate chain verification failed", verifyError);
        return NULL;
    }

    /* Get the built chain */
    chain = wolfSSL_X509_STORE_CTX_get_chain(ctx);
    if (chain == NULL) {
        LogStr("wolfSSL_X509_STORE_CTX_get_chain() returned NULL\n");
        wolfSSL_X509_STORE_CTX_free(ctx);
        wolfSSL_X509_free(targetX509);
        if (intermediates != NULL) {
            wolfSSL_sk_X509_pop_free(intermediates, wolfSSL_X509_free);
        }
        throwWolfCryptException(env, "Failed to get certificate chain");
        return NULL;
    }

    chainLen = wolfSSL_sk_X509_num(chain);
    if (chainLen <= 0) {
        LogStr("Empty certificate chain\n");
        wolfSSL_X509_STORE_CTX_free(ctx);
        wolfSSL_X509_free(targetX509);
        if (intermediates != NULL) {
            wolfSSL_sk_X509_pop_free(intermediates, wolfSSL_X509_free);
        }
        throwWolfCryptException(env, "Empty certificate chain");
        return NULL;
    }

    /* Create Java byte[][] array for result */
    byteArrayClass = (*env)->FindClass(env, "[B");
    if (byteArrayClass == NULL) {
        wolfSSL_X509_STORE_CTX_free(ctx);
        wolfSSL_X509_free(targetX509);
        if (intermediates != NULL) {
            wolfSSL_sk_X509_pop_free(intermediates, wolfSSL_X509_free);
        }
        return NULL;
    }

    result = (*env)->NewObjectArray(env, chainLen, byteArrayClass, NULL);
    if (result == NULL) {
        (*env)->DeleteLocalRef(env, byteArrayClass);
        wolfSSL_X509_STORE_CTX_free(ctx);
        wolfSSL_X509_free(targetX509);
        if (intermediates != NULL) {
            wolfSSL_sk_X509_pop_free(intermediates, wolfSSL_X509_free);
        }
        return NULL;
    }

    /* Convert each WOLFSSL_X509 in chain to DER and add to result array.
     * If any conversion fails, fail the entire operation to avoid
     * returning a partial chain with null elements. */
    for (i = 0; i < chainLen; i++) {
        int derLen = 0;
        WOLFSSL_X509* cert = NULL;
        const unsigned char* der = NULL;
        jbyteArray derArray = NULL;

        cert = wolfSSL_sk_X509_value(chain, i);
        if (cert == NULL) {
            LogStr("Chain cert %d is NULL\n", i);
            result = NULL;
            throwWolfCryptException(env, "Certificate in chain is NULL");
            break;
        }

        der = wolfSSL_X509_get_der(cert, &derLen);
        if (der == NULL || derLen <= 0) {
            LogStr("wolfSSL_X509_get_der() failed for cert %d\n", i);
            result = NULL;
            throwWolfCryptException(env,
                "Failed to get DER encoding of certificate");
            break;
        }

        derArray = (*env)->NewByteArray(env, derLen);
        if (derArray == NULL) {
            LogStr("NewByteArray failed for cert %d\n", i);
            result = NULL;
            break;
        }

        (*env)->SetByteArrayRegion(env, derArray, 0, derLen, (const jbyte*)der);
        (*env)->SetObjectArrayElement(env, result, i, derArray);
        (*env)->DeleteLocalRef(env, derArray);
    }

    /* Cleanup */
    (*env)->DeleteLocalRef(env, byteArrayClass);
    wolfSSL_X509_STORE_CTX_free(ctx);
    wolfSSL_X509_free(targetX509);
    if (intermediates != NULL) {
        wolfSSL_sk_X509_pop_free(intermediates, wolfSSL_X509_free);
    }

#else
    (void)jcl;
    (void)storePtr;
    (void)targetCertDer;
    (void)intermediateCertsDer;
    (void)maxPathLength;
    throwWolfCryptException(env, "OPENSSL_EXTRA not defined");
#endif

    return result;
}

