/* jni_wolfssl_cert_manager.c
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

#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/ocsp.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <com_wolfssl_wolfcrypt_WolfSSLCertManager.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

/* Struct holding Java callback information for verify callback to use for
 * reaching back to Java. Stored in CallbackNode struct, which is is mapped to
 * WOLFSSL_CERT_MANAGER pointer in CallbackNode. */
typedef struct {
    JavaVM* jvm;       /* Java VM pointer for thread attachment */
    jobject callback;  /* Global reference to Java callback object */
} VerifyCallbackCtx;

/* Linked list node struct for callback context storage */
typedef struct CallbackNode {
    WOLFSSL_CERT_MANAGER* cm;     /* Native WOLFSSL_CERT_MANAGER pointer */
    VerifyCallbackCtx* ctx;       /* Java verify callback info */
    struct CallbackNode* next;
} CallbackNode;

/* Global linked list of CallbackNode structs, protected by mutex */
static CallbackNode* g_callbackList = NULL;

/* Mutex for protecting g_callbackList access */
static wolfSSL_Mutex g_callbackMutex;

/* Flag to track if g_callbackMutex has been initialized. */
static int g_mutexInitialized = 0;

/* Initialize the global g_callbackMutex. Called from JNI_OnLoad() to ensure
 * thread-safe init before any CertManager operations.
 *
 * Returns 0 on success, negative on error. */
int wolfSSL_CertManager_init(void)
{
    if (!g_mutexInitialized) {
        if (wc_InitMutex(&g_callbackMutex) != 0) {
            return -1;
        }
        g_mutexInitialized = 1;
    }
    return 0;
}

/* Free the global g_callbackMutex. Called from JNI_OnUnload() when native
 * library is unloaded. */
void wolfSSL_CertManager_cleanup(void)
{
    if (g_mutexInitialized) {
        wc_FreeMutex(&g_callbackMutex);
        g_mutexInitialized = 0;
    }
}

/* Find correct VerifyCallbackCtx in global g_callbackList by comparing
 * WOLFSSL_CERT_MANAGER pointers.
 *
 * Caller must hold g_callbackMutex.
 *
 * Returns NULL if not found, or VerifyCallbackCtx pointer on success. */
static VerifyCallbackCtx* findCallbackCtx(WOLFSSL_CERT_MANAGER* cm)
{
    CallbackNode* node = g_callbackList;

    while (node != NULL) {
        if (node->cm == cm) {
            return node->ctx;
        }
        node = node->next;
    }

    return NULL;
}

/* Add VerifyCallbackCtx to global g_callbackList
 *
 * Caller must hold g_callbackMutex.
 *
 * Returns 0 on success, negative on error. */
static int addCallbackCtx(WOLFSSL_CERT_MANAGER* cm, VerifyCallbackCtx* ctx)
{
    CallbackNode* node = NULL;

    if (cm == NULL || ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Allocate new node */
    node = (CallbackNode*)XMALLOC(sizeof(CallbackNode), NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (node == NULL) {
        return MEMORY_E;
    }

    /* Store WOLFSSL_CERT_MANAGER and context */
    node->cm = cm;
    node->ctx = ctx;

    /* Add to front of global callback list */
    node->next = g_callbackList;
    g_callbackList = node;

    return 0;
}

/* Remove CallbackNode from global g_callbackList.
 *
 * Caller must hold g_callbackMutex. */
static void removeCallbackCtx(WOLFSSL_CERT_MANAGER* cm)
{
    CallbackNode* node = g_callbackList;
    CallbackNode* prev = NULL;

    if (cm == NULL) {
        return;
    }

    while (node != NULL) {
        if (node->cm == cm) {
            /* Found matching node, remove from list */
            if (prev == NULL) {
                g_callbackList = node->next;
            }
            else {
                prev->next = node->next;
            }

            /* Free node (ctx is freed separately) */
            XFREE(node, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return;
        }

        prev = node;
        node = node->next;
    }
}

/* Extract cert DER bytes at given depth from WOLFSSL_X509_STORE_CTX into
 * a new jbyteArray. Returns NULL if cert not available at depth. */
static jbyteArray getCertDerAtDepth(JNIEnv* jenv,
    WOLFSSL_X509_STORE_CTX* store, int depth)
{
    jbyteArray der = NULL;
    WOLFSSL_BUFFER_INFO* certInfo = NULL;

    if (store->certs == NULL || depth < 0 || depth >= store->totalCerts) {
        return NULL;
    }

    certInfo = &store->certs[depth];
    if (certInfo->buffer == NULL || certInfo->length == 0) {
        return NULL;
    }

    der = (*jenv)->NewByteArray(jenv, (jsize)certInfo->length);
    if (der != NULL) {
        (*jenv)->SetByteArrayRegion(jenv, der, 0, (jsize)certInfo->length,
            (const jbyte*)certInfo->buffer);
    }

    return der;
}

/* Native verify callback that calls into Java verify callback.
 *
 * This is registered with wolfSSL_CertManagerSetVerify() and called
 * during certificate verification.
 *
 * Return of 0 causes verification to fail, otherwise non-zero error
 * indicates verification should continue. */
static int nativeVerifyCallback(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    int needsDetach = 0;
    int error = 0;
    int errorDepth = 0;
    jint result = 0;
    JNIEnv* jenv = NULL;
    VerifyCallbackCtx* ctx = NULL;
    jbyteArray certDer     = NULL;
    jclass callbackClass   = NULL;
    jmethodID verifyMethod = NULL;

    if (store == NULL) {
        return 0;
    }

    if (wc_LockMutex(&g_callbackMutex) != 0) {
        return 0;
    }

    /* Try to find callback by WOLFSSL_CERT_MANAGER if cm available in store */
    if (store->store != NULL && store->store->cm != NULL) {
        ctx = findCallbackCtx(store->store->cm);
    }
    else if (g_callbackList != NULL) {
        /* When using CertManagerVerifyBuffer, we can't look up by cm pointer.
         * Use the first callback in the list as a fallback. This works for
         * single-threaded verification or when only one CertManager in use. */
        ctx = g_callbackList->ctx;
    }

    wc_UnLockMutex(&g_callbackMutex);

    /* No callback registered, use preverify result */
    if (ctx == NULL || ctx->callback == NULL) {
        return preverify;
    }

    /* Get JNIEnv for current thread. Native callback may be called from
     * different thread than original Java thread. */
    if ((*ctx->jvm)->GetEnv(ctx->jvm, (void**)&jenv,
        JNI_VERSION_1_6) == JNI_EDETACHED) {
#ifdef __ANDROID__
        result = (*ctx->jvm)->AttachCurrentThread(
            ctx->jvm, &jenv, NULL);
#else
        result = (*ctx->jvm)->AttachCurrentThread(
            ctx->jvm, (void**)&jenv, NULL);
#endif
        if (result != 0) {
            /* Failed to attach, reject */
            return 0;
        }
        needsDetach = 1;
    }

    /* Get error code and depth from store */
    error = store->error;
    errorDepth = store->error_depth;

    /* If available, extract cert DER bytes from store context at errorDepth */
    certDer = getCertDerAtDepth(jenv, store, errorDepth);

    /* Find verify() method on callback object */
    callbackClass = (*jenv)->GetObjectClass(jenv, ctx->callback);
    if (callbackClass == NULL) {
        if (certDer != NULL) {
            (*jenv)->DeleteLocalRef(jenv, certDer);
        }
        if (needsDetach) {
            (*ctx->jvm)->DetachCurrentThread(ctx->jvm);
        }
        return 0;
    }

    verifyMethod = (*jenv)->GetMethodID(jenv, callbackClass,
        "verify", "(III[B)I");
    if (verifyMethod == NULL) {
        if (certDer != NULL) {
            (*jenv)->DeleteLocalRef(jenv, certDer);
        }
        (*jenv)->DeleteLocalRef(jenv, callbackClass);
        if (needsDetach) {
            (*ctx->jvm)->DetachCurrentThread(ctx->jvm);
        }
        return 0;
    }

    /* Call Java callback.verify(preverify, error, errorDepth, certDer) */
    result = (*jenv)->CallIntMethod(jenv, ctx->callback, verifyMethod,
        (jint)preverify, (jint)error, (jint)errorDepth, certDer);

    /* Check for Java exceptions, reject on exception */
    if ((*jenv)->ExceptionCheck(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        result = 0;
    }

    /* If callback accepts the certificate (returns 1), clear the error.
     * This is necessary because wolfSSL checks the error code after
     * calling the callback. If we override an error, we must clear it. */
    if (result == 1 && store->error != 0) {
        store->error = 0;
    }

    if (certDer != NULL) {
        (*jenv)->DeleteLocalRef(jenv, certDer);
    }
    (*jenv)->DeleteLocalRef(jenv, callbackClass);
    if (needsDetach) {
        (*ctx->jvm)->DetachCurrentThread(ctx->jvm);
    }

    return (int)result;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_getWOLFSSL_1LOAD_1FLAG_1DATE_1ERR_1OKAY
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;

    return WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY;
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerNew
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;

    /* Mutex should be initialized in JNI_OnLoad(). If not initialized,
     * try again here as fallback. */
    if (!g_mutexInitialized) {
        if (wolfSSL_CertManager_init() != 0) {
            return 0;
        }
    }

    return (jlong)(uintptr_t)wolfSSL_CertManagerNew();
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerFree
  (JNIEnv* env, jclass jcl, jlong cmPtr)
{
    (void)env;
    (void)jcl;

    wolfSSL_CertManagerFree((WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerLoadCA
  (JNIEnv* env, jclass jcl, jlong cmPtr, jstring f, jstring d)
{
#ifndef NO_FILESYSTEM
    int ret;
    const char* certFile = NULL;
    const char* certPath = NULL;
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;

    if (env == NULL || cm == NULL) {
        return (jint)BAD_FUNC_ARG;
    }

    certFile = (*env)->GetStringUTFChars(env, f, 0);
    certPath = (*env)->GetStringUTFChars(env, d, 0);

    ret = wolfSSL_CertManagerLoadCA(cm, certFile, certPath);

    (*env)->ReleaseStringUTFChars(env, f, certFile);
    (*env)->ReleaseStringUTFChars(env, d, certPath);

    return (jint)ret;
#else
    (void)env;
    (void)jcl;
    (void)cmPtr;
    (void)f;
    (void)d;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerLoadCABuffer
  (JNIEnv* env, jclass jcl, jlong cmPtr, jbyteArray in, jlong sz, jint format)
{
    int ret = 0;
    word32 buffSz = 0;
    byte* buff = NULL;
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;

    if (env == NULL || in == NULL || (sz < 0)) {
        return BAD_FUNC_ARG;
    }

    buff = (byte*)(*env)->GetByteArrayElements(env, in, NULL);
    buffSz = (*env)->GetArrayLength(env, in);

    ret = wolfSSL_CertManagerLoadCABuffer(cm, buff, buffSz, format);

    (*env)->ReleaseByteArrayElements(env, in, (jbyte*)buff, JNI_ABORT);

    return (jint)ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerLoadCABufferEx
  (JNIEnv* env, jclass jcl, jlong cmPtr, jbyteArray in, jlong sz, jint format, jint flags)
{
    int ret = 0;
    word32 buffSz = 0;
    byte* buff = NULL;
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;
    (void)sz;

    if (env == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    buff = (byte*)(*env)->GetByteArrayElements(env, in, NULL);
    buffSz = (*env)->GetArrayLength(env, in);

    ret = wolfSSL_CertManagerLoadCABuffer_ex(cm, buff, buffSz, format, 0,
        (word32)flags);

    (*env)->ReleaseByteArrayElements(env, in, (jbyte*)buff, JNI_ABORT);

    return (jint)ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerUnloadCAs
  (JNIEnv* env, jclass jcl, jlong cmPtr)
{
    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;

    if (env == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wolfSSL_CertManagerUnloadCAs(cm);

    return (jint)ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerVerifyBuffer
  (JNIEnv* env, jclass jcl, jlong cmPtr, jbyteArray in, jlong sz, jint format)
{
    int ret = 0;
    word32 buffSz = 0;
    byte* buff = NULL;
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;

    if (env == NULL || in == NULL || (sz < 0)) {
        return BAD_FUNC_ARG;
    }

    buff = (byte*)(*env)->GetByteArrayElements(env, in, NULL);
    buffSz = (*env)->GetArrayLength(env, in);

    ret = wolfSSL_CertManagerVerifyBuffer(cm, buff, buffSz, format);

    (*env)->ReleaseByteArrayElements(env, in, (jbyte*)buff, JNI_ABORT);

    return (jint)ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerEnableCRL
  (JNIEnv* env, jclass jcl, jlong cmPtr, jint options)
{
#ifdef HAVE_CRL
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;

    if (env == NULL || cm == NULL) {
        return BAD_FUNC_ARG;
    }

    return wolfSSL_CertManagerEnableCRL(cm, (int)options);

#else
    (void)env;
    (void)jcl;
    (void)cmPtr;
    (void)options;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerDisableCRL
  (JNIEnv* env, jclass jcl, jlong cmPtr)
{
#ifdef HAVE_CRL
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;

    if (env == NULL || cm == NULL) {
        return BAD_FUNC_ARG;
    }

    return wolfSSL_CertManagerDisableCRL(cm);

#else
    (void)env;
    (void)jcl;
    (void)cmPtr;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerLoadCRLBuffer
  (JNIEnv* env, jclass jcl, jlong cmPtr, jbyteArray in, jlong sz, jint type)
{
#ifdef HAVE_CRL
    int ret = 0;
    word32 buffSz = 0;
    byte* buff = NULL;
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;

    if (env == NULL || in == NULL || (sz < 0)) {
        return BAD_FUNC_ARG;
    }

    buff = (byte*)(*env)->GetByteArrayElements(env, in, NULL);
    buffSz = (*env)->GetArrayLength(env, in);

    ret = wolfSSL_CertManagerLoadCRLBuffer(cm, buff, buffSz, type);

    (*env)->ReleaseByteArrayElements(env, in, (jbyte*)buff, JNI_ABORT);

    return (jint)ret;
#else
    (void)env;
    (void)jcl;
    (void)cmPtr;
    (void)in;
    (void)sz;
    (void)type;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerEnableOCSP
  (JNIEnv* env, jclass jcl, jlong cmPtr, jint options)
{
#ifdef HAVE_OCSP
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;

    if (env == NULL || cm == NULL) {
        return BAD_FUNC_ARG;
    }

    return wolfSSL_CertManagerEnableOCSP(cm, (int)options);

#else
    (void)env;
    (void)jcl;
    (void)cmPtr;
    (void)options;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerDisableOCSP
  (JNIEnv* env, jclass jcl, jlong cmPtr)
{
#ifdef HAVE_OCSP
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;

    if (env == NULL || cm == NULL) {
        return BAD_FUNC_ARG;
    }

    return wolfSSL_CertManagerDisableOCSP(cm);

#else
    (void)env;
    (void)jcl;
    (void)cmPtr;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerSetOCSPOverrideURL
  (JNIEnv* env, jclass jcl, jlong cmPtr, jstring url)
{
#ifdef HAVE_OCSP
    int ret = 0;
    const char* urlStr = NULL;
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;

    if (env == NULL || cm == NULL || url == NULL) {
        return BAD_FUNC_ARG;
    }

    urlStr = (*env)->GetStringUTFChars(env, url, NULL);
    if (urlStr == NULL) {
        return MEMORY_E;
    }

    ret = wolfSSL_CertManagerSetOCSPOverrideURL(cm, urlStr);

    (*env)->ReleaseStringUTFChars(env, url, urlStr);

    return (jint)ret;

#else
    (void)env;
    (void)jcl;
    (void)cmPtr;
    (void)url;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerCheckOCSP
  (JNIEnv* env, jclass jcl, jlong cmPtr, jbyteArray cert, jint sz)
{
#ifdef HAVE_OCSP
    int ret = 0;
    word32 certSz = 0;
    byte* certBuf = NULL;
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;

    if (env == NULL || cm == NULL || cert == NULL || (sz < 0)) {
        return BAD_FUNC_ARG;
    }

    certBuf = (byte*)(*env)->GetByteArrayElements(env, cert, NULL);
    if (certBuf == NULL) {
        return MEMORY_E;
    }
    certSz = (*env)->GetArrayLength(env, cert);

    ret = wolfSSL_CertManagerCheckOCSP(cm, certBuf, certSz);

    (*env)->ReleaseByteArrayElements(env, cert, (jbyte*)certBuf, JNI_ABORT);

    LogStr("wolfSSL_CertManagerCheckOCSP(cm=%p, certSz=%d) = %d\n",
        cm, certSz, ret);

    return (jint)ret;

#else
    (void)env;
    (void)jcl;
    (void)cmPtr;
    (void)cert;
    (void)sz;
    return NOT_COMPILED_IN;
#endif
}

/* Verify OCSP response for a certificate.
 *
 * Returns 0 (WOLFSSL_SUCCESS) on valid OCSP response, negative on error:
 *   BAD_FUNC_ARG (-173)  - Invalid arguments (NULL pointers, negative sizes)
 *   MEMORY_E (-125)      - Memory allocation failure
 *   ASN_PARSE_E (-140)   - Failed to parse OCSP response or certificate
 *   OCSP_LOOKUP_FAIL     - OCSP response status not successful
 *   OCSP_CERT_REVOKED    - Certificate has been revoked
 *   OCSP_CERT_UNKNOWN    - Certificate status unknown
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerCheckOCSPResponse
  (JNIEnv* env, jclass jcl, jlong cmPtr, jbyteArray response,
   jint responseSz, jbyteArray cert, jint certSz)
{
#ifdef HAVE_OCSP
    int ret = 0;
    word32 respBufSz = 0;
    word32 certBufSz = 0;
    byte* respBuf = NULL;
    byte* certBuf = NULL;
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    OcspEntry* entry = NULL;
    CertStatus* status = NULL;
    OcspRequest* request = NULL;
    DecodedCert* cert_decoded = NULL;
    (void)jcl;
    (void)responseSz;

    if (env == NULL || cm == NULL || response == NULL || cert == NULL ||
        (responseSz < 0) || (certSz < 0)) {
        return BAD_FUNC_ARG;
    }

    /* Get response buffer and size */
    respBuf = (byte*)(*env)->GetByteArrayElements(env, response, NULL);
    if (respBuf == NULL) {
        return MEMORY_E;
    }
    respBufSz = (*env)->GetArrayLength(env, response);

    /* Get cert buffer and size */
    certBuf = (byte*)(*env)->GetByteArrayElements(env, cert, NULL);
    if (certBuf == NULL) {
        (*env)->ReleaseByteArrayElements(env, response,
            (jbyte*)respBuf, JNI_ABORT);
        return MEMORY_E;
    }
    certBufSz = (*env)->GetArrayLength(env, cert);

    /* Allocate request and decoded cert structures */
    request = wolfSSL_OCSP_REQUEST_new();
    if (request != NULL) {
        cert_decoded = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (request != NULL && cert_decoded != NULL) {
        /* Decode the certificate to extract OCSP request info */
        InitDecodedCert(cert_decoded, certBuf, certBufSz, NULL);
        ret = ParseCert(cert_decoded, CERT_TYPE, NO_VERIFY, NULL);
        if (ret == 0) {
            /* Populate OcspRequest from decoded certificate.
             * Need serial number, issuer hash, and issuer key hash. */
            if (cert_decoded->serialSz > 0) {
                request->serialSz = cert_decoded->serialSz;
                request->serial = (byte*)XMALLOC(cert_decoded->serialSz,
                    NULL, DYNAMIC_TYPE_OCSP_REQUEST);
                if (request->serial != NULL) {
                    XMEMCPY(request->serial, cert_decoded->serial,
                        cert_decoded->serialSz);
                    XMEMCPY(request->issuerHash, cert_decoded->issuerHash,
                        KEYID_SIZE);
                    XMEMCPY(request->issuerKeyHash,
                        cert_decoded->issuerKeyHash, KEYID_SIZE);

                    /* CertManager operations are internally thread-safe
                     * wolfSSL uses mutex locking on the OCSP cache. */
                    ret = wolfSSL_CertManagerCheckOCSPResponse(cm, respBuf,
                        respBufSz, NULL, status, entry, request);
                }
                else {
                    ret = MEMORY_E;
                }
            }
            else {
                ret = ASN_PARSE_E;
            }
        }
        FreeDecodedCert(cert_decoded);
    }
    else {
        ret = MEMORY_E;
    }

    /* Release JNI byte array elements */
    (*env)->ReleaseByteArrayElements(env, response,
        (jbyte*)respBuf, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, cert,
        (jbyte*)certBuf, JNI_ABORT);

    /* Free allocated native structures */
    if (request != NULL) {
        wolfSSL_OCSP_REQUEST_free(request);
    }
    if (cert_decoded != NULL) {
        XFREE(cert_decoded, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return (jint)ret;

#else
    (void)env;
    (void)jcl;
    (void)cmPtr;
    (void)response;
    (void)responseSz;
    (void)cert;
    (void)certSz;
    return NOT_COMPILED_IN;
#endif
}

/* Get OCSPResponseStatus from raw OCSP response bytes.
 *
 * Uses wolfSSL_d2i_OCSP_RESPONSE() to parse response and
 * wolfSSL_OCSP_response_status() to extract the status.
 *
 * RFC 6960:
 *   OCSPResponse ::= SEQUENCE {
 *       responseStatus OCSPResponseStatus,
 *       responseBytes  [0] EXPLICIT ResponseBytes OPTIONAL }
 *   OCSPResponseStatus ::= ENUMERATED {
 *       successful (0), malformedRequest (1), internalError (2),
 *       tryLater (3), sigRequired (5), unauthorized (6) }
 *
 * Returns OCSPResponseStatus ENUMERATED value (0-6) on success, or negative
 * error code on failure (BAD_FUNC_ARG, MEMORY_E, NOT_COMPILED_IN, or -1 on
 * parse failure).
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_OcspResponseStatus
  (JNIEnv* env, jclass jcl, jbyteArray response, jint responseSz)
{
#if defined(HAVE_OCSP) && defined(OPENSSL_EXTRA)
    int ret = -1;
    jint arrLen = 0;
    byte* respBuf = NULL;
    const unsigned char* p = NULL;
    OcspResponse* ocspResp = NULL;
    (void)jcl;
    (void)responseSz;

    if (env == NULL || response == NULL) {
        return BAD_FUNC_ARG;
    }

    arrLen = (*env)->GetArrayLength(env, response);
    if (arrLen <= 0) {
        return BAD_FUNC_ARG;
    }

    respBuf = (byte*)(*env)->GetByteArrayElements(env, response, NULL);
    if (respBuf == NULL) {
        return MEMORY_E;
    }

    p = (const unsigned char*)respBuf;
    ocspResp = wolfSSL_d2i_OCSP_RESPONSE(NULL, &p, (int)arrLen);
    if (ocspResp != NULL) {
        ret = wolfSSL_OCSP_response_status(ocspResp);
        wolfSSL_OCSP_RESPONSE_free(ocspResp);
    }

    (*env)->ReleaseByteArrayElements(env, response, (jbyte*)respBuf, JNI_ABORT);

    return (jint)ret;

#else
    (void)env;
    (void)jcl;
    (void)response;
    (void)responseSz;
    return NOT_COMPILED_IN;
#endif /* HAVE_OCSP && OPENSSL_EXTRA */
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerSetVerify
  (JNIEnv* env, jclass jcl, jlong cmPtr, jobject callback)
{
#ifndef NO_WOLFSSL_CM_VERIFY
    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    VerifyCallbackCtx* ctx = NULL;
    JavaVM* jvm = NULL;
    (void)jcl;

    if (env == NULL || cm == NULL || callback == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Get JavaVM pointer for thread attachment in callback */
    if ((*env)->GetJavaVM(env, &jvm) != 0) {
        return BAD_FUNC_ARG;
    }

    /* Allocate context structure to store callback info */
    ctx = (VerifyCallbackCtx*)XMALLOC(sizeof(VerifyCallbackCtx), NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx == NULL) {
        return MEMORY_E;
    }

    /* Create global reference to callback object so it persists across
     * JNI calls and thread boundaries */
    ctx->callback = (*env)->NewGlobalRef(env, callback);
    if (ctx->callback == NULL) {
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
    ctx->jvm = jvm;

    /* Add context to global list */
    if (wc_LockMutex(&g_callbackMutex) != 0) {
        (*env)->DeleteGlobalRef(env, ctx->callback);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return BAD_MUTEX_E;
    }

    ret = addCallbackCtx(cm, ctx);

    wc_UnLockMutex(&g_callbackMutex);

    if (ret != 0) {
        (*env)->DeleteGlobalRef(env, ctx->callback);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    /* Register native callback with wolfSSL */
    wolfSSL_CertManagerSetVerify(cm, nativeVerifyCallback);

    return WOLFSSL_SUCCESS;
#else
    (void)env;
    (void)jcl;
    (void)cmPtr;
    (void)callback;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL
Java_com_wolfssl_wolfcrypt_WolfSSLCertManager_CertManagerClearVerify
  (JNIEnv* env, jclass jcl, jlong cmPtr)
{
#ifndef NO_WOLFSSL_CM_VERIFY
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    VerifyCallbackCtx* ctx = NULL;
    (void)jcl;

    if (env == NULL || cm == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Clear callback in wolfSSL first */
    wolfSSL_CertManagerSetVerify(cm, NULL);

    /* Lock mutex and find/remove callback context */
    if (wc_LockMutex(&g_callbackMutex) != 0) {
        return BAD_MUTEX_E;
    }

    ctx = findCallbackCtx(cm);
    if (ctx != NULL) {
        /* Remove from global list */
        removeCallbackCtx(cm);
    }

    wc_UnLockMutex(&g_callbackMutex);

    /* Free context if it existed */
    if (ctx != NULL) {
        /* Delete global reference to callback object */
        if (ctx->callback != NULL) {
            (*env)->DeleteGlobalRef(env, ctx->callback);
        }

        /* Free context structure */
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return WOLFSSL_SUCCESS;
#else
    (void)env;
    (void)jcl;
    (void)cmPtr;
    return NOT_COMPILED_IN;
#endif
}

