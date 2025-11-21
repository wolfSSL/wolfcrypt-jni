/* jni_wolfssl_cert_manager.c
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

#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
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

    /* Find verify() method on callback object */
    callbackClass = (*jenv)->GetObjectClass(jenv, ctx->callback);
    if (callbackClass == NULL) {
        if (needsDetach) {
            (*ctx->jvm)->DetachCurrentThread(ctx->jvm);
        }
        return 0;
    }

    verifyMethod = (*jenv)->GetMethodID(jenv, callbackClass,
        "verify", "(III)I");
    if (verifyMethod == NULL) {
        (*jenv)->DeleteLocalRef(jenv, callbackClass);
        if (needsDetach) {
            (*ctx->jvm)->DetachCurrentThread(ctx->jvm);
        }
        return 0;
    }

    /* Call Java callback.verify(preverify, error, errorDepth) */
    result = (*jenv)->CallIntMethod(jenv, ctx->callback, verifyMethod,
        (jint)preverify, (jint)error, (jint)errorDepth);

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

    (*jenv)->DeleteLocalRef(jenv, callbackClass);
    if (needsDetach) {
        (*ctx->jvm)->DetachCurrentThread(ctx->jvm);
    }

    return (int)result;
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

