/* jni_ed25519.c
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
#ifdef HAVE_FIPS
    #include <wolfssl/wolfcrypt/fips.h>
#endif
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef HAVE_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
    #include <wolfssl/wolfcrypt/asn.h>
    #include <wolfssl/wolfcrypt/asn_public.h>
#endif
#include <wolfssl/wolfcrypt/memory.h>

#include <com_wolfssl_wolfcrypt_Ed25519.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

#if !defined(WC_NO_RNG) && defined(NO_OLD_RNGNAME)
    #define RNG WC_RNG
#endif

#if (LIBWOLFSSL_VERSION_HEX >= 0x05008004) && !defined(WOLFSSL_NO_FORCE_ZERO)
    #define ED25519_FORCE_ZERO(p, len) wc_ForceZero((p), (len))
#else
    #define ED25519_FORCE_ZERO(p, len) XMEMSET((p), 0, (len))
#endif

/* Maximum EdDSA context length, RFC 8032 (contextLen is a byte) */
#define ED25519_JNI_MAX_CONTEXT_LEN 255

#ifdef HAVE_ED25519

#if defined(HAVE_ED25519_SIGN) || defined(HAVE_ED25519_KEY_EXPORT)

/* Copy native buffer into a new Java byte[]. Returns NULL with an
 * OutOfMemoryError pending when allocation fails. */
static jbyteArray ed25519_jni_new_byte_array(JNIEnv* env, const byte* buf,
    word32 sz)
{
    jbyteArray result = (*env)->NewByteArray(env, (jsize)sz);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)sz,
            (const jbyte*)buf);
        if ((*env)->ExceptionCheck(env)) {
            result = NULL;
        }
    }
    return result;
}

#endif /* SIGN || KEY_EXPORT */

/* Get the ed25519_key behind given jobject. Returns NULL with an exception
 * pending on failure. */
static ed25519_key* ed25519_jni_get_key(JNIEnv* env, jobject this)
{
    ed25519_key* key = (ed25519_key*)getNativeStruct(env, this);

    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return NULL;
    }
    if (key == NULL) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        }
        return NULL;
    }
    return key;
}

#endif /* HAVE_ED25519 */

#if defined(HAVE_ED25519) && \
    (defined(HAVE_ED25519_SIGN) || defined(HAVE_ED25519_VERIFY))

/* Pin an optional context array. Returns 0 on success, BUFFER_E when context
 * is longer than 255 bytes and BAD_FUNC_ARG when the array cannot be pinned.
 * NULL jbyteArray means no context: ctx stays NULL and ctxSz 0. */
static int ed25519_jni_pin_context(JNIEnv* env, jbyteArray ctxObj, byte** ctx,
    word32* ctxSz)
{
    *ctx = NULL;
    *ctxSz = 0;

    if (ctxObj == NULL) {
        return 0;
    }

    *ctxSz = getByteArrayLength(env, ctxObj);
    if (*ctxSz > ED25519_JNI_MAX_CONTEXT_LEN) {
        *ctxSz = 0;
        return BUFFER_E;
    }

    if (*ctxSz > 0) {
        *ctx = getByteArray(env, ctxObj);
        if (*ctx == NULL) {
            *ctxSz = 0;
            return BAD_FUNC_ARG;
        }
    }
    return 0;
}

#endif /* HAVE_ED25519_SIGN || HAVE_ED25519_VERIFY */

#if defined(HAVE_ED25519) && defined(HAVE_ED25519_SIGN)

/* Map native sign function a JNI entry point maps to */
enum {
    ED25519_JNI_SIGN_MSG = 0,       /* wc_ed25519_sign_msg      */
    ED25519_JNI_SIGN_CTX_MSG,       /* wc_ed25519ctx_sign_msg   */
    ED25519_JNI_SIGN_PH_MSG,        /* wc_ed25519ph_sign_msg    */
    ED25519_JNI_SIGN_PH_HASH,       /* wc_ed25519ph_sign_hash   */
    ED25519_JNI_SIGN_MSG_EX         /* wc_ed25519_sign_msg_ex   */
};

static jbyteArray ed25519_jni_sign(JNIEnv* env, jobject this, jbyteArray inObj,
    jbyteArray ctxObj, jint type, int fn)
{
    int ret = 0;
    jbyteArray result = NULL;
    ed25519_key* key = NULL;
    byte* in = NULL;
    byte* ctx = NULL;
    word32 inSz = 0;
    word32 ctxSz = 0;
    byte dummy = 0;
    byte out[ED25519_SIG_SIZE];
    word32 outSz = (word32)sizeof(out);

    key = ed25519_jni_get_key(env, this);
    if (key == NULL) {
        return NULL;
    }

    if (inObj == NULL) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        }
        return NULL;
    }

    inSz = getByteArrayLength(env, inObj);
    if (inSz > 0) {
        in = getByteArray(env, inObj);
        if (in == NULL) {
            ret = BAD_FUNC_ARG;
        }
    }
    else {
        in = &dummy;
    }

    if (ret == 0) {
        ret = ed25519_jni_pin_context(env, ctxObj, &ctx, &ctxSz);
    }

    if (ret == 0) {
        XMEMSET(out, 0, sizeof(out));
        PRIVATE_KEY_UNLOCK();
        switch (fn) {
            case ED25519_JNI_SIGN_MSG:
                ret = wc_ed25519_sign_msg(in, inSz, out, &outSz, key);
                break;
            case ED25519_JNI_SIGN_CTX_MSG:
                ret = wc_ed25519ctx_sign_msg(in, inSz, out, &outSz, key, ctx,
                    (byte)ctxSz);
                break;
            case ED25519_JNI_SIGN_PH_MSG:
                ret = wc_ed25519ph_sign_msg(in, inSz, out, &outSz, key, ctx,
                    (byte)ctxSz);
                break;
            case ED25519_JNI_SIGN_PH_HASH:
                ret = wc_ed25519ph_sign_hash(in, inSz, out, &outSz, key, ctx,
                    (byte)ctxSz);
                break;
            case ED25519_JNI_SIGN_MSG_EX:
                ret = wc_ed25519_sign_msg_ex(in, inSz, out, &outSz, key,
                    (byte)type, ctx, (byte)ctxSz);
                break;
            default:
                ret = BAD_FUNC_ARG;
                break;
        }
        PRIVATE_KEY_LOCK();
    }

    if (ret == 0) {
        result = ed25519_jni_new_byte_array(env, out, outSz);
    }
    else {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, ret);
        }
    }

    LogStr("ed25519_jni_sign(fn=%d, type=%d, inSz=%u, ctxSz=%u) = %d\n",
        fn, (int)type, inSz, ctxSz, ret);

    if (in != &dummy) {
        releaseByteArray(env, inObj, in, JNI_ABORT);
    }
    releaseByteArray(env, ctxObj, ctx, JNI_ABORT);

    return result;
}

#endif /* HAVE_ED25519_SIGN */

#if defined(HAVE_ED25519) && defined(HAVE_ED25519_VERIFY)

/* Map native verify function a JNI entry point maps to */
enum {
    ED25519_JNI_VERIFY_MSG = 0,     /* wc_ed25519_verify_msg     */
    ED25519_JNI_VERIFY_CTX_MSG,     /* wc_ed25519ctx_verify_msg  */
    ED25519_JNI_VERIFY_PH_MSG,      /* wc_ed25519ph_verify_msg   */
    ED25519_JNI_VERIFY_PH_HASH,     /* wc_ed25519ph_verify_hash  */
    ED25519_JNI_VERIFY_MSG_EX       /* wc_ed25519_verify_msg_ex  */
};

static jboolean ed25519_jni_verify(JNIEnv* env, jobject this, jbyteArray sigObj,
    jbyteArray inObj, jbyteArray ctxObj, jint type, int fn)
{
    int ret = 0;
    int called = 0;
    int res = 0;
    jboolean result = JNI_FALSE;
    ed25519_key* key = NULL;
    byte* sig = NULL;
    byte* in = NULL;
    byte* ctx = NULL;
    word32 sigSz = 0;
    word32 inSz = 0;
    word32 ctxSz = 0;
    byte dummy = 0;

    key = ed25519_jni_get_key(env, this);
    if (key == NULL) {
        return JNI_FALSE;
    }

    if (sigObj == NULL || inObj == NULL) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        }
        return JNI_FALSE;
    }

    sigSz = getByteArrayLength(env, sigObj);
    sig = getByteArray(env, sigObj);
    if (sig == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        inSz = getByteArrayLength(env, inObj);
        if (inSz > 0) {
            in = getByteArray(env, inObj);
            if (in == NULL) {
                ret = BAD_FUNC_ARG;
            }
        }
        else {
            in = &dummy;
        }
    }

    if (ret == 0) {
        ret = ed25519_jni_pin_context(env, ctxObj, &ctx, &ctxSz);
    }

    if (ret == 0) {
        called = 1;
        switch (fn) {
            case ED25519_JNI_VERIFY_MSG:
                ret = wc_ed25519_verify_msg(sig, sigSz, in, inSz, &res, key);
                break;
            case ED25519_JNI_VERIFY_CTX_MSG:
                ret = wc_ed25519ctx_verify_msg(sig, sigSz, in, inSz, &res, key,
                    ctx, (byte)ctxSz);
                break;
            case ED25519_JNI_VERIFY_PH_MSG:
                ret = wc_ed25519ph_verify_msg(sig, sigSz, in, inSz, &res, key,
                    ctx, (byte)ctxSz);
                break;
            case ED25519_JNI_VERIFY_PH_HASH:
                ret = wc_ed25519ph_verify_hash(sig, sigSz, in, inSz, &res, key,
                    ctx, (byte)ctxSz);
                break;
            case ED25519_JNI_VERIFY_MSG_EX:
                ret = wc_ed25519_verify_msg_ex(sig, sigSz, in, inSz, &res, key,
                    (byte)type, ctx, (byte)ctxSz);
                break;
            default:
                ret = BAD_STATE_E;
                break;
        }
    }

    if (ret == 0 && res == 1) {
        result = JNI_TRUE;
    }
    else if (ret == 0 || ret == SIG_VERIFY_E ||
            (called && ret == BAD_FUNC_ARG)) {
        /* did not verify, BAD_FUNC_ARG from wc_ is a malformed signature or
         * an invalid public key */
        result = JNI_FALSE;
    }
    else {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, ret);
        }
    }

    LogStr("ed25519_jni_verify(fn=%d, type=%d, sigSz=%u, inSz=%u, ctxSz=%u) = "
           "%d, res = %d\n", fn, (int)type, sigSz, inSz, ctxSz, ret, res);

    if (in != &dummy) {
        releaseByteArray(env, inObj, in, JNI_ABORT);
    }
    releaseByteArray(env, sigObj, sig, JNI_ABORT);
    releaseByteArray(env, ctxObj, ctx, JNI_ABORT);

    return result;
}

#endif /* HAVE_ED25519_VERIFY */

#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)

static void ed25519_jni_import_private(JNIEnv* env, jobject this,
    jbyteArray privObj, jbyteArray pubObj, int privOnly, int useEx,
    jboolean trusted)
{
    int ret = 0;
    ed25519_key* key = NULL;
    byte* priv = NULL;
    byte* pub = NULL;
    word32 privSz = 0;
    word32 pubSz = 0;
    jboolean privIsCopy = JNI_FALSE;

    key = ed25519_jni_get_key(env, this);
    if (key == NULL) {
        return;
    }

    if (privObj == NULL) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        }
        return;
    }

    priv = getByteArrayIsCopy(env, privObj, &privIsCopy);
    if (priv != NULL) {
        privSz = getByteArrayLength(env, privObj);
        if (pubObj != NULL) {
            pub = getByteArray(env, pubObj);
        }
        if (pub != NULL) {
            pubSz = getByteArrayLength(env, pubObj);
        }
    }

    if (priv == NULL || (pubObj != NULL && pub == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else if (privOnly || (pub == NULL && privSz == ED25519_KEY_SIZE)) {
        ret = wc_ed25519_import_private_only(priv, privSz, key);
    }
    else if (useEx) {
        ret = wc_ed25519_import_private_key_ex(priv, privSz, pub, pubSz, key,
            (trusted == JNI_TRUE) ? 1 : 0);
    }
    else {
        ret = wc_ed25519_import_private_key(priv, privSz, pub, pubSz, key);
    }

    if (ret != 0) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, ret);
        }
    }

    LogStr("ed25519_jni_import_private(privSz=%u, pubSz=%u, ex=%d, "
        "trusted=%d) = %d\n", privSz, pubSz, useEx, (int)trusted, ret);

    zeroizeByteArrayCopy(priv, privSz, privIsCopy);
    releaseByteArray(env, privObj, priv, JNI_ABORT);
    releaseByteArray(env, pubObj, pub, JNI_ABORT);
}

static void ed25519_jni_import_public(JNIEnv* env, jobject this,
    jbyteArray pubObj, int useEx, jboolean trusted)
{
    int ret = 0;
    ed25519_key* key = NULL;
    byte* pub = NULL;
    word32 pubSz = 0;

    key = ed25519_jni_get_key(env, this);
    if (key == NULL) {
        return;
    }

    if (pubObj == NULL) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        }
        return;
    }

    pub = getByteArray(env, pubObj);
    if (pub != NULL) {
        pubSz = getByteArrayLength(env, pubObj);
    }

    if (pub == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else if (useEx) {
        ret = wc_ed25519_import_public_ex(pub, pubSz, key,
            (trusted == JNI_TRUE) ? 1 : 0);
    }
    else {
        ret = wc_ed25519_import_public(pub, pubSz, key);
    }

    if (ret != 0) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, ret);
        }
    }

    LogStr("ed25519_jni_import_public(pubSz=%u, ex=%d, trusted=%d) = %d\n",
        pubSz, useEx, (int)trusted, ret);

    releaseByteArray(env, pubObj, pub, JNI_ABORT);
}

#endif /* HAVE_ED25519_KEY_IMPORT */

#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT)

/* Map native export function a JNI entry point maps to */
enum {
    ED25519_JNI_EXPORT_PUBLIC = 0,  /* wc_ed25519_export_public       */
    ED25519_JNI_EXPORT_PRIVATE_ONLY,/* wc_ed25519_export_private_only */
    ED25519_JNI_EXPORT_PRIVATE      /* wc_ed25519_export_private      */
};

static jbyteArray ed25519_jni_export(JNIEnv* env, jobject this, int fn)
{
    int ret = 0;
    jbyteArray result = NULL;
    ed25519_key* key = NULL;
    byte out[ED25519_PRV_KEY_SIZE];
    word32 outSz = 0;

    key = ed25519_jni_get_key(env, this);
    if (key == NULL) {
        return NULL;
    }

    XMEMSET(out, 0, sizeof(out));

    PRIVATE_KEY_UNLOCK();
    switch (fn) {
        case ED25519_JNI_EXPORT_PUBLIC:
            outSz = ED25519_PUB_KEY_SIZE;
            ret = wc_ed25519_export_public(key, out, &outSz);
            break;
        case ED25519_JNI_EXPORT_PRIVATE_ONLY:
            outSz = ED25519_KEY_SIZE;
            ret = wc_ed25519_export_private_only(key, out, &outSz);
            break;
        case ED25519_JNI_EXPORT_PRIVATE:
            outSz = ED25519_PRV_KEY_SIZE;
            ret = wc_ed25519_export_private(key, out, &outSz);
            break;
        default:
            ret = BAD_FUNC_ARG;
            break;
    }
    PRIVATE_KEY_LOCK();

    if (ret == 0) {
        result = ed25519_jni_new_byte_array(env, out, outSz);
    }
    else {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, ret);
        }
    }

    LogStr("ed25519_jni_export(fn=%d) = %d, outSz = %u\n", fn, ret, outSz);

    ED25519_FORCE_ZERO(out, sizeof(out));

    return result;
}

#endif /* HAVE_ED25519_KEY_EXPORT */

#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT) && \
    !defined(NO_ASN)

/* Map native DER export function a JNI entry point maps to */
enum {
    ED25519_JNI_DER_PUBLIC = 0,     /* wc_Ed25519PublicKeyToDer  */
    ED25519_JNI_DER_PRIVATE_ONLY,   /* wc_Ed25519PrivateKeyToDer */
    ED25519_JNI_DER_KEY             /* wc_Ed25519KeyToDer        */
};

static int ed25519_jni_der_call(ed25519_key* key, int fn, jboolean withAlg,
    byte* output, word32 outLen)
{
    int ret = 0;

    switch (fn) {
        case ED25519_JNI_DER_PUBLIC:
            ret = wc_Ed25519PublicKeyToDer(key, output, outLen,
                (withAlg == JNI_TRUE) ? 1 : 0);
            break;
        case ED25519_JNI_DER_PRIVATE_ONLY:
            ret = wc_Ed25519PrivateKeyToDer(key, output, outLen);
            break;
        case ED25519_JNI_DER_KEY:
            ret = wc_Ed25519KeyToDer(key, output, outLen);
            break;
        default:
            ret = BAD_FUNC_ARG;
            break;
    }
    return ret;
}

static jbyteArray ed25519_jni_der_export(JNIEnv* env, jobject this, int fn,
    jboolean withAlg)
{
    int ret = 0;
    jbyteArray result = NULL;
    ed25519_key* key = NULL;
    byte* output = NULL;
    word32 outputSz = 0;

    key = ed25519_jni_get_key(env, this);
    if (key == NULL) {
        return NULL;
    }

    PRIVATE_KEY_UNLOCK();
    ret = ed25519_jni_der_call(key, fn, withAlg, NULL, 0);
    PRIVATE_KEY_LOCK();
    if (ret <= 0) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env,
                (ret == 0) ? BAD_FUNC_ARG : ret);
        }
        return NULL;
    }
    outputSz = (word32)ret;

    output = (byte*)XMALLOC(outputSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate DER buffer");
        return NULL;
    }
    XMEMSET(output, 0, outputSz);

    PRIVATE_KEY_UNLOCK();
    ret = ed25519_jni_der_call(key, fn, withAlg, output, outputSz);
    PRIVATE_KEY_LOCK();

    if (ret > 0) {
        result = ed25519_jni_new_byte_array(env, output, (word32)ret);
    }
    else {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env,
                (ret == 0) ? BAD_FUNC_ARG : ret);
        }
    }

    LogStr("ed25519_jni_der_export(fn=%d, withAlg=%d) = %d\n", fn,
        (int)withAlg, ret);

    ED25519_FORCE_ZERO(output, outputSz);
    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return result;
}

#endif /* HAVE_ED25519_KEY_EXPORT && !NO_ASN */

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_mallocNativeStruct
  (JNIEnv* env, jobject this)
{
#ifdef HAVE_ED25519
    ed25519_key* key = NULL;

    (void)this;

    key = (ed25519_key*)XMALLOC(sizeof(ed25519_key), NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (key == NULL) {
        throwOutOfMemoryException(env, "Failed to allocate Ed25519 object");
    }
    else {
        XMEMSET(key, 0, sizeof(ed25519_key));
    }

    LogStr("new Ed25519() = %p\n", key);

    return (jlong)(uintptr_t)key;
#else
    (void)this;
    throwNotCompiledInException(env);
    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1init
  (JNIEnv* env, jobject this)
{
#ifdef HAVE_ED25519
    int ret = 0;
    ed25519_key* key = ed25519_jni_get_key(env, this);
    if (key == NULL) {
        return;
    }

    ret = wc_ed25519_init(key);
    if (ret != 0) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, ret);
        }
    }

    LogStr("wc_ed25519_init(key=%p) = %d\n", key, ret);
#else
    (void)this;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1init_1ex
  (JNIEnv* env, jobject this, jint devId)
{
#ifdef HAVE_ED25519
    int ret = 0;
    ed25519_key* key = ed25519_jni_get_key(env, this);
    if (key == NULL) {
        return;
    }

    ret = wc_ed25519_init_ex(key, NULL, (int)devId);
    if (ret != 0) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, ret);
        }
    }

    LogStr("wc_ed25519_init_ex(key=%p, devId=%d) = %d\n", key, (int)devId, ret);
#else
    (void)this;
    (void)devId;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1free
  (JNIEnv* env, jobject this)
{
#ifdef HAVE_ED25519
    ed25519_key* key = (ed25519_key*)getNativeStruct(env, this);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception */
        return;
    }

    if (key != NULL) {
        wc_ed25519_free(key);
    }

    LogStr("wc_ed25519_free(key=%p)\n", key);
#else
    (void)this;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1make_1key
  (JNIEnv* env, jobject this, jobject rng_object, jint size)
{
#if defined(HAVE_ED25519) && !defined(NO_ED25519_MAKE_KEY)
    int ret = 0;
    ed25519_key* key = NULL;
    RNG* rng = NULL;

    key = ed25519_jni_get_key(env, this);
    if (key == NULL) {
        return;
    }

    rng = (RNG*)getNativeStruct(env, rng_object);
    if ((*env)->ExceptionOccurred(env)) {
        /* getNativeStruct may throw exception, prevent throwing another */
        return;
    }

    if (rng == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_ed25519_make_key(rng, (int)size, key);
    }

    if (ret != 0) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, ret);
        }
    }

    LogStr("wc_ed25519_make_key(rng, size=%d, key=%p) = %d\n", (int)size,
        key, ret);
#else
    (void)this;
    (void)rng_object;
    (void)size;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1make_1public
  (JNIEnv* env, jobject this)
{
#if defined(HAVE_ED25519) && !defined(NO_ED25519_MAKE_KEY) && \
    defined(HAVE_ED25519_KEY_EXPORT) && defined(HAVE_ED25519_KEY_IMPORT)
    int ret = 0;
    jbyteArray result = NULL;
    ed25519_key* key = NULL;
    byte priv[ED25519_KEY_SIZE];
    byte pub[ED25519_PUB_KEY_SIZE];
    word32 privSz = (word32)sizeof(priv);

    key = ed25519_jni_get_key(env, this);
    if (key == NULL) {
        return NULL;
    }

    PRIVATE_KEY_UNLOCK();
    ret = wc_ed25519_make_public(key, pub, (word32)sizeof(pub));
    /* re-import so the key holds priv||pub as after wc_ed25519_make_key() */
    if (ret == 0) {
        ret = wc_ed25519_export_private_only(key, priv, &privSz);
    }
    if (ret == 0) {
        ret = wc_ed25519_import_private_key_ex(priv, privSz, pub,
            (word32)sizeof(pub), key, 1);
    }
    PRIVATE_KEY_LOCK();
    ED25519_FORCE_ZERO(priv, sizeof(priv));

    if (ret == 0) {
        result = ed25519_jni_new_byte_array(env, pub, (word32)sizeof(pub));
    }
    else if (!(*env)->ExceptionCheck(env)) {
        throwWolfCryptExceptionFromError(env, ret);
    }

    LogStr("wc_ed25519_make_public(key=%p) = %d\n", key, ret);

    return result;
#else
    (void)this;
    throwNotCompiledInException(env);
    return NULL;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1check_1key
  (JNIEnv* env, jobject this)
{
#ifdef HAVE_ED25519
    int ret = 0;
    ed25519_key* key = ed25519_jni_get_key(env, this);
    if (key == NULL) {
        return;
    }

    ret = wc_ed25519_check_key(key);
    if (ret != 0) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, ret);
        }
    }

    LogStr("wc_ed25519_check_key(key=%p) = %d\n", key, ret);
#else
    (void)this;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_ed25519_1key_1privKeySet
  (JNIEnv* env, jobject this)
{
#ifdef HAVE_ED25519
    ed25519_key* key = ed25519_jni_get_key(env, this);
    if (key == NULL) {
        return JNI_FALSE;
    }

    return key->privKeySet ? JNI_TRUE : JNI_FALSE;
#else
    (void)this;
    throwNotCompiledInException(env);
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_ed25519_1key_1pubKeySet
  (JNIEnv* env, jobject this)
{
#ifdef HAVE_ED25519
    ed25519_key* key = ed25519_jni_get_key(env, this);
    if (key == NULL) {
        return JNI_FALSE;
    }

    return key->pubKeySet ? JNI_TRUE : JNI_FALSE;
#else
    (void)this;
    throwNotCompiledInException(env);
    return JNI_FALSE;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1size
  (JNIEnv* env, jobject this)
{
#ifdef HAVE_ED25519
    int ret = 0;
    ed25519_key* key = ed25519_jni_get_key(env, this);
    if (key == NULL) {
        return 0;
    }

    ret = wc_ed25519_size(key);
    if (ret < 0) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, ret);
        }
        return 0;
    }

    return (jint)ret;
#else
    (void)this;
    throwNotCompiledInException(env);
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1priv_1size
  (JNIEnv* env, jobject this)
{
#ifdef HAVE_ED25519
    int ret = 0;
    ed25519_key* key = ed25519_jni_get_key(env, this);
    if (key == NULL) {
        return 0;
    }

    ret = wc_ed25519_priv_size(key);
    if (ret < 0) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, ret);
        }
        return 0;
    }

    return (jint)ret;
#else
    (void)this;
    throwNotCompiledInException(env);
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1pub_1size
  (JNIEnv* env, jobject this)
{
#ifdef HAVE_ED25519
    int ret = 0;
    ed25519_key* key = ed25519_jni_get_key(env, this);
    if (key == NULL) {
        return 0;
    }

    ret = wc_ed25519_pub_size(key);
    if (ret < 0) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, ret);
        }
        return 0;
    }

    return (jint)ret;
#else
    (void)this;
    throwNotCompiledInException(env);
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1sig_1size
  (JNIEnv* env, jobject this)
{
#ifdef HAVE_ED25519
    int ret = 0;
    ed25519_key* key = ed25519_jni_get_key(env, this);
    if (key == NULL) {
        return 0;
    }

    ret = wc_ed25519_sig_size(key);
    if (ret < 0) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, ret);
        }
        return 0;
    }

    return (jint)ret;
#else
    (void)this;
    throwNotCompiledInException(env);
    return 0;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1import_1private
  (JNIEnv* env, jobject this, jbyteArray priv_object, jbyteArray pub_object)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
    ed25519_jni_import_private(env, this, priv_object, pub_object, 0, 0,
        JNI_FALSE);
#else
    (void)this;
    (void)priv_object;
    (void)pub_object;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1import_1private_1key_1ex
  (JNIEnv* env, jobject this, jbyteArray priv_object, jbyteArray pub_object,
   jboolean trusted)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
    ed25519_jni_import_private(env, this, priv_object, pub_object, 0, 1,
        trusted);
#else
    (void)this;
    (void)priv_object;
    (void)pub_object;
    (void)trusted;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1import_1private_1only
  (JNIEnv* env, jobject this, jbyteArray priv_object)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
    ed25519_jni_import_private(env, this, priv_object, NULL, 1, 0, JNI_FALSE);
#else
    (void)this;
    (void)priv_object;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1import_1public
  (JNIEnv* env, jobject this, jbyteArray pub_object)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
    ed25519_jni_import_public(env, this, pub_object, 0, JNI_FALSE);
#else
    (void)this;
    (void)pub_object;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1import_1public_1ex
  (JNIEnv* env, jobject this, jbyteArray pub_object, jboolean trusted)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
    ed25519_jni_import_public(env, this, pub_object, 1, trusted);
#else
    (void)this;
    (void)pub_object;
    (void)trusted;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1export_1private
  (JNIEnv* env, jobject this)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT)
    return ed25519_jni_export(env, this, ED25519_JNI_EXPORT_PRIVATE);
#else
    (void)this;
    throwNotCompiledInException(env);
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1export_1private_1only
  (JNIEnv* env, jobject this)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT)
    return ed25519_jni_export(env, this, ED25519_JNI_EXPORT_PRIVATE_ONLY);
#else
    (void)this;
    throwNotCompiledInException(env);
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1export_1public
  (JNIEnv* env, jobject this)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT)
    return ed25519_jni_export(env, this, ED25519_JNI_EXPORT_PUBLIC);
#else
    (void)this;
    throwNotCompiledInException(env);
    return NULL;
#endif
}

JNIEXPORT jobjectArray JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1export_1key
  (JNIEnv* env, jobject this)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT)
    int ret = 0;
    jobjectArray result = NULL;
    jbyteArray privArr = NULL;
    jbyteArray pubArr = NULL;
    jclass byteArrayClass = NULL;
    ed25519_key* key = NULL;
    /* native exports the private||public form into priv */
    byte priv[ED25519_PRV_KEY_SIZE];
    byte pub[ED25519_PUB_KEY_SIZE];
    word32 privSz = (word32)sizeof(priv);
    word32 pubSz = (word32)sizeof(pub);

    key = ed25519_jni_get_key(env, this);
    if (key == NULL) {
        return NULL;
    }

    XMEMSET(priv, 0, sizeof(priv));
    XMEMSET(pub, 0, sizeof(pub));

    PRIVATE_KEY_UNLOCK();
    ret = wc_ed25519_export_key(key, priv, &privSz, pub, &pubSz);
    PRIVATE_KEY_LOCK();

    if (ret == 0) {
        byteArrayClass = (*env)->FindClass(env, "[B");
        if (byteArrayClass != NULL) {
            result = (*env)->NewObjectArray(env, 2, byteArrayClass, NULL);
        }
        if (result != NULL) {
            privArr = ed25519_jni_new_byte_array(env, priv, privSz);
        }
        if (privArr != NULL) {
            (*env)->SetObjectArrayElement(env, result, 0, privArr);
            pubArr = ed25519_jni_new_byte_array(env, pub, pubSz);
        }
        if (pubArr != NULL) {
            (*env)->SetObjectArrayElement(env, result, 1, pubArr);
        }
        if (privArr == NULL || pubArr == NULL) {
            /* a JVM exception is pending */
            result = NULL;
        }
    }
    else {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, ret);
        }
    }

    LogStr("wc_ed25519_export_key(key=%p) = %d\n", key, ret);

    ED25519_FORCE_ZERO(priv, sizeof(priv));

    return result;
#else
    (void)this;
    throwNotCompiledInException(env);
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1sign_1msg
  (JNIEnv* env, jobject this, jbyteArray msg_in)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_SIGN)
    return ed25519_jni_sign(env, this, msg_in, NULL, (jint)Ed25519,
        ED25519_JNI_SIGN_MSG);
#else
    (void)this;
    (void)msg_in;
    throwNotCompiledInException(env);
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519ctx_1sign_1msg
  (JNIEnv* env, jobject this, jbyteArray msg_in, jbyteArray ctx_in)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_SIGN)
    return ed25519_jni_sign(env, this, msg_in, ctx_in, (jint)Ed25519ctx,
        ED25519_JNI_SIGN_CTX_MSG);
#else
    (void)this;
    (void)msg_in;
    (void)ctx_in;
    throwNotCompiledInException(env);
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519ph_1sign_1msg
  (JNIEnv* env, jobject this, jbyteArray msg_in, jbyteArray ctx_in)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_SIGN)
    return ed25519_jni_sign(env, this, msg_in, ctx_in, (jint)Ed25519ph,
        ED25519_JNI_SIGN_PH_MSG);
#else
    (void)this;
    (void)msg_in;
    (void)ctx_in;
    throwNotCompiledInException(env);
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519ph_1sign_1hash
  (JNIEnv* env, jobject this, jbyteArray hash_in, jbyteArray ctx_in)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_SIGN)
    return ed25519_jni_sign(env, this, hash_in, ctx_in, (jint)Ed25519ph,
        ED25519_JNI_SIGN_PH_HASH);
#else
    (void)this;
    (void)hash_in;
    (void)ctx_in;
    throwNotCompiledInException(env);
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1sign_1msg_1ex
  (JNIEnv* env, jobject this, jbyteArray msg_in, jint type, jbyteArray ctx_in)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_SIGN)
    return ed25519_jni_sign(env, this, msg_in, ctx_in, type,
        ED25519_JNI_SIGN_MSG_EX);
#else
    (void)this;
    (void)msg_in;
    (void)type;
    (void)ctx_in;
    throwNotCompiledInException(env);
    return NULL;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1verify_1msg
  (JNIEnv* env, jobject this, jbyteArray sig_in, jbyteArray msg_in)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_VERIFY)
    return ed25519_jni_verify(env, this, sig_in, msg_in, NULL,
        (jint)Ed25519, ED25519_JNI_VERIFY_MSG);
#else
    (void)this;
    (void)sig_in;
    (void)msg_in;
    throwNotCompiledInException(env);
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519ctx_1verify_1msg
  (JNIEnv* env, jobject this, jbyteArray sig_in, jbyteArray msg_in,
   jbyteArray ctx_in)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_VERIFY)
    return ed25519_jni_verify(env, this, sig_in, msg_in, ctx_in,
        (jint)Ed25519ctx, ED25519_JNI_VERIFY_CTX_MSG);
#else
    (void)this;
    (void)sig_in;
    (void)msg_in;
    (void)ctx_in;
    throwNotCompiledInException(env);
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519ph_1verify_1msg
  (JNIEnv* env, jobject this, jbyteArray sig_in, jbyteArray msg_in,
   jbyteArray ctx_in)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_VERIFY)
    return ed25519_jni_verify(env, this, sig_in, msg_in, ctx_in,
        (jint)Ed25519ph, ED25519_JNI_VERIFY_PH_MSG);
#else
    (void)this;
    (void)sig_in;
    (void)msg_in;
    (void)ctx_in;
    throwNotCompiledInException(env);
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519ph_1verify_1hash
  (JNIEnv* env, jobject this, jbyteArray sig_in, jbyteArray hash_in,
   jbyteArray ctx_in)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_VERIFY)
    return ed25519_jni_verify(env, this, sig_in, hash_in, ctx_in,
        (jint)Ed25519ph, ED25519_JNI_VERIFY_PH_HASH);
#else
    (void)this;
    (void)sig_in;
    (void)hash_in;
    (void)ctx_in;
    throwNotCompiledInException(env);
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1verify_1msg_1ex
  (JNIEnv* env, jobject this, jbyteArray sig_in, jbyteArray msg_in,
   jint type, jbyteArray ctx_in)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_VERIFY)
    return ed25519_jni_verify(env, this, sig_in, msg_in, ctx_in, type,
        ED25519_JNI_VERIFY_MSG_EX);
#else
    (void)this;
    (void)sig_in;
    (void)msg_in;
    (void)type;
    (void)ctx_in;
    throwNotCompiledInException(env);
    return JNI_FALSE;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1verify_1msg_1init
  (JNIEnv* env, jobject this, jbyteArray sig_in, jint type, jbyteArray ctx_in)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_VERIFY) && \
    !defined(WOLFSSL_SE050) && defined(WOLFSSL_ED25519_STREAMING_VERIFY)
    int ret = 0;
    ed25519_key* key = NULL;
    byte* sig = NULL;
    byte* ctx = NULL;
    word32 sigSz = 0;
    word32 ctxSz = 0;

    key = ed25519_jni_get_key(env, this);
    if (key == NULL) {
        return;
    }
    if (sig_in == NULL) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        }
        return;
    }

    sig = getByteArray(env, sig_in);
    sigSz = getByteArrayLength(env, sig_in);
    if (sig == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = ed25519_jni_pin_context(env, ctx_in, &ctx, &ctxSz);
    }

    if (ret == 0) {
        ret = wc_ed25519_verify_msg_init(sig, sigSz, key, (byte)type, ctx,
            (byte)ctxSz);
        if (ret == BAD_FUNC_ARG) {
            /* malformed signature */
            ret = SIG_VERIFY_E;
        }
    }

    if (ret != 0) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, ret);
        }
    }

    LogStr("wc_ed25519_verify_msg_init(sigSz=%u, type=%d, ctxSz=%u) = %d\n",
        sigSz, (int)type, ctxSz, ret);

    releaseByteArray(env, sig_in, sig, JNI_ABORT);
    releaseByteArray(env, ctx_in, ctx, JNI_ABORT);
#else
    (void)this;
    (void)sig_in;
    (void)type;
    (void)ctx_in;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1verify_1msg_1update
  (JNIEnv* env, jobject this, jbyteArray seg_in, jint offset, jint len)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_VERIFY) && \
    !defined(WOLFSSL_SE050) && defined(WOLFSSL_ED25519_STREAMING_VERIFY)
    int ret = 0;
    ed25519_key* key = NULL;
    byte* seg = NULL;
    word32 segSz = 0;
    byte dummy = 0;

    key = ed25519_jni_get_key(env, this);
    if (key == NULL) {
        return;
    }
    if (seg_in == NULL || offset < 0 || len < 0) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        }
        return;
    }

    segSz = getByteArrayLength(env, seg_in);
    if ((word32)offset > segSz || (word32)len > segSz - (word32)offset) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        }
        return;
    }

    if (len > 0) {
        seg = getByteArray(env, seg_in);
        if (seg == NULL) {
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        ret = wc_ed25519_verify_msg_update((seg != NULL) ? seg + offset :
            &dummy, (word32)len, key);
    }

    if (ret != 0) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, ret);
        }
    }

    LogStr("wc_ed25519_verify_msg_update(len=%d) = %d\n", (int)len, ret);

    releaseByteArray(env, seg_in, seg, JNI_ABORT);
#else
    (void)this;
    (void)seg_in;
    (void)offset;
    (void)len;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1ed25519_1verify_1msg_1final
  (JNIEnv* env, jobject this, jbyteArray sig_in)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_VERIFY) && \
    !defined(WOLFSSL_SE050) && defined(WOLFSSL_ED25519_STREAMING_VERIFY)
    int ret = 0;
    int called = 0;
    int res = 0;
    jboolean result = JNI_FALSE;
    ed25519_key* key = NULL;
    byte* sig = NULL;
    word32 sigSz = 0;

    key = ed25519_jni_get_key(env, this);
    if (key == NULL) {
        return JNI_FALSE;
    }
    if (sig_in == NULL) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        }
        return JNI_FALSE;
    }

    sig = getByteArray(env, sig_in);
    sigSz = getByteArrayLength(env, sig_in);
    if (sig == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        called = 1;
        ret = wc_ed25519_verify_msg_final(sig, sigSz, &res, key);
    }

    if (ret == 0 && res == 1) {
        result = JNI_TRUE;
    }
    else if (ret == 0 || ret == SIG_VERIFY_E ||
             (called && ret == BAD_FUNC_ARG)) {
        /* did not verify, BAD_FUNC_ARG from wc_ is a malformed signature or
         * an invalid public key */
        result = JNI_FALSE;
    }
    else {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, ret);
        }
    }

    LogStr("wc_ed25519_verify_msg_final(sigSz=%u) = %d, res = %d\n", sigSz,
        ret, res);

    releaseByteArray(env, sig_in, sig, JNI_ABORT);

    return result;
#else
    (void)this;
    (void)sig_in;
    throwNotCompiledInException(env);
    return JNI_FALSE;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1Ed25519PublicKeyDecode
  (JNIEnv* env, jobject this, jbyteArray der_in)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT) && \
    !defined(NO_ASN)
    int ret = 0;
    ed25519_key* key = NULL;
    byte* der = NULL;
    word32 derSz = 0;
    word32 idx = 0;

    key = ed25519_jni_get_key(env, this);
    if (key == NULL) {
        return;
    }
    if (der_in == NULL) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        }
        return;
    }

    der = getByteArray(env, der_in);
    if (der != NULL) {
        derSz = getByteArrayLength(env, der_in);
    }

    if (der == NULL || derSz == 0) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_Ed25519PublicKeyDecode(der, &idx, key, derSz);
    }

    if (ret != 0) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, ret);
        }
    }

    LogStr("wc_Ed25519PublicKeyDecode(derSz=%u) = %d\n", derSz, ret);

    releaseByteArray(env, der_in, der, JNI_ABORT);
#else
    (void)this;
    (void)der_in;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1Ed25519PrivateKeyDecode
  (JNIEnv* env, jobject this, jbyteArray der_in)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT) && \
    !defined(NO_ASN)
    int ret = 0;
    ed25519_key* key = NULL;
    byte* der = NULL;
    word32 derSz = 0;
    word32 idx = 0;
    jboolean derIsCopy = JNI_FALSE;

    key = ed25519_jni_get_key(env, this);
    if (key == NULL) {
        return;
    }
    if (der_in == NULL) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, BAD_FUNC_ARG);
        }
        return;
    }

    der = getByteArrayIsCopy(env, der_in, &derIsCopy);
    if (der != NULL) {
        derSz = getByteArrayLength(env, der_in);
    }

    if (der == NULL || derSz == 0) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_Ed25519PrivateKeyDecode(der, &idx, key, derSz);
    }

    if (ret != 0) {
        if (!(*env)->ExceptionCheck(env)) {
            throwWolfCryptExceptionFromError(env, ret);
        }
    }

    LogStr("wc_Ed25519PrivateKeyDecode(derSz=%u) = %d\n", derSz, ret);

    zeroizeByteArrayCopy(der, derSz, derIsCopy);
    releaseByteArray(env, der_in, der, JNI_ABORT);
#else
    (void)this;
    (void)der_in;
    throwNotCompiledInException(env);
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1Ed25519PublicKeyToDer
  (JNIEnv* env, jobject this, jboolean withAlg)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT) && \
    !defined(NO_ASN)
    return ed25519_jni_der_export(env, this, ED25519_JNI_DER_PUBLIC, withAlg);
#else
    (void)this;
    (void)withAlg;
    throwNotCompiledInException(env);
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1Ed25519PrivateKeyToDer
  (JNIEnv* env, jobject this)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT) && \
    !defined(NO_ASN)
    return ed25519_jni_der_export(env, this, ED25519_JNI_DER_PRIVATE_ONLY,
        JNI_FALSE);
#else
    (void)this;
    throwNotCompiledInException(env);
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_Ed25519_wc_1Ed25519KeyToDer
  (JNIEnv* env, jobject this)
{
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT) && \
    !defined(NO_ASN)
    return ed25519_jni_der_export(env, this, ED25519_JNI_DER_KEY, JNI_FALSE);
#else
    (void)this;
    throwNotCompiledInException(env);
    return NULL;
#endif
}

