#include <com_wolfssl_wolfcrypt_Rsa.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/rsa.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Rsa_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    jlong ret = 0;

#ifdef NO_RSA
    throwNotCompiledInException(env);
#else

    ret = (jlong) XMALLOC(sizeof(RsaKey), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Rsa object");

    LogStr("new Rsa() = %p\n", ret);

#endif

    return ret;
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Rsa_decodeRawPublicKey(
    JNIEnv* env, jobject this, jobject n_object, jlong nSize, jobject e_object,
    jlong eSize)
{
#ifdef NO_RSA
    throwNotCompiledInException(env);
#else

    RsaKey* key = (RsaKey*) getNativeStruct(env, this);
    byte* n = getDirectBufferAddress(env, n_object);
    byte* e = getDirectBufferAddress(env, e_object);

    if (!key || !n || !e)
        throwWolfCryptException(env, "Bad method argument provided");

    if (wc_RsaPublicKeyDecodeRaw(n, nSize, e, eSize, key) != 0)
        throwWolfCryptException(env, "Failed to decode raw public key");

#endif
}
