#include <com_wolfssl_wolfcrypt_Sha.h>
#include <wolfcrypt_jni_error.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Sha_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    jlong ret = 0;

#ifdef NO_SHA
    throwNotCompiledInException(env);
#else

    ret = (jlong) XMALLOC(sizeof(Sha), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Sha object");

    LogStr("new Sha() = %p\n", ret);

#endif

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Sha256_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    jlong ret = 0;

#ifdef NO_SHA256
    throwNotCompiledInException(env);
#else

    ret = (jlong) XMALLOC(sizeof(Sha256), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Sha256 object");

    LogStr("new Sha256() = %p\n", ret);

#endif

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Sha384_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    jlong ret = 0;

#ifndef WOLFSSL_SHA512
    throwNotCompiledInException(env);
#else

    ret = (jlong) XMALLOC(sizeof(Sha384), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Sha384 object");

    LogStr("new Sha384() = %p\n", ret);

#endif

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Sha512_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    jlong ret = 0;

#ifndef WOLFSSL_SHA512
    throwNotCompiledInException(env);
#else

    ret = (jlong) XMALLOC(sizeof(Sha512), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Sha512 object");

    LogStr("new Sha512() = %p\n", ret);

#endif

    return ret;
}
