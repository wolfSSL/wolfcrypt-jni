#include <com_wolfssl_wolfcrypt_Ecc.h>
#include <wolfcrypt_jni_error.h>

#ifndef __ANDROID__
    #include <wolfssl/options.h>
#endif

#include <wolfssl/wolfcrypt/ecc.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Ecc_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    jlong ret = 0;

#ifndef HAVE_ECC
    throwNotCompiledInException(env);
#else

    ret = (jlong) XMALLOC(sizeof(ecc_key), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Ecc object");

    LogStr("new Ecc() = %p\n", ret);

#endif

    return ret;
}
