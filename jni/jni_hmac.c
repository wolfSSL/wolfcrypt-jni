#include <com_wolfssl_wolfcrypt_Hmac.h>
#include <wolfcrypt_jni_error.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hmac.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Hmac_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    jlong ret = 0;

#ifdef NO_HMAC
    throwNotCompiledInException(env);
#else

    ret = (jlong) XMALLOC(sizeof(Hmac), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Hmac object");

    LogStr("new Hmac() = %p\n", ret);

#endif

    return ret;
}
