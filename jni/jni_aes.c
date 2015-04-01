#include <com_wolfssl_wolfcrypt_Aes.h>
#include <wolfcrypt_jni_error.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Aes_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    jlong ret = 0;

#ifdef NO_AES
    throwNotCompiledInException(env);
#else

    ret = (jlong) XMALLOC(sizeof(Aes), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Aes object");

    LogStr("new Aes() = %p\n", ret);

#endif

    return ret;
}
