#include <com_wolfssl_wolfcrypt_Sha.h>
#include <wolfcrypt_jni_error.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/dh.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Dh_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    jlong ret = 0;

#ifdef NO_DH
    throwNotCompiledInException(env);
#else

    ret = (jlong) XMALLOC(sizeof(DhKey), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Dh object");

    LogStr("new Dh() = %p\n", ret);

#endif

    return ret;
}
