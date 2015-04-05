#include <com_wolfssl_wolfcrypt_Sha.h>
#include <wolfcrypt_jni_error.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/md5.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Md5_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    jlong ret = 0;

#ifdef NO_MD5
    throwNotCompiledInException(env);
#else

    ret = (jlong) XMALLOC(sizeof(Md5), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ret)
        throwOutOfMemoryException(env, "Failed to allocate Md5 object");

    LogStr("new Md5() = %p\n", ret);

#endif

    return ret;
}
