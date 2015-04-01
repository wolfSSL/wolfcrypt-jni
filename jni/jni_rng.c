#include <com_wolfssl_wolfcrypt_Rng.h>
#include <wolfcrypt_jni_error.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_Rng_mallocNativeStruct(
    JNIEnv* env, jobject this)
{
    RNG* rng = (RNG*) XMALLOC(sizeof(RNG), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!rng)
        throwOutOfMemoryException(env, "Failed to allocate Rng object");

    LogStr("new Rng() = %p\n", rng);

    return (jlong) rng;
}
