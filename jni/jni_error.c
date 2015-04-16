#include <com_wolfssl_wolfcrypt_WolfCryptError.h>

#ifndef __ANDROID__
    #include <wolfssl/options.h>
#endif

#include <wolfssl/wolfcrypt/error-crypt.h>
JNIEXPORT jstring JNICALL Java_com_wolfssl_wolfcrypt_WolfCryptError_wc_1GetErrorString
  (JNIEnv* env, jclass obj, jint error)
{
    return (*env)->NewStringUTF(env, wc_GetErrorString(error));
}

