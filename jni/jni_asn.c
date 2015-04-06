#include <com_wolfssl_wolfcrypt_Asn.h>
#include <wolfcrypt_jni_NativeStruct.h>
#include <wolfcrypt_jni_error.h>

#ifndef __ANDROID__
    #include <wolfssl/options.h>
#endif

#include <wolfssl/wolfcrypt/asn_public.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Asn_encodeSignature(
    JNIEnv* env, jclass class, jobject encoded_object, jobject hash_object,
    jlong hashSize, jint hashOID)
{
    byte* encoded = getDirectBufferAddress(env, encoded_object);
    byte* hash = getDirectBufferAddress(env, hash_object);

    if (!encoded || !hash)
        throwWolfCryptException(env, "Bad method argument provided");

    setDirectBufferLimit(env, encoded_object,
        wc_EncodeSignature(encoded, hash, hashSize, hashOID));
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Asn_getCTC_1HashOID(
    JNIEnv* env, jclass class, jint type)
{
    return wc_GetCTC_HashOID(type);
}
