/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_wolfssl_wolfcrypt_AesGcm */

#ifndef _Included_com_wolfssl_wolfcrypt_AesGcm
#define _Included_com_wolfssl_wolfcrypt_AesGcm
#ifdef __cplusplus
extern "C" {
#endif
#undef com_wolfssl_wolfcrypt_AesGcm_NULL
#define com_wolfssl_wolfcrypt_AesGcm_NULL 0LL
/*
 * Class:     com_wolfssl_wolfcrypt_AesGcm
 * Method:    mallocNativeStruct_internal
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_com_wolfssl_wolfcrypt_AesGcm_mallocNativeStruct_1internal
  (JNIEnv *, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_AesGcm
 * Method:    wc_AesInit
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesGcm_wc_1AesInit
  (JNIEnv *, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_AesGcm
 * Method:    wc_AesFree
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesGcm_wc_1AesFree
  (JNIEnv *, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_AesGcm
 * Method:    wc_AesGcmSetKey
 * Signature: ([B)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_AesGcm_wc_1AesGcmSetKey
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     com_wolfssl_wolfcrypt_AesGcm
 * Method:    wc_AesGcmEncrypt
 * Signature: ([B[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_AesGcm_wc_1AesGcmEncrypt
  (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     com_wolfssl_wolfcrypt_AesGcm
 * Method:    wc_AesGcmDecrypt
 * Signature: ([B[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_AesGcm_wc_1AesGcmDecrypt
  (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray, jbyteArray);

#ifdef __cplusplus
}
#endif
#endif
