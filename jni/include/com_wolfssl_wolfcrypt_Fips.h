/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_wolfssl_wolfcrypt_Fips */

#ifndef _Included_com_wolfssl_wolfcrypt_Fips
#define _Included_com_wolfssl_wolfcrypt_Fips
#ifdef __cplusplus
extern "C" {
#endif
#undef com_wolfssl_wolfcrypt_Fips_WC_KEYTYPE_ALL
#define com_wolfssl_wolfcrypt_Fips_WC_KEYTYPE_ALL 0L
/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wolfCrypt_SetCb_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Fips/ErrorCallback;)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Fips_wolfCrypt_1SetCb_1fips
  (JNIEnv *, jclass, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wolfCrypt_GetCoreHash_fips
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_wolfssl_wolfcrypt_Fips_wolfCrypt_1GetCoreHash_1fips
  (JNIEnv *, jclass);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    enabled
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_Fips_enabled
  (JNIEnv *, jclass);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    setPrivateKeyReadEnable
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_setPrivateKeyReadEnable
  (JNIEnv *, jclass, jint, jint);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    getPrivateKeyReadEnable
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_getPrivateKeyReadEnable
  (JNIEnv *, jclass, jint);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_runAllCast_fips
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1runAllCast_1fips
  (JNIEnv *, jclass);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wolfCrypt_GetStatus_fips
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wolfCrypt_1GetStatus_1fips
  (JNIEnv *, jclass);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wolfCrypt_SetStatus_fips
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wolfCrypt_1SetStatus_1fips
  (JNIEnv *, jclass, jint);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    getFipsVersion
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_getFipsVersion
  (JNIEnv *, jclass);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_AesSetKey_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Aes;Ljava/nio/ByteBuffer;JLjava/nio/ByteBuffer;I)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1AesSetKey_1fips__Lcom_wolfssl_wolfcrypt_Aes_2Ljava_nio_ByteBuffer_2JLjava_nio_ByteBuffer_2I
  (JNIEnv *, jclass, jobject, jobject, jlong, jobject, jint);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_AesSetKey_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Aes;[BJ[BI)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1AesSetKey_1fips__Lcom_wolfssl_wolfcrypt_Aes_2_3BJ_3BI
  (JNIEnv *, jclass, jobject, jbyteArray, jlong, jbyteArray, jint);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_AesSetIV_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Aes;Ljava/nio/ByteBuffer;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1AesSetIV_1fips__Lcom_wolfssl_wolfcrypt_Aes_2Ljava_nio_ByteBuffer_2
  (JNIEnv *, jclass, jobject, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_AesSetIV_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Aes;[B)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1AesSetIV_1fips__Lcom_wolfssl_wolfcrypt_Aes_2_3B
  (JNIEnv *, jclass, jobject, jbyteArray);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_AesCbcEncrypt_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Aes;Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1AesCbcEncrypt_1fips__Lcom_wolfssl_wolfcrypt_Aes_2Ljava_nio_ByteBuffer_2Ljava_nio_ByteBuffer_2J
  (JNIEnv *, jclass, jobject, jobject, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_AesCbcEncrypt_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Aes;[B[BJ)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1AesCbcEncrypt_1fips__Lcom_wolfssl_wolfcrypt_Aes_2_3B_3BJ
  (JNIEnv *, jclass, jobject, jbyteArray, jbyteArray, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_AesCbcDecrypt_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Aes;Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1AesCbcDecrypt_1fips__Lcom_wolfssl_wolfcrypt_Aes_2Ljava_nio_ByteBuffer_2Ljava_nio_ByteBuffer_2J
  (JNIEnv *, jclass, jobject, jobject, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_AesCbcDecrypt_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Aes;[B[BJ)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1AesCbcDecrypt_1fips__Lcom_wolfssl_wolfcrypt_Aes_2_3B_3BJ
  (JNIEnv *, jclass, jobject, jbyteArray, jbyteArray, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_AesGcmSetKey_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Aes;Ljava/nio/ByteBuffer;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1AesGcmSetKey_1fips__Lcom_wolfssl_wolfcrypt_Aes_2Ljava_nio_ByteBuffer_2J
  (JNIEnv *, jclass, jobject, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_AesGcmSetKey_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Aes;[BJ)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1AesGcmSetKey_1fips__Lcom_wolfssl_wolfcrypt_Aes_2_3BJ
  (JNIEnv *, jclass, jobject, jbyteArray, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_AesGcmSetExtIV_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Aes;Ljava/nio/ByteBuffer;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1AesGcmSetExtIV_1fips__Lcom_wolfssl_wolfcrypt_Aes_2Ljava_nio_ByteBuffer_2J
  (JNIEnv *, jclass, jobject, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_AesGcmSetExtIV_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Aes;[BJ)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1AesGcmSetExtIV_1fips__Lcom_wolfssl_wolfcrypt_Aes_2_3BJ
  (JNIEnv *, jclass, jobject, jbyteArray, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_AesGcmEncrypt_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Aes;Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;JLjava/nio/ByteBuffer;JLjava/nio/ByteBuffer;JLjava/nio/ByteBuffer;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1AesGcmEncrypt_1fips__Lcom_wolfssl_wolfcrypt_Aes_2Ljava_nio_ByteBuffer_2Ljava_nio_ByteBuffer_2JLjava_nio_ByteBuffer_2JLjava_nio_ByteBuffer_2JLjava_nio_ByteBuffer_2J
  (JNIEnv *, jclass, jobject, jobject, jobject, jlong, jobject, jlong, jobject, jlong, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_AesGcmEncrypt_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Aes;[B[BJ[BJ[BJ[BJ)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1AesGcmEncrypt_1fips__Lcom_wolfssl_wolfcrypt_Aes_2_3B_3BJ_3BJ_3BJ_3BJ
  (JNIEnv *, jclass, jobject, jbyteArray, jbyteArray, jlong, jbyteArray, jlong, jbyteArray, jlong, jbyteArray, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_AesGcmDecrypt_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Aes;Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;JLjava/nio/ByteBuffer;JLjava/nio/ByteBuffer;JLjava/nio/ByteBuffer;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1AesGcmDecrypt_1fips__Lcom_wolfssl_wolfcrypt_Aes_2Ljava_nio_ByteBuffer_2Ljava_nio_ByteBuffer_2JLjava_nio_ByteBuffer_2JLjava_nio_ByteBuffer_2JLjava_nio_ByteBuffer_2J
  (JNIEnv *, jclass, jobject, jobject, jobject, jlong, jobject, jlong, jobject, jlong, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_AesGcmDecrypt_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Aes;[B[BJ[BJ[BJ[BJ)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1AesGcmDecrypt_1fips__Lcom_wolfssl_wolfcrypt_Aes_2_3B_3BJ_3BJ_3BJ_3BJ
  (JNIEnv *, jclass, jobject, jbyteArray, jbyteArray, jlong, jbyteArray, jlong, jbyteArray, jlong, jbyteArray, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Des3_SetKey_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Des3;Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;I)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Des3_1SetKey_1fips__Lcom_wolfssl_wolfcrypt_Des3_2Ljava_nio_ByteBuffer_2Ljava_nio_ByteBuffer_2I
  (JNIEnv *, jclass, jobject, jobject, jobject, jint);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Des3_SetKey_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Des3;[B[BI)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Des3_1SetKey_1fips__Lcom_wolfssl_wolfcrypt_Des3_2_3B_3BI
  (JNIEnv *, jclass, jobject, jbyteArray, jbyteArray, jint);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Des3_SetIV_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Des3;Ljava/nio/ByteBuffer;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Des3_1SetIV_1fips__Lcom_wolfssl_wolfcrypt_Des3_2Ljava_nio_ByteBuffer_2
  (JNIEnv *, jclass, jobject, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Des3_SetIV_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Des3;[B)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Des3_1SetIV_1fips__Lcom_wolfssl_wolfcrypt_Des3_2_3B
  (JNIEnv *, jclass, jobject, jbyteArray);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Des3_CbcEncrypt_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Des3;Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Des3_1CbcEncrypt_1fips__Lcom_wolfssl_wolfcrypt_Des3_2Ljava_nio_ByteBuffer_2Ljava_nio_ByteBuffer_2J
  (JNIEnv *, jclass, jobject, jobject, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Des3_CbcEncrypt_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Des3;[B[BJ)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Des3_1CbcEncrypt_1fips__Lcom_wolfssl_wolfcrypt_Des3_2_3B_3BJ
  (JNIEnv *, jclass, jobject, jbyteArray, jbyteArray, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Des3_CbcDecrypt_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Des3;Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Des3_1CbcDecrypt_1fips__Lcom_wolfssl_wolfcrypt_Des3_2Ljava_nio_ByteBuffer_2Ljava_nio_ByteBuffer_2J
  (JNIEnv *, jclass, jobject, jobject, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Des3_CbcDecrypt_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Des3;[B[BJ)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Des3_1CbcDecrypt_1fips__Lcom_wolfssl_wolfcrypt_Des3_2_3B_3BJ
  (JNIEnv *, jclass, jobject, jbyteArray, jbyteArray, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_HmacSetKey_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Hmac;ILjava/nio/ByteBuffer;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1HmacSetKey_1fips__Lcom_wolfssl_wolfcrypt_Hmac_2ILjava_nio_ByteBuffer_2J
  (JNIEnv *, jclass, jobject, jint, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_HmacSetKey_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Hmac;I[BJ)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1HmacSetKey_1fips__Lcom_wolfssl_wolfcrypt_Hmac_2I_3BJ
  (JNIEnv *, jclass, jobject, jint, jbyteArray, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_HmacUpdate_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Hmac;Ljava/nio/ByteBuffer;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1HmacUpdate_1fips__Lcom_wolfssl_wolfcrypt_Hmac_2Ljava_nio_ByteBuffer_2J
  (JNIEnv *, jclass, jobject, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_HmacUpdate_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Hmac;[BJ)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1HmacUpdate_1fips__Lcom_wolfssl_wolfcrypt_Hmac_2_3BJ
  (JNIEnv *, jclass, jobject, jbyteArray, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_HmacFinal_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Hmac;Ljava/nio/ByteBuffer;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1HmacFinal_1fips__Lcom_wolfssl_wolfcrypt_Hmac_2Ljava_nio_ByteBuffer_2
  (JNIEnv *, jclass, jobject, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_HmacFinal_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Hmac;[B)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1HmacFinal_1fips__Lcom_wolfssl_wolfcrypt_Hmac_2_3B
  (JNIEnv *, jclass, jobject, jbyteArray);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_InitRng_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Rng;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1InitRng_1fips
  (JNIEnv *, jclass, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_FreeRng_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Rng;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1FreeRng_1fips
  (JNIEnv *, jclass, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_RNG_GenerateBlock_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Rng;Ljava/nio/ByteBuffer;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1RNG_1GenerateBlock_1fips__Lcom_wolfssl_wolfcrypt_Rng_2Ljava_nio_ByteBuffer_2J
  (JNIEnv *, jclass, jobject, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_RNG_GenerateBlock_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Rng;[BJ)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1RNG_1GenerateBlock_1fips__Lcom_wolfssl_wolfcrypt_Rng_2_3BJ
  (JNIEnv *, jclass, jobject, jbyteArray, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_RNG_HealthTest_fips
 * Signature: (ILjava/nio/ByteBuffer;JLjava/nio/ByteBuffer;JLjava/nio/ByteBuffer;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1RNG_1HealthTest_1fips__ILjava_nio_ByteBuffer_2JLjava_nio_ByteBuffer_2JLjava_nio_ByteBuffer_2J
  (JNIEnv *, jclass, jint, jobject, jlong, jobject, jlong, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_RNG_HealthTest_fips
 * Signature: (I[BJ[BJ[BJ)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1RNG_1HealthTest_1fips__I_3BJ_3BJ_3BJ
  (JNIEnv *, jclass, jint, jbyteArray, jlong, jbyteArray, jlong, jbyteArray, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_InitRsaKey_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Rsa;Ljava/nio/ByteBuffer;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1InitRsaKey_1fips
  (JNIEnv *, jclass, jobject, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_FreeRsaKey_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Rsa;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1FreeRsaKey_1fips
  (JNIEnv *, jclass, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_RsaSSL_Sign_fips
 * Signature: (Ljava/nio/ByteBuffer;JLjava/nio/ByteBuffer;JLcom/wolfssl/wolfcrypt/Rsa;Lcom/wolfssl/wolfcrypt/Rng;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1RsaSSL_1Sign_1fips__Ljava_nio_ByteBuffer_2JLjava_nio_ByteBuffer_2JLcom_wolfssl_wolfcrypt_Rsa_2Lcom_wolfssl_wolfcrypt_Rng_2
  (JNIEnv *, jclass, jobject, jlong, jobject, jlong, jobject, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_RsaSSL_Sign_fips
 * Signature: ([BJ[BJLcom/wolfssl/wolfcrypt/Rsa;Lcom/wolfssl/wolfcrypt/Rng;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1RsaSSL_1Sign_1fips___3BJ_3BJLcom_wolfssl_wolfcrypt_Rsa_2Lcom_wolfssl_wolfcrypt_Rng_2
  (JNIEnv *, jclass, jbyteArray, jlong, jbyteArray, jlong, jobject, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_RsaSSL_Verify_fips
 * Signature: (Ljava/nio/ByteBuffer;JLjava/nio/ByteBuffer;JLcom/wolfssl/wolfcrypt/Rsa;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1RsaSSL_1Verify_1fips__Ljava_nio_ByteBuffer_2JLjava_nio_ByteBuffer_2JLcom_wolfssl_wolfcrypt_Rsa_2
  (JNIEnv *, jclass, jobject, jlong, jobject, jlong, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_RsaSSL_Verify_fips
 * Signature: ([BJ[BJLcom/wolfssl/wolfcrypt/Rsa;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1RsaSSL_1Verify_1fips___3BJ_3BJLcom_wolfssl_wolfcrypt_Rsa_2
  (JNIEnv *, jclass, jbyteArray, jlong, jbyteArray, jlong, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_RsaEncryptSize_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Rsa;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1RsaEncryptSize_1fips
  (JNIEnv *, jclass, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_RsaPrivateKeyDecode_fips
 * Signature: (Ljava/nio/ByteBuffer;[JLcom/wolfssl/wolfcrypt/Rsa;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1RsaPrivateKeyDecode_1fips__Ljava_nio_ByteBuffer_2_3JLcom_wolfssl_wolfcrypt_Rsa_2J
  (JNIEnv *, jclass, jobject, jlongArray, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_RsaPrivateKeyDecode_fips
 * Signature: ([B[JLcom/wolfssl/wolfcrypt/Rsa;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1RsaPrivateKeyDecode_1fips___3B_3JLcom_wolfssl_wolfcrypt_Rsa_2J
  (JNIEnv *, jclass, jbyteArray, jlongArray, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_RsaPublicKeyDecode_fips
 * Signature: (Ljava/nio/ByteBuffer;[JLcom/wolfssl/wolfcrypt/Rsa;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1RsaPublicKeyDecode_1fips__Ljava_nio_ByteBuffer_2_3JLcom_wolfssl_wolfcrypt_Rsa_2J
  (JNIEnv *, jclass, jobject, jlongArray, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_RsaPublicKeyDecode_fips
 * Signature: ([B[JLcom/wolfssl/wolfcrypt/Rsa;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1RsaPublicKeyDecode_1fips___3B_3JLcom_wolfssl_wolfcrypt_Rsa_2J
  (JNIEnv *, jclass, jbyteArray, jlongArray, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_InitSha_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Sha;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1InitSha_1fips
  (JNIEnv *, jclass, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_ShaUpdate_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Sha;Ljava/nio/ByteBuffer;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1ShaUpdate_1fips__Lcom_wolfssl_wolfcrypt_Sha_2Ljava_nio_ByteBuffer_2J
  (JNIEnv *, jclass, jobject, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_ShaUpdate_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Sha;[BJ)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1ShaUpdate_1fips__Lcom_wolfssl_wolfcrypt_Sha_2_3BJ
  (JNIEnv *, jclass, jobject, jbyteArray, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_ShaFinal_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Sha;Ljava/nio/ByteBuffer;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1ShaFinal_1fips__Lcom_wolfssl_wolfcrypt_Sha_2Ljava_nio_ByteBuffer_2
  (JNIEnv *, jclass, jobject, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_ShaFinal_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Sha;[B)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1ShaFinal_1fips__Lcom_wolfssl_wolfcrypt_Sha_2_3B
  (JNIEnv *, jclass, jobject, jbyteArray);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_InitSha256_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Sha256;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1InitSha256_1fips
  (JNIEnv *, jclass, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Sha256Update_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Sha256;Ljava/nio/ByteBuffer;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Sha256Update_1fips__Lcom_wolfssl_wolfcrypt_Sha256_2Ljava_nio_ByteBuffer_2J
  (JNIEnv *, jclass, jobject, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Sha256Update_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Sha256;[BJ)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Sha256Update_1fips__Lcom_wolfssl_wolfcrypt_Sha256_2_3BJ
  (JNIEnv *, jclass, jobject, jbyteArray, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Sha256Final_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Sha256;Ljava/nio/ByteBuffer;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Sha256Final_1fips__Lcom_wolfssl_wolfcrypt_Sha256_2Ljava_nio_ByteBuffer_2
  (JNIEnv *, jclass, jobject, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Sha256Final_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Sha256;[B)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Sha256Final_1fips__Lcom_wolfssl_wolfcrypt_Sha256_2_3B
  (JNIEnv *, jclass, jobject, jbyteArray);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_InitSha384_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Sha384;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1InitSha384_1fips
  (JNIEnv *, jclass, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Sha384Update_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Sha384;Ljava/nio/ByteBuffer;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Sha384Update_1fips__Lcom_wolfssl_wolfcrypt_Sha384_2Ljava_nio_ByteBuffer_2J
  (JNIEnv *, jclass, jobject, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Sha384Update_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Sha384;[BJ)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Sha384Update_1fips__Lcom_wolfssl_wolfcrypt_Sha384_2_3BJ
  (JNIEnv *, jclass, jobject, jbyteArray, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Sha384Final_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Sha384;Ljava/nio/ByteBuffer;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Sha384Final_1fips__Lcom_wolfssl_wolfcrypt_Sha384_2Ljava_nio_ByteBuffer_2
  (JNIEnv *, jclass, jobject, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Sha384Final_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Sha384;[B)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Sha384Final_1fips__Lcom_wolfssl_wolfcrypt_Sha384_2_3B
  (JNIEnv *, jclass, jobject, jbyteArray);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_InitSha512_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Sha512;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1InitSha512_1fips
  (JNIEnv *, jclass, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Sha512Update_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Sha512;Ljava/nio/ByteBuffer;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Sha512Update_1fips__Lcom_wolfssl_wolfcrypt_Sha512_2Ljava_nio_ByteBuffer_2J
  (JNIEnv *, jclass, jobject, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Sha512Update_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Sha512;[BJ)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Sha512Update_1fips__Lcom_wolfssl_wolfcrypt_Sha512_2_3BJ
  (JNIEnv *, jclass, jobject, jbyteArray, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Sha512Final_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Sha512;Ljava/nio/ByteBuffer;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Sha512Final_1fips__Lcom_wolfssl_wolfcrypt_Sha512_2Ljava_nio_ByteBuffer_2
  (JNIEnv *, jclass, jobject, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Sha512Final_fips
 * Signature: (Lcom/wolfssl/wolfcrypt/Sha512;[B)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Sha512Final_1fips__Lcom_wolfssl_wolfcrypt_Sha512_2_3B
  (JNIEnv *, jclass, jobject, jbyteArray);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_RsaPublicEncrypt_fips
 * Signature: (Ljava/nio/ByteBuffer;JLjava/nio/ByteBuffer;JLcom/wolfssl/wolfcrypt/Rsa;Lcom/wolfssl/wolfcrypt/Rng;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1RsaPublicEncrypt_1fips__Ljava_nio_ByteBuffer_2JLjava_nio_ByteBuffer_2JLcom_wolfssl_wolfcrypt_Rsa_2Lcom_wolfssl_wolfcrypt_Rng_2
  (JNIEnv *, jclass, jobject, jlong, jobject, jlong, jobject, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_RsaPublicEncrypt_fips
 * Signature: ([BJ[BJLcom/wolfssl/wolfcrypt/Rsa;Lcom/wolfssl/wolfcrypt/Rng;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1RsaPublicEncrypt_1fips___3BJ_3BJLcom_wolfssl_wolfcrypt_Rsa_2Lcom_wolfssl_wolfcrypt_Rng_2
  (JNIEnv *, jclass, jbyteArray, jlong, jbyteArray, jlong, jobject, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_RsaPrivateDecrypt_fips
 * Signature: (Ljava/nio/ByteBuffer;JLjava/nio/ByteBuffer;JLcom/wolfssl/wolfcrypt/Rsa;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1RsaPrivateDecrypt_1fips__Ljava_nio_ByteBuffer_2JLjava_nio_ByteBuffer_2JLcom_wolfssl_wolfcrypt_Rsa_2
  (JNIEnv *, jclass, jobject, jlong, jobject, jlong, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_RsaPrivateDecrypt_fips
 * Signature: ([BJ[BJLcom/wolfssl/wolfcrypt/Rsa;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1RsaPrivateDecrypt_1fips___3BJ_3BJLcom_wolfssl_wolfcrypt_Rsa_2
  (JNIEnv *, jclass, jbyteArray, jlong, jbyteArray, jlong, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_InitMd5
 * Signature: (Lcom/wolfssl/wolfcrypt/Md5;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1InitMd5
  (JNIEnv *, jclass, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Md5Update
 * Signature: (Lcom/wolfssl/wolfcrypt/Md5;Ljava/nio/ByteBuffer;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Md5Update__Lcom_wolfssl_wolfcrypt_Md5_2Ljava_nio_ByteBuffer_2J
  (JNIEnv *, jclass, jobject, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Md5Update
 * Signature: (Lcom/wolfssl/wolfcrypt/Md5;[BJ)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Md5Update__Lcom_wolfssl_wolfcrypt_Md5_2_3BJ
  (JNIEnv *, jclass, jobject, jbyteArray, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Md5Final
 * Signature: (Lcom/wolfssl/wolfcrypt/Md5;Ljava/nio/ByteBuffer;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Md5Final__Lcom_wolfssl_wolfcrypt_Md5_2Ljava_nio_ByteBuffer_2
  (JNIEnv *, jclass, jobject, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_Md5Final
 * Signature: (Lcom/wolfssl/wolfcrypt/Md5;[B)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1Md5Final__Lcom_wolfssl_wolfcrypt_Md5_2_3B
  (JNIEnv *, jclass, jobject, jbyteArray);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_InitDhKey
 * Signature: (Lcom/wolfssl/wolfcrypt/Dh;)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1InitDhKey
  (JNIEnv *, jclass, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_FreeDhKey
 * Signature: (Lcom/wolfssl/wolfcrypt/Dh;)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1FreeDhKey
  (JNIEnv *, jclass, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_DhGenerateKeyPair
 * Signature: (Lcom/wolfssl/wolfcrypt/Dh;Lcom/wolfssl/wolfcrypt/Rng;Ljava/nio/ByteBuffer;[JLjava/nio/ByteBuffer;[J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1DhGenerateKeyPair__Lcom_wolfssl_wolfcrypt_Dh_2Lcom_wolfssl_wolfcrypt_Rng_2Ljava_nio_ByteBuffer_2_3JLjava_nio_ByteBuffer_2_3J
  (JNIEnv *, jclass, jobject, jobject, jobject, jlongArray, jobject, jlongArray);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_DhGenerateKeyPair
 * Signature: (Lcom/wolfssl/wolfcrypt/Dh;Lcom/wolfssl/wolfcrypt/Rng;[B[J[B[J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1DhGenerateKeyPair__Lcom_wolfssl_wolfcrypt_Dh_2Lcom_wolfssl_wolfcrypt_Rng_2_3B_3J_3B_3J
  (JNIEnv *, jclass, jobject, jobject, jbyteArray, jlongArray, jbyteArray, jlongArray);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_DhAgree
 * Signature: (Lcom/wolfssl/wolfcrypt/Dh;Ljava/nio/ByteBuffer;[JLjava/nio/ByteBuffer;JLjava/nio/ByteBuffer;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1DhAgree__Lcom_wolfssl_wolfcrypt_Dh_2Ljava_nio_ByteBuffer_2_3JLjava_nio_ByteBuffer_2JLjava_nio_ByteBuffer_2J
  (JNIEnv *, jclass, jobject, jobject, jlongArray, jobject, jlong, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_DhAgree
 * Signature: (Lcom/wolfssl/wolfcrypt/Dh;[B[J[BJ[BJ)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1DhAgree__Lcom_wolfssl_wolfcrypt_Dh_2_3B_3J_3BJ_3BJ
  (JNIEnv *, jclass, jobject, jbyteArray, jlongArray, jbyteArray, jlong, jbyteArray, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_DhKeyDecode
 * Signature: (Ljava/nio/ByteBuffer;[JLcom/wolfssl/wolfcrypt/Dh;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1DhKeyDecode__Ljava_nio_ByteBuffer_2_3JLcom_wolfssl_wolfcrypt_Dh_2J
  (JNIEnv *, jclass, jobject, jlongArray, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_DhKeyDecode
 * Signature: ([B[JLcom/wolfssl/wolfcrypt/Dh;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1DhKeyDecode___3B_3JLcom_wolfssl_wolfcrypt_Dh_2J
  (JNIEnv *, jclass, jbyteArray, jlongArray, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_DhSetKey
 * Signature: (Lcom/wolfssl/wolfcrypt/Dh;Ljava/nio/ByteBuffer;JLjava/nio/ByteBuffer;J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1DhSetKey__Lcom_wolfssl_wolfcrypt_Dh_2Ljava_nio_ByteBuffer_2JLjava_nio_ByteBuffer_2J
  (JNIEnv *, jclass, jobject, jobject, jlong, jobject, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_DhSetKey
 * Signature: (Lcom/wolfssl/wolfcrypt/Dh;[BJ[BJ)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1DhSetKey__Lcom_wolfssl_wolfcrypt_Dh_2_3BJ_3BJ
  (JNIEnv *, jclass, jobject, jbyteArray, jlong, jbyteArray, jlong);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_DhParamsLoad
 * Signature: (Ljava/nio/ByteBuffer;JLjava/nio/ByteBuffer;[JLjava/nio/ByteBuffer;[J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1DhParamsLoad__Ljava_nio_ByteBuffer_2JLjava_nio_ByteBuffer_2_3JLjava_nio_ByteBuffer_2_3J
  (JNIEnv *, jclass, jobject, jlong, jobject, jlongArray, jobject, jlongArray);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_DhParamsLoad
 * Signature: ([BJ[B[J[B[J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1DhParamsLoad___3BJ_3B_3J_3B_3J
  (JNIEnv *, jclass, jbyteArray, jlong, jbyteArray, jlongArray, jbyteArray, jlongArray);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_ecc_init
 * Signature: (Lcom/wolfssl/wolfcrypt/Ecc;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1ecc_1init
  (JNIEnv *, jclass, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_ecc_free
 * Signature: (Lcom/wolfssl/wolfcrypt/Ecc;)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1ecc_1free
  (JNIEnv *, jclass, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_ecc_make_key
 * Signature: (Lcom/wolfssl/wolfcrypt/Rng;ILcom/wolfssl/wolfcrypt/Ecc;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1ecc_1make_1key
  (JNIEnv *, jclass, jobject, jint, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_ecc_shared_secret
 * Signature: (Lcom/wolfssl/wolfcrypt/Ecc;Lcom/wolfssl/wolfcrypt/Ecc;Ljava/nio/ByteBuffer;[J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1ecc_1shared_1secret__Lcom_wolfssl_wolfcrypt_Ecc_2Lcom_wolfssl_wolfcrypt_Ecc_2Ljava_nio_ByteBuffer_2_3J
  (JNIEnv *, jclass, jobject, jobject, jobject, jlongArray);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_ecc_shared_secret
 * Signature: (Lcom/wolfssl/wolfcrypt/Ecc;Lcom/wolfssl/wolfcrypt/Ecc;[B[J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1ecc_1shared_1secret__Lcom_wolfssl_wolfcrypt_Ecc_2Lcom_wolfssl_wolfcrypt_Ecc_2_3B_3J
  (JNIEnv *, jclass, jobject, jobject, jbyteArray, jlongArray);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_ecc_import_x963
 * Signature: (Ljava/nio/ByteBuffer;JLcom/wolfssl/wolfcrypt/Ecc;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1ecc_1import_1x963__Ljava_nio_ByteBuffer_2JLcom_wolfssl_wolfcrypt_Ecc_2
  (JNIEnv *, jclass, jobject, jlong, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_ecc_import_x963
 * Signature: ([BJLcom/wolfssl/wolfcrypt/Ecc;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1ecc_1import_1x963___3BJLcom_wolfssl_wolfcrypt_Ecc_2
  (JNIEnv *, jclass, jbyteArray, jlong, jobject);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_ecc_export_x963
 * Signature: (Lcom/wolfssl/wolfcrypt/Ecc;Ljava/nio/ByteBuffer;[J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1ecc_1export_1x963__Lcom_wolfssl_wolfcrypt_Ecc_2Ljava_nio_ByteBuffer_2_3J
  (JNIEnv *, jclass, jobject, jobject, jlongArray);

/*
 * Class:     com_wolfssl_wolfcrypt_Fips
 * Method:    wc_ecc_export_x963
 * Signature: (Lcom/wolfssl/wolfcrypt/Ecc;[B[J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wc_1ecc_1export_1x963__Lcom_wolfssl_wolfcrypt_Ecc_2_3B_3J
  (JNIEnv *, jclass, jobject, jbyteArray, jlongArray);

#ifdef __cplusplus
}
#endif
#endif
