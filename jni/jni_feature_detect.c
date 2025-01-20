/* jni_feature_detect.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#elif !defined(__ANDROID__)
    #include <wolfssl/options.h>
#endif
#include <jni.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_Md5Enabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#ifndef NO_MD5
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_ShaEnabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#ifndef NO_SHA
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_Sha224Enabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#ifdef WOLFSSL_SHA224
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_Sha256Enabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#ifndef NO_SHA256
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_Sha384Enabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#ifdef WOLFSSL_SHA384
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_Sha512Enabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#ifdef WOLFSSL_SHA512
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_AesEnabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if !defined(NO_AES)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_Aes128Enabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if !defined(NO_AES) && defined(WOLFSSL_AES_128)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_Aes192Enabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if !defined(NO_AES) && defined(WOLFSSL_AES_192)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_Aes256Enabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if !defined(NO_AES) && defined(WOLFSSL_AES_256)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_AesCbcEnabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if !defined(NO_AES) && defined(HAVE_AES_CBC)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_AesGcmEnabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if !defined(NO_AES) && defined(HAVE_AESGCM)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_AesGcmStreamEnabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if !defined(NO_AES) && defined(WOLFSSL_AESGCM_STREAM)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_Des3Enabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#ifndef NO_DES3
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_ChaChaEnabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#ifdef HAVE_CHACHA
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_HmacEnabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if !defined(NO_HMAC)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_HmacMd5Enabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if !defined(NO_HMAC) && !defined(NO_MD5) && FIPS_VERSION_LT(5,2)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_HmacShaEnabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if !defined(NO_HMAC) && !defined(NO_SHA)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_HmacSha224Enabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if !defined(NO_HMAC) && defined(WOLFSSL_SHA224)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_HmacSha256Enabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if !defined(NO_HMAC) && !defined(NO_SHA256)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_HmacSha384Enabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if !defined(NO_HMAC) && defined(WOLFSSL_SHA384)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_HmacSha512Enabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if !defined(NO_HMAC) && defined(WOLFSSL_SHA512)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_HmacSha3_1224Enabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if !defined(NO_HMAC) && defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_224)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_HmacSha3_1256Enabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if !defined(NO_HMAC) && defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_256)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_HmacSha3_1384Enabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if !defined(NO_HMAC) && defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_384)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_HmacSha3_1512Enabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if !defined(NO_HMAC) && defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_512)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_Pbkdf1Enabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if !defined(NO_PWDBASED) && defined(HAVE_PBKDF1)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_Pbkdf2Enabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if !defined(NO_PWDBASED) && defined(HAVE_PBKDF2) && !defined(NO_HMAC)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_Pkcs12PbkdfEnabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if !defined(NO_PWDBASED) && defined(HAVE_PKCS12)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_RsaEnabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#ifndef NO_RSA
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_RsaKeyGenEnabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_DhEnabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#ifndef NO_DH
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_EccEnabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#ifdef HAVE_ECC
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_EccKeyGenEnabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if defined(HAVE_ECC) && defined(WOLFSSL_KEY_GEN)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_EccDheEnabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#if defined(HAVE_ECC) && defined(HAVE_ECC_DHE)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_Curve25519Enabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#ifdef HAVE_CURVE25519
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_FeatureDetect_Ed25519Enabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;
#ifdef HAVE_ED25519
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

