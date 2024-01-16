/* jni_feature_detect.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

