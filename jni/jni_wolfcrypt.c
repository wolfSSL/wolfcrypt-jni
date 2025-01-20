/* jni_wolfcrypt.c
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

#include <stdint.h>

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#elif !defined(__ANDROID__)
    #include <wolfssl/options.h>
#endif

#include <wolfssl/wolfcrypt/types.h>
#include <com_wolfssl_wolfcrypt_WolfCrypt.h>
#include <wolfcrypt_jni_error.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1NONE
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_NONE;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1MD2
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_MD2;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1MD4
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_MD4;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1MD5
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_MD5;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1SHA
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_SHA;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1SHA224
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_SHA224;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1SHA256
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_SHA256;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1SHA384
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_SHA384;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1SHA512
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_SHA512;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1MD5_1SHA
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_MD5_SHA;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1SHA3_1224
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_SHA3_224;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1SHA3_1256
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_SHA3_256;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1SHA3_1384
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_SHA3_384;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_getWC_1HASH_1TYPE_1SHA3_1512
  (JNIEnv* env, jclass class)
{
    return WC_HASH_TYPE_SHA3_512;
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_wolfcrypt_WolfCrypt_CrlEnabled
  (JNIEnv* env, jclass jcl)
{
    (void)env;
    (void)jcl;

#ifdef HAVE_CRL
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

