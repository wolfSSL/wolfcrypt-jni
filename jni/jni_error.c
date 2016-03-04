/* jni_error.c
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef __ANDROID__
    #include <wolfssl/options.h>
#endif

#include <com_wolfssl_wolfcrypt_WolfCryptError.h>

#include <wolfssl/wolfcrypt/error-crypt.h>

JNIEXPORT jstring JNICALL Java_com_wolfssl_wolfcrypt_WolfCryptError_wc_1GetErrorString
  (JNIEnv* env, jclass obj, jint error)
{
    return (*env)->NewStringUTF(env, wc_GetErrorString(error));
}

