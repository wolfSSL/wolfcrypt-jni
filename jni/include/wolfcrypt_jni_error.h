/* wolfcrypt_jni_error.h
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
 *
 * This file is part of wolfCrypt.
 *
 * wolfCrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfCrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef _Included_wolfcrypt_jni_error
#define _Included_wolfcrypt_jni_error

#ifndef USE_WINDOWS_API
    #pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
#endif

#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef __cplusplus
extern "C" {
#endif

void throwWolfCryptExceptionFromError(JNIEnv* env, int code);

#define throwWolfCryptException(env, msg) (*env)->ThrowNew(env, \
    (*env)->FindClass(env, "com/wolfssl/wolfcrypt/WolfCryptException"), msg)

#define throwNotCompiledInException(env) \
    throwWolfCryptExceptionFromError(env, NOT_COMPILED_IN)

#define throwOutOfMemoryException(env, msg) (*env)->ThrowNew(env, \
    (*env)->FindClass(env, "java/lang/OutOfMemoryError"), msg)

#ifdef __cplusplus
}
#endif
#endif
