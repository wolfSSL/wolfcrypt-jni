/* wolfcrypt_jni_NativeStruct.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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
#include <wolfssl/wolfcrypt/types.h>

#ifndef _Included_wolfcrypt_jni_NativeStruct
#define _Included_wolfcrypt_jni_NativeStruct
#ifdef __cplusplus
extern "C" {
#endif

void* getNativeStruct(JNIEnv* env, jobject this);

void setByteArrayMember(
    JNIEnv* env, jobject this, const char* name, jobject value);

byte* getDirectBufferAddress(JNIEnv* env, jobject buffer);
word32 getDirectBufferLimit(JNIEnv* env, jobject buffer);
void setDirectBufferLimit(JNIEnv* env, jobject buffer, jint limit);

byte* getByteArray(JNIEnv* env, jbyteArray array);
void releaseByteArray(JNIEnv* env, jbyteArray array, byte* elements, jint abort);
word32 getByteArrayLength(JNIEnv* env, jbyteArray array);
void initializeNativeStruct(JNIEnv* env, jobject obj);

#ifdef __cplusplus
}
#endif
#endif
