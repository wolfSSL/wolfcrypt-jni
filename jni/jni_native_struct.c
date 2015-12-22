/* jni_native_struct.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
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

#include <com_wolfssl_wolfcrypt_NativeStruct.h>
#include <wolfcrypt_jni_NativeStruct.h>

#ifndef __ANDROID__
    #include <wolfssl/options.h>
#endif

#include <wolfssl/wolfcrypt/types.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"

JavaVM* g_vm = NULL;

/* called when native library is loaded */
jint JNI_OnLoad(JavaVM* vm, void* reserved)
{
    /* store JavaVM */
    g_vm = vm;
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_NativeStruct_xfree(
    JNIEnv* env, jobject this, jlong ptr)
{
    LogStr("Freeing (%p)\n", prt);

    XFREE((void*)ptr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

/*
 * Utilitary functions
 */
static void throwGetNativeStructError(JNIEnv* env)
{
    (*env)->ThrowNew(env,
        (*env)->FindClass(env, "com/wolfssl/wolfcrypt/WolfCryptException"),
        "Failed to retrieve native struct");
}

void* getNativeStruct(JNIEnv* env, jobject this)
{
    if (this) {
        jclass class = (*env)->GetObjectClass(env, this);
        jfieldID field = (*env)->GetFieldID(env, class, "pointer", "J");
        jlong nativeStruct = (*env)->GetLongField(env, this, field);

        if (!nativeStruct)
            throwGetNativeStructError(env);

        return (void*) nativeStruct;
    }

    return NULL;
}

byte* getDirectBufferAddress(JNIEnv* env, jobject buffer)
{
    return buffer ? (*env)->GetDirectBufferAddress(env, buffer) : NULL;
}

word32 getDirectBufferLimit(JNIEnv* env, jobject buffer)
{
    jclass class = (*env)->GetObjectClass(env, buffer);
    jmethodID method = (*env)->GetMethodID(env, class, "limit", "()I");

    return (word32) (*env)->CallIntMethod(env, buffer, method);
}

void setDirectBufferLimit(JNIEnv* env, jobject buffer, jint limit)
{
    jclass class = (*env)->GetObjectClass(env, buffer);
    jmethodID method = (*env)->GetMethodID(env, class, "limit",
        "(I)Ljava/nio/Buffer;");

    (*env)->CallObjectMethod(env, buffer, method, limit);
}

byte* getByteArray(JNIEnv* env, jbyteArray array)
{
    return array ? (byte*)(*env)->GetByteArrayElements(env, array, NULL) : NULL;
}

void releaseByteArray(JNIEnv* env, jbyteArray array, byte* elements, jint abort)
{
    if (elements)
        (*env)->ReleaseByteArrayElements(env, array, (jbyte*) elements,
            abort ? JNI_ABORT : 0);
}

word32 getByteArrayLength(JNIEnv* env, jbyteArray array)
{
    return array ? (*env)->GetArrayLength(env, array) : 0;
}
