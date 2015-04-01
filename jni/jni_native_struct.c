#include <com_wolfssl_wolfcrypt_NativeStruct.h>
#include <wolfcrypt_jni_NativeStruct.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"

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

void setDirectBufferLimit(JNIEnv* env, jobject buffer, jint limit)
{
    jclass class = (*env)->GetObjectClass(env, buffer);
    jmethodID method = (*env)->GetMethodID(env, class,
                           "limit", "(I)Ljava/nio/Buffer;");

    (*env)->CallObjectMethod(env, buffer, method, limit);
}
