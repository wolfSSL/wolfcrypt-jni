/* wolfcrypt_jni_debug.h
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

#ifndef _Included_wolfcrypt_jni_debug
#define _Included_wolfcrypt_jni_debug
#ifdef __cplusplus
extern "C" {
#endif

#ifdef WOLFCRYPT_JNI_DEBUG_ON

    #include <wolfssl/wolfcrypt/types.h>

    #ifdef __ANDROID__
        #include <android/log.h>

        #ifndef WOLFCRYPTJNI_MAX_LOG_WIDTH
            #define WOLFCRYPTJNI_MAX_LOG_WIDTH 120
        #endif

        static void ANDROID_LOG(const char* fmt, ...)
        {
            va_list vlist;
            char msgStr[WOLFCRYPTJNI_MAX_LOG_WIDTH];

            va_start(vlist, fmt);
            XVSNPRINTF(msgStr, sizeof(msgStr), fmt, vlist);
            __android_log_print(ANDROID_LOG_VERBOSE, "[wolfCrypt JNI]",
                                "%s", msgStr);
            va_end(vlist);
        }
        #define LogStr ANDROID_LOG
    #else
        #define LogStr printf
    #endif

    static inline void LogHex(byte* data, word32 offset, word32 length)
    {
        #define LINE_LEN 16

        word32 i;

        printf("\t");

        if (!data) {
            printf("NULL\n");
            return;
        }

        data += offset;

        for (i = 0; i < LINE_LEN; i++) {
            if (i < length)
                printf("%02x ", data[i]);
            else
                printf("   ");
        }

        printf("| ");

        for (i = 0; i < LINE_LEN; i++)
            if (i < length)
                printf("%c", 31 < data[i] && data[i] < 127 ? data[i] : '.');

        printf("\n");

        if (length > LINE_LEN)
            LogHex(data, LINE_LEN, length - LINE_LEN);
    }

#else
    #define LogStr(...)
    #define LogHex(...)
#endif

#ifdef __cplusplus
}
#endif
#endif
