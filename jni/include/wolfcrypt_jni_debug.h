/* wolfcrypt_jni_debug.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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

#ifndef _Included_wolfcrypt_jni_debug
#define _Included_wolfcrypt_jni_debug
#ifdef __cplusplus
extern "C" {
#endif

#ifdef WOLFCRYPT_JNI_DEBUG_ON

#define LogStr printf

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
