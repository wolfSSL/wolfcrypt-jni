/* jni_logging.c
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

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/logging.h>

#include <com_wolfssl_wolfcrypt_Logging.h>

int wolfSSL_Debugging_ON(void);
void wolfSSL_Debugging_OFF(void);

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Logging_wolfSSL_1Debugging_1ON
  (JNIEnv* env, jclass class)
{
    return wolfSSL_Debugging_ON();
}

JNIEXPORT void JNICALL Java_com_wolfssl_wolfcrypt_Logging_wolfSSL_1Debugging_1OFF
  (JNIEnv* env, jclass class)
{
    wolfSSL_Debugging_OFF();
}
