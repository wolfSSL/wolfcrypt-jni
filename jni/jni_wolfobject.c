/* jni_wolfobject.c
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

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#elif !defined(__ANDROID__)
    #include <wolfssl/options.h>
#endif
#include <jni.h>
#include <wolfcrypt_jni_debug.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#ifdef WC_RNG_SEED_CB
    #include <wolfssl/wolfcrypt/random.h>
#endif
#ifdef HAVE_FIPS
    #include <wolfssl/wolfcrypt/fips_test.h>
#endif

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_WolfObject_init
  (JNIEnv* jenv, jclass jcl)
{
    (void)jenv;
    (void)jcl;

    /* Code which runs the FIPS CASTs up front has been moved to the
     * com.wolfssl.wolfcrypt.Fips.runAllCast_fips() method. runAllCast_fips()
     * includes a synchronized check that only runs the CASTs once as long
     * as they were successful. Fips.runAllCast_fips() is called at both
     * the JNI-only level (WolfObject.init()), and the JCE level
     * (WolfCryptProvider constructor). Both of these runAllCast_fips()
     * at JNI/JCE levels are called before this wolfCrypt_Init() below. */

    return (jint)wolfCrypt_Init();
}

