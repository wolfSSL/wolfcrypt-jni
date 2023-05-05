/* jni_wolfobject.c
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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

    int ret = 0;

#ifdef WC_RNG_SEED_CB
    ret = wc_SetSeed_Cb(wc_GenerateSeed);
    if (ret != 0) {
        printf("wc_SetSeed_Cb() failed");
    }
#endif

#if defined(HAVE_FIPS) && defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION == 5)
    /* run FIPS 140-3 conditional algorithm self tests early to prevent
     * multi threaded issues later on */
    if (ret == 0) {
        ret = wc_RunCast_fips(FIPS_CAST_AES_CBC);
        if (ret != 0) {
            printf("AES-CBC CAST failed");
        }
    }
    if (ret == 0) {
        ret = wc_RunCast_fips(FIPS_CAST_AES_GCM);
        if (ret != 0) {
            printf("AES-GCM CAST failed");
        }
    }
    if (ret == 0) {
        ret = wc_RunCast_fips(FIPS_CAST_HMAC_SHA1);
        if (ret != 0) {
            printf("HMAC-SHA1 CAST failed");
        }
    }
    if (ret == 0) {
        ret = wc_RunCast_fips(FIPS_CAST_HMAC_SHA2_256);
        if (ret != 0) {
            printf("HMAC-SHA2-256 CAST failed");
        }
    }
    if (ret == 0) {
        ret = wc_RunCast_fips(FIPS_CAST_HMAC_SHA2_512);
        if (ret != 0) {
            printf("HMAC-SHA2-512 CAST failed");
        }
    }

    if (ret == 0) {
        ret = wc_RunCast_fips(FIPS_CAST_HMAC_SHA3_256);
        if (ret != 0) {
            printf("HMAC-SHA3-256 CAST failed");
        }
    }
    if (ret == 0) {
        ret = wc_RunCast_fips(FIPS_CAST_DRBG);
        if (ret != 0) {
            printf("Hash_DRBG CAST failed");
        }
    }
    if (ret == 0) {
        ret = wc_RunCast_fips(FIPS_CAST_RSA_SIGN_PKCS1v15);
        if (ret != 0) {
            printf("RSA sign CAST failed");
        }
    }
    if (ret == 0) {
        ret = wc_RunCast_fips(FIPS_CAST_ECC_PRIMITIVE_Z);
        if (ret != 0) {
            printf("ECC Primitive Z CAST failed");
        }
    }
    if (ret == 0) {
        ret = wc_RunCast_fips(FIPS_CAST_DH_PRIMITIVE_Z);
        if (ret != 0) {
            printf("DH Primitive Z CAST failed");
        }
    }
    if (ret == 0) {
        ret = wc_RunCast_fips(FIPS_CAST_ECDSA);
        if (ret != 0) {
            printf("ECDSA CAST failed");
        }
    }
    if (ret == 0) {
        ret = wc_RunCast_fips(FIPS_CAST_KDF_TLS12);
        if (ret != 0) {
            printf("KDF TLSv1.2 CAST failed");
        }
    }
    if (ret == 0) {
        ret = wc_RunCast_fips(FIPS_CAST_KDF_TLS13);
        if (ret != 0) {
            printf("KDF TLSv1.3 CAST failed");
        }
    }
    if (ret == 0) {
        ret = wc_RunCast_fips(FIPS_CAST_KDF_SSH);
        if (ret != 0) {
            printf("KDF SSHv2.0 CAST failed");
        }
    }
#endif

    if (ret < 0) {
        return ret;
    }

    return (jint)wolfCrypt_Init();
}

