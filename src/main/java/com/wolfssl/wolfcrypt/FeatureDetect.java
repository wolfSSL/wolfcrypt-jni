/* FeatureDetect.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

package com.wolfssl.wolfcrypt;

/**
 * Native feature detection class
 * Used to expose native preprocessor values to Java
 */
public class FeatureDetect {

    /**
     * Tests if MD5 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean Md5Enabled();

    /**
     * Tests if SHA-1 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean ShaEnabled();

    /**
     * Tests if SHA-224 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean Sha224Enabled();

    /**
     * Tests if SHA-256 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean Sha256Enabled();

    /**
     * Tests if SHA-384 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean Sha384Enabled();

    /**
     * Tests if SHA-512 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean Sha512Enabled();

    /**
     * Tests if SHA3 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean Sha3Enabled();

    /**
     * Tests if AES is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean AesEnabled();

    /**
     * Tests if AES-128 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean Aes128Enabled();

    /**
     * Tests if AES-192 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean Aes192Enabled();

    /**
     * Tests if AES-256 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean Aes256Enabled();

    /**
     * Tests if AES-CBC is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean AesCbcEnabled();


    /**
     * Tests if AES-CTR is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean AesCtrEnabled();

    /**
     * Tests if AES-ECB is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean AesEcbEnabled();

    /**
     * Tests if AES-OFB is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean AesOfbEnabled();

    /**
     * Tests if AES decrypt functionality (HAVE_AES_DECRYPT) is compiled into
     * the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean AesDecryptEnabled();

    /**
     * Tests if AES-GCM is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean AesGcmEnabled();

    /**
     * Tests if AES-GCM stream mode (WOLFSSL_AESGCM_STREAM) is compiled into
     * native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean AesGcmStreamEnabled();

    /**
     * Tests if AES-CCM is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean AesCcmEnabled();

    /**
     * Tests if AES-CTS is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean AesCtsEnabled();

    /**
     * Tests if AES-CMAC is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean AesCmacEnabled();

    /**
     * Tests if AES-GMAC is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean AesGmacEnabled();

    /**
     * Tests if 3DES is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean Des3Enabled();

    /**
     * Tests if ChaCha is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean ChaChaEnabled();

    /**
     * Tests if HMAC is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false.
     */
    public static native boolean HmacEnabled();

    /**
     * Tests if HMAC-MD5 is compiled into the native wolfSSL library and
     * available for use.
     *
     * For FIPS 140-3, even if MD5 is compiled into the
     * library, HMAC-MD5 is not available and will throw BAD_FUNC_ARG.
     * Use this helper to prevent people from calling it in the first place.
     *
     * @return true if enabled, otherwise false.
     */
    public static native boolean HmacMd5Enabled();

    /**
     * Tests if HMAC-SHA1 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false.
     */
    public static native boolean HmacShaEnabled();

    /**
     * Tests if HMAC-SHA224 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false.
     */
    public static native boolean HmacSha224Enabled();

    /**
     * Tests if HMAC-SHA256 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false.
     */
    public static native boolean HmacSha256Enabled();

    /**
     * Tests if HMAC-SHA384 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false.
     */
    public static native boolean HmacSha384Enabled();

    /**
     * Tests if HMAC-SHA512 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false.
     */
    public static native boolean HmacSha512Enabled();

    /**
     * Tests if HMAC-SHA3-224 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false.
     */
    public static native boolean HmacSha3_224Enabled();

    /**
     * Tests if HMAC-SHA3-256 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false.
     */
    public static native boolean HmacSha3_256Enabled();

    /**
     * Tests if HMAC-SHA3-384 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false.
     */
    public static native boolean HmacSha3_384Enabled();

    /**
     * Tests if HMAC-SHA3-512 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false.
     */
    public static native boolean HmacSha3_512Enabled();

    /**
     * Tests if PKCS#5 PBKDF1 is compiled into the native wolfSSL library.
     *
     * @return true if PBKDF1 is enabled (HAVE_PBKDF1, !NO_PWDBASED),
     *         otherwise false.
     */
    public static native boolean Pbkdf1Enabled();

    /**
     * Tests if PKCS#5 v2.1 PBKDF2 is compiled into the native wolfSSL library.
     *
     * @return true if PBKDF2 is enabled (HAVE_PBKDF2, !NO_PWDBASED, !NO_HMAC),
     *         otherwise false.
     */
    public static native boolean Pbkdf2Enabled();

    /**
     * Tests if PKCS#12 PBKDF is compiled into the native wolfSSL library.
     *
     * @return true if PKCS#12 PBKDF is enabled (HAVE_PKCS12, !NO_PWDBASED),
     *         otherwise false.
     */
    public static native boolean Pkcs12PbkdfEnabled();

    /**
     * Tests if RSA is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean RsaEnabled();

    /**
     * Tests if RSA key generation is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean RsaKeyGenEnabled();

    /**
     * Tests if RSA-PSS is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean RsaPssEnabled();

    /**
     * Tests if RSA-OAEP is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean RsaOaepEnabled();

    /**
     * Tests if DH is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean DhEnabled();

    /**
     * Tests if WOLFSSL_DH_EXTRA is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean DhExtraEnabled();

    /**
     * Tests if ECC is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean EccEnabled();

    /**
     * Tests if ECC key generation is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean EccKeyGenEnabled();

    /**
     * Tests if ECDHE / wc_ecc_shared_secret() is compiled into the native
     * wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean EccDheEnabled();

    /**
     * Tests if Curve25519 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean Curve25519Enabled();

    /**
     * Tests if Ed25519 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean Ed25519Enabled();

    /**
     * Tests if WOLFSSL_PUBLIC_MP is defined in the native wolfSSL library.
     *
     * @return true if WOLFSSL_PUBLIC_MP is defined, otherwise false.
     */
    public static native boolean WolfSSLPublicMpEnabled();

    /**
     * Tests if ML-KEM (FIPS 203) is compiled into the native wolfSSL library.
     *
     * @return true if enabled (WOLFSSL_HAVE_MLKEM), otherwise false if not
     *         compiled in.
     */
    public static native boolean MlKemEnabled();

    /**
     * Tests if ML-DSA (FIPS 204, formerly Dilithium) is compiled into the
     * native wolfSSL library.
     *
     * @return true if enabled (HAVE_DILITHIUM), otherwise false if not
     *         compiled in.
     */
    public static native boolean MlDsaEnabled();

    /**
     * Tests if SLH-DSA (FIPS 205) is compiled into the native wolfSSL
     * library.
     *
     * @return true if enabled (WOLFSSL_HAVE_SLHDSA), otherwise false if not
     *         compiled in.
     */
    public static native boolean SlhDsaEnabled();

    /**
     * Tests if SLH-DSA (FIPS 205) key generation and signing are compiled
     * into the native wolfSSL library. False on verify-only native builds.
     *
     * @return true if enabled (WOLFSSL_HAVE_SLHDSA without
     *         WOLFSSL_SLHDSA_VERIFY_ONLY), otherwise false if not
     *         compiled in.
     */
    public static native boolean SlhDsaKeyGenEnabled();

    /**
     * Tests if given ML-DSA level is compiled into native wolfSSL.
     *
     * Probes native key initialization at runtime, so the result exactly
     * matches what key operations will accept, including level-restricted
     * native wolfSSL builds.
     *
     * @param level ML-DSA level, one of MlDsa.ML_DSA_44/65/87
     *
     * @return true if the level is compiled in and usable, otherwise false
     */
    public static native boolean MlDsaLevelEnabled(int level);

    /**
     * Tests if given SLH-DSA parameter set is compiled into native wolfSSL.
     *
     * Probes native key initialization at runtime, so the result exactly
     * matches what key operations will accept, including parameter set
     * restricted native wolfSSL builds (ex: --enable-slhdsa=128f,sha2-128f).
     *
     * @param param SLH-DSA parameter set, one of SlhDsa.SLH_DSA_*
     *
     * @return true if the parameter set is compiled in and usable,
     *         otherwise false
     */
    public static native boolean SlhDsaParamEnabled(int param);

    /**
     * Tests if LMS/HSS (RFC 8554) is compiled into the native wolfSSL
     * library.
     *
     * @return true if enabled (WOLFSSL_HAVE_LMS), otherwise false if not
     *         compiled in.
     */
    public static native boolean LmsEnabled();

    /**
     * Tests if XMSS/XMSS^MT (RFC 8391) is compiled into the native wolfSSL
     * library.
     *
     * @return true if enabled (WOLFSSL_HAVE_XMSS), otherwise false if not
     *         compiled in.
     */
    public static native boolean XmssEnabled();

    /**
     * Loads JNI library.
     *
     * The native library is expected to be called "wolfcryptjni", and must be
     * on the system library search path.
     *
     * "wolfcryptjni" links against the wolfSSL native C library ("wolfssl"),
     * and for Windows compatibility "wolfssl" needs to be explicitly loaded
     * first here.
     *
     * Library loading can be skipped by setting the System property
     * "wolfssl.skipLibraryLoad" to "true". This allows applications to
     * load native libraries manually using System.load() before accessing
     * any wolfSSL classes.
     */
    static {
        int fipsLoaded = 0;

        String skipLoad = System.getProperty("wolfssl.skipLibraryLoad");
        if (skipLoad != null && skipLoad.equalsIgnoreCase("true")) {
            /* User indicated they will load native libraries manually */
        }
        else {
            String osName = System.getProperty("os.name");
            if (osName != null && osName.toLowerCase().contains("win")) {
                try {
                    /* Default wolfCrypt FIPS library on Windows is compiled
                     * as "wolfssl-fips" by Visual Studio solution */
                    System.loadLibrary("wolfssl-fips");
                    fipsLoaded = 1;
                } catch (UnsatisfiedLinkError e) {
                    /* wolfCrypt FIPS not available */
                }

                if (fipsLoaded == 0) {
                    /* FIPS library not loaded, try normal libwolfssl */
                    System.loadLibrary("wolfssl");
                }
            }

            /* Load wolfcryptjni library */
            System.loadLibrary("wolfcryptjni");
        }
    }

    /** Default FeatureDetect constructor */
    public FeatureDetect() { }
}

