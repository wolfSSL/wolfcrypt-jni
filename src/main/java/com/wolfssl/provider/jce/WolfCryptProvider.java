/* wolfCryptProvider.java
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

package com.wolfssl.provider.jce;

import java.security.Provider;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.Fips;

/**
 * wolfCrypt JCE Provider implementation
 */
public final class WolfCryptProvider extends Provider {

    /**
     * Create new WolfCryptProvider object
     */
    public WolfCryptProvider() {
        super("wolfJCE", 1.5, "wolfCrypt JCE Provider");

        /* MessageDigest */
        if (FeatureDetect.Md5Enabled()) {
            put("MessageDigest.MD5",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestMd5");
        }
        if (FeatureDetect.ShaEnabled()) {
            put("MessageDigest.SHA",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha");
            put("MessageDigest.SHA-1",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha");
        }
        if (FeatureDetect.Sha256Enabled()) {
            put("MessageDigest.SHA-256",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha256");
        }
        if (FeatureDetect.Sha384Enabled()) {
            put("MessageDigest.SHA-384",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha384");
        }
        if (FeatureDetect.Sha512Enabled()) {
            put("MessageDigest.SHA-512",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha512");
        }

        /* SecureRandom */
        /* TODO: May need to add "SHA1PRNG" alias, other JCA consumemrs may
         * explicitly request it? Needs more testing. */
        put("SecureRandom.HashDRBG",
                "com.wolfssl.provider.jce.WolfCryptRandom");

        /* Signature */
        if (FeatureDetect.Md5Enabled()) {
            put("Signature.MD5withRSA",
                    "com.wolfssl.provider.jce.WolfCryptSignature$wcMD5wRSA");
        }
        if (FeatureDetect.ShaEnabled()) {
            put("Signature.SHA1withRSA",
                    "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA1wRSA");
            put("Signature.SHA1withECDSA",
                    "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA1wECDSA");
        }
        if (FeatureDetect.Sha256Enabled()) {
            put("Signature.SHA256withRSA",
                    "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA256wRSA");
            put("Signature.SHA256withECDSA",
                  "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA256wECDSA");
        }
        if (FeatureDetect.Sha384Enabled()) {
            put("Signature.SHA384withRSA",
                    "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA384wRSA");
            put("Signature.SHA384withECDSA",
                  "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA384wECDSA");
        }
        if (FeatureDetect.Sha512Enabled()) {
            put("Signature.SHA512withRSA",
                    "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA512wRSA");
            put("Signature.SHA512withECDSA",
                  "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA512wECDSA");
        }

        /* Mac */
        if (FeatureDetect.Md5Enabled()) {
            put("Mac.HmacMD5",
                    "com.wolfssl.provider.jce.WolfCryptMac$wcHmacMD5");
        }
        if (FeatureDetect.ShaEnabled()) {
            put("Mac.HmacSHA1",
                    "com.wolfssl.provider.jce.WolfCryptMac$wcHmacSHA1");
        }
        if (FeatureDetect.Sha256Enabled()) {
            put("Mac.HmacSHA256",
                    "com.wolfssl.provider.jce.WolfCryptMac$wcHmacSHA256");
        }
        if (FeatureDetect.Sha384Enabled()) {
            put("Mac.HmacSHA384",
                    "com.wolfssl.provider.jce.WolfCryptMac$wcHmacSHA384");
        }
        if (FeatureDetect.Sha512Enabled()) {
            put("Mac.HmacSHA512",
                    "com.wolfssl.provider.jce.WolfCryptMac$wcHmacSHA512");
        }

        /* Cipher */
        put("Cipher.AES/CBC/NoPadding",
                "com.wolfssl.provider.jce.WolfCryptCipher$wcAESCBCNoPadding");

        put("Cipher.DESede/CBC/NoPadding",
                "com.wolfssl.provider.jce.WolfCryptCipher$wcDESedeCBCNoPadding");

        put("Cipher.RSA/ECB/PKCS1Padding",
                "com.wolfssl.provider.jce.WolfCryptCipher$wcRSAECBPKCS1Padding");

        /* KeyAgreement */
        put("KeyAgreement.DiffieHellman",
                "com.wolfssl.provider.jce.WolfCryptKeyAgreement$wcDH");
        put("Alg.Alias.KeyAgreement.DH", "DiffieHellman");
        put("KeyAgreement.ECDH",
                "com.wolfssl.provider.jce.WolfCryptKeyAgreement$wcECDH");

        /* KeyPairGenerator */
        put("KeyPairGenerator.EC",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenECC");
        put("KeyPairGenerator.DH",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenDH");
        put("Alg.Alias.KeyPairGenerator.DiffieHellman", "DH");

        /* If using a FIPS version of wolfCrypt, allow private key to be
         * exported for use. Only applicable to FIPS 140-3 */
        if (Fips.enabled) {
            Fips.setPrivateKeyReadEnable(1, Fips.WC_KEYTYPE_ALL);
        }
    }
}

