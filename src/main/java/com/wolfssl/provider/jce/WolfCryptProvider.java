/* wolfCryptProvider.java
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

package com.wolfssl.provider.jce;

import java.security.Provider;
import java.security.Security;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.Fips;

/**
 * wolfCrypt JCE Provider implementation
 */
public final class WolfCryptProvider extends Provider {

    private static final long serialVersionUID = 1L;

    /**
     * Create new WolfCryptProvider object
     */
    public WolfCryptProvider() {
        super("wolfJCE", 1.8, "wolfCrypt JCE Provider");
        registerServices();
    }

    /**
     * Refresh the services provided by this JCE provider.
     *
     * This is required when one of the Security properties has been changed
     * that affect the services offered by this provider. For example:
     *     wolfjce.mapJKStoWKS
     *     wolfjce.mapPKCS12toWKS
     */
    public void refreshServices() {
        registerServices();
    }

    /**
     * Register services provided by wolfJCE, called by class constructor.
     */
    private void registerServices() {
        String mapJksToWks = null;
        String mapPkcs12ToWks = null;

        /* Run FIPS algorithm self tests (CASTs) if needed */
        if (Fips.enabled) {
            Fips.runAllCast_fips();
        }

        /* MessageDigest */
        if (FeatureDetect.Md5Enabled()) {
            put("MessageDigest.MD5",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestMd5");
        }
        if (FeatureDetect.ShaEnabled()) {
            put("MessageDigest.SHA",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha");
            put("MessageDigest.SHA1",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha");
            put("MessageDigest.SHA-1",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha");
        }
        if (FeatureDetect.Sha224Enabled()) {
            put("MessageDigest.SHA-224",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha224");
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
        if (FeatureDetect.Sha3Enabled()) {
            put("MessageDigest.SHA3-224",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha3$wcSHA3_224");
            put("MessageDigest.SHA3-256",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha3$wcSHA3_256");
            put("MessageDigest.SHA3-384",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha3$wcSHA3_384");
            put("MessageDigest.SHA3-512",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha3$wcSHA3_512");
        }

        /* SecureRandom */
        /* TODO: May need to add "SHA1PRNG" alias, other JCA consumemrs may
         * explicitly request it? Needs more testing. */
        put("SecureRandom.DEFAULT",
                "com.wolfssl.provider.jce.WolfCryptRandom");
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
        if (FeatureDetect.Sha224Enabled()) {
            put("Signature.SHA224withRSA",
                    "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA224wRSA");
            put("Signature.SHA224withECDSA",
                  "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA224wECDSA");
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
        if (FeatureDetect.HmacMd5Enabled()) {
            put("Mac.HmacMD5",
                    "com.wolfssl.provider.jce.WolfCryptMac$wcHmacMD5");
        }
        if (FeatureDetect.HmacShaEnabled()) {
            put("Mac.HmacSHA1",
                    "com.wolfssl.provider.jce.WolfCryptMac$wcHmacSHA1");
        }
        if (FeatureDetect.HmacSha224Enabled()) {
            put("Mac.HmacSHA224",
                    "com.wolfssl.provider.jce.WolfCryptMac$wcHmacSHA224");
        }
        if (FeatureDetect.HmacSha256Enabled()) {
            put("Mac.HmacSHA256",
                    "com.wolfssl.provider.jce.WolfCryptMac$wcHmacSHA256");
        }
        if (FeatureDetect.HmacSha384Enabled()) {
            put("Mac.HmacSHA384",
                    "com.wolfssl.provider.jce.WolfCryptMac$wcHmacSHA384");
        }
        if (FeatureDetect.HmacSha512Enabled()) {
            put("Mac.HmacSHA512",
                    "com.wolfssl.provider.jce.WolfCryptMac$wcHmacSHA512");
        }

        /* Cipher */
        if (FeatureDetect.AesCbcEnabled()) {
            put("Cipher.AES/CBC/NoPadding",
                "com.wolfssl.provider.jce.WolfCryptCipher$wcAESCBCNoPadding");
            put("Cipher.AES/CBC/PKCS5Padding",
                "com.wolfssl.provider.jce.WolfCryptCipher$wcAESCBCPKCS5Padding");
        }
        if (FeatureDetect.AesGcmEnabled()) {
            put("Cipher.AES/GCM/NoPadding",
                "com.wolfssl.provider.jce.WolfCryptCipher$wcAESGCMNoPadding");
        }

        if (FeatureDetect.Des3Enabled()) {
            put("Cipher.DESede/CBC/NoPadding",
                "com.wolfssl.provider.jce.WolfCryptCipher$wcDESedeCBCNoPadding");
        }

        if (FeatureDetect.RsaEnabled()) {
            put("Cipher.RSA",
                "com.wolfssl.provider.jce.WolfCryptCipher$wcRSAECBPKCS1Padding");
            put("Cipher.RSA/ECB/PKCS1Padding",
                "com.wolfssl.provider.jce.WolfCryptCipher$wcRSAECBPKCS1Padding");
        }

        /* KeyAgreement */
        if (FeatureDetect.DhEnabled()) {
            put("KeyAgreement.DiffieHellman",
                "com.wolfssl.provider.jce.WolfCryptKeyAgreement$wcDH");
            put("Alg.Alias.KeyAgreement.DH", "DiffieHellman");
        }
        if (FeatureDetect.EccDheEnabled()) {
            put("KeyAgreement.ECDH",
                "com.wolfssl.provider.jce.WolfCryptKeyAgreement$wcECDH");
        }

        /* KeyGenerator */
        if (FeatureDetect.AesEnabled()) {
            put("KeyGenerator.AES",
                "com.wolfssl.provider.jce.WolfCryptKeyGenerator$wcAESKeyGenerator");
        }
        if (FeatureDetect.HmacShaEnabled()) {
            put("KeyGenerator.HmacSHA1",
                "com.wolfssl.provider.jce.WolfCryptKeyGenerator$wcHMACSha1KeyGenerator");
        }
        if (FeatureDetect.HmacSha224Enabled()) {
            put("KeyGenerator.HmacSHA224",
                "com.wolfssl.provider.jce.WolfCryptKeyGenerator$wcHMACSha224KeyGenerator");
        }
        if (FeatureDetect.HmacSha256Enabled()) {
            put("KeyGenerator.HmacSHA256",
                "com.wolfssl.provider.jce.WolfCryptKeyGenerator$wcHMACSha256KeyGenerator");
        }
        if (FeatureDetect.HmacSha384Enabled()) {
            put("KeyGenerator.HmacSHA384",
                "com.wolfssl.provider.jce.WolfCryptKeyGenerator$wcHMACSha384KeyGenerator");
        }
        if (FeatureDetect.HmacSha512Enabled()) {
            put("KeyGenerator.HmacSHA512",
                "com.wolfssl.provider.jce.WolfCryptKeyGenerator$wcHMACSha512KeyGenerator");
        }

        /* KeyPairGenerator */
        if (FeatureDetect.RsaKeyGenEnabled()) {
            put("KeyPairGenerator.RSA",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenRSA");
        }
        if (FeatureDetect.EccKeyGenEnabled()) {
            put("KeyPairGenerator.EC",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenECC");
        }
        if (FeatureDetect.DhEnabled()) {
            put("KeyPairGenerator.DH",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenDH");
            put("Alg.Alias.KeyPairGenerator.DiffieHellman", "DH");
        }

        /* CertPathValidator */
        put("CertPathValidator.PKIX",
                "com.wolfssl.provider.jce.WolfCryptPKIXCertPathValidator");

        /* SecretKeyFactory */
        if (FeatureDetect.Pbkdf2Enabled()) {
            if (FeatureDetect.HmacShaEnabled()) {
                put("SecretKeyFactory.PBKDF2WithHmacSHA1",
                    "com.wolfssl.provider.jce.WolfCryptSecretKeyFactory$wcPBKDF2WithHmacSHA1");
            }
            if (FeatureDetect.HmacSha224Enabled()) {
                put("SecretKeyFactory.PBKDF2WithHmacSHA224",
                    "com.wolfssl.provider.jce.WolfCryptSecretKeyFactory$wcPBKDF2WithHmacSHA224");
            }
            if (FeatureDetect.HmacSha256Enabled()) {
                put("SecretKeyFactory.PBKDF2WithHmacSHA256",
                    "com.wolfssl.provider.jce.WolfCryptSecretKeyFactory$wcPBKDF2WithHmacSHA256");
            }
            if (FeatureDetect.HmacSha384Enabled()) {
                put("SecretKeyFactory.PBKDF2WithHmacSHA384",
                    "com.wolfssl.provider.jce.WolfCryptSecretKeyFactory$wcPBKDF2WithHmacSHA384");
            }
            if (FeatureDetect.HmacSha512Enabled()) {
                put("SecretKeyFactory.PBKDF2WithHmacSHA512",
                    "com.wolfssl.provider.jce.WolfCryptSecretKeyFactory$wcPBKDF2WithHmacSHA512");
            }
            if (FeatureDetect.HmacSha3_224Enabled()) {
                put("SecretKeyFactory.PBKDF2WithHmacSHA3-224",
                    "com.wolfssl.provider.jce.WolfCryptSecretKeyFactory$wcPBKDF2WithHmacSHA3_224");
            }
            if (FeatureDetect.HmacSha3_256Enabled()) {
                put("SecretKeyFactory.PBKDF2WithHmacSHA3-256",
                    "com.wolfssl.provider.jce.WolfCryptSecretKeyFactory$wcPBKDF2WithHmacSHA3_256");
            }
            if (FeatureDetect.HmacSha3_384Enabled()) {
                put("SecretKeyFactory.PBKDF2WithHmacSHA3-384",
                    "com.wolfssl.provider.jce.WolfCryptSecretKeyFactory$wcPBKDF2WithHmacSHA3_384");
            }
            if (FeatureDetect.HmacSha3_512Enabled()) {
                put("SecretKeyFactory.PBKDF2WithHmacSHA3-512",
                    "com.wolfssl.provider.jce.WolfCryptSecretKeyFactory$wcPBKDF2WithHmacSHA3_512");
            }
        }

        /* KeyStore */
        put("KeyStore.WKS",
                "com.wolfssl.provider.jce.WolfSSLKeyStore");

        /* Fake mapping of JKS to WKS type. Use with caution! This is
         * usually used when FIPS compliance is needed but code cannot be
         * changed that creates a JKS KeyStore object type. Any files loaded
         * into this fake JKS KeyStore MUST be of actual type WKS or failures
         * will happen. Remove service first here in case of refresh. */
        remove("KeyStore.JKS");
        mapJksToWks = Security.getProperty("wolfjce.mapJKStoWKS");
        if (mapJksToWks != null && !mapJksToWks.isEmpty() &&
            mapJksToWks.equalsIgnoreCase("true")) {
            put("KeyStore.JKS",
                "com.wolfssl.provider.jce.WolfSSLKeyStore");
        }

        /* Fake mapping of PKCS12 to WKS type. Use with caution! This is
         * usually used when FIPS compliance is needed but code cannot be
         * changed that creates a JKS KeyStore object type. Any files loaded
         * into this fake JKS KeyStore MUST be of actual type WKS or failures
         * will happen. Remove service first here in case of refresh. */
        remove("KeyStore.PKCS12");
        mapPkcs12ToWks = Security.getProperty("wolfjce.mapPKCS12toWKS");
        if (mapPkcs12ToWks != null && !mapPkcs12ToWks.isEmpty() &&
            mapPkcs12ToWks.equalsIgnoreCase("true")) {
            put("KeyStore.PKCS12",
                "com.wolfssl.provider.jce.WolfSSLKeyStore");
        }

        /* If using a FIPS version of wolfCrypt, allow private key to be
         * exported for use. Only applicable to FIPS 140-3 */
        if (Fips.enabled) {
            Fips.setPrivateKeyReadEnable(1, Fips.WC_KEYTYPE_ALL);
        }
    }
}

