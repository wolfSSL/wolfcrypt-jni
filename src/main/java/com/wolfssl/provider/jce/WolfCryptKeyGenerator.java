/* WolfCryptKeyGenerator.java
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

import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.wolfcrypt.Aes;
import com.wolfssl.wolfcrypt.Sha256;
import com.wolfssl.wolfcrypt.Sha384;
import com.wolfssl.wolfcrypt.Sha512;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.InvalidParameterException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * wolfCrypt JCE KeyGenerator implementation.
 */
public class WolfCryptKeyGenerator extends KeyGeneratorSpi {

    enum AlgoType {
        WC_INVALID,
        WC_AES,
        WC_HMAC_SHA1,
        WC_HMAC_SHA256,
        WC_HMAC_SHA384,
        WC_HMAC_SHA512
    }

    private AlgoType algoType = AlgoType.WC_INVALID;
    private String algString = null;

    private int keySizeBits = 0;
    private AlgorithmParameterSpec algoParams = null;
    private SecureRandom random = null;

    /**
     * Internal private constructor for WolfCryptKeyGenerator.
     *
     * Default key sizes are set up to match the defaults of SunJCE.
     *
     * @param type algorithm type, from AlgoType enum.
     */
    private WolfCryptKeyGenerator(AlgoType type) {
        switch (type) {
            case WC_AES:
                this.algString = "AES";
                this.keySizeBits = (Aes.BLOCK_SIZE * 8);
                break;
            case WC_HMAC_SHA1:
                this.algString = "HmacSHA1";
                /* SunJCE default key size for HmacSHA1 is 64 bytes */
                this.keySizeBits = (Sha512.DIGEST_SIZE * 8);
                break;
            case WC_HMAC_SHA256:
                this.algString = "HmacSHA256";
                this.keySizeBits = (Sha256.DIGEST_SIZE * 8);
                break;
            case WC_HMAC_SHA384:
                this.algString = "HmacSHA384";
                this.keySizeBits = (Sha384.DIGEST_SIZE * 8);
                break;
            case WC_HMAC_SHA512:
                this.algString = "HmacSHA512";
                this.keySizeBits = (Sha512.DIGEST_SIZE * 8);
                break;
        }

        log("created KeyGenerator(" + this.algString + ")");
        this.algoType = type;
    }

    /*
     * Log debug messages, if debug is enabled.
     *
     * @param msg Message string to log
     */
    private void log(String msg) {
        WolfCryptDebug.print("[KeyGenerator, " + algString + "] " + msg);
    }

    /**
     * Sanitize key size depending on algorithm type.
     *
     * @param keysize key size used for key generation, provided in bits.
     *
     * @throws InvalidParameterException if key size is invalid for this
     *         algorithm.
     */
    private void sanitizeKeySize(int keysize)
        throws InvalidParameterException {

        if (this.algoType == AlgoType.WC_AES) {
            if (keysize != 128 && keysize != 192 && keysize != 256) {
                throw new InvalidParameterException(
                    "Invalid AES key size: " + keysize + " bits");
            }
        }
    }

    /**
     * Sanitize SecureRandom object if in FIPS mode to ensure we are
     * using wolfCrypt FIPS DRBG.
     *
     * @param random SecureRandom object used for key generation.
     *
     * @throws InvalidParameterException if on top of wolfCrypt FIPS
     *         and SecureRandom provider is not wolfJCE.
     */
    private void sanitizeSecureRandom(SecureRandom random)
        throws InvalidParameterException {

        if (Fips.enabled && (random != null)) {
            String randomProvider = random.getProvider().getName();
            if (!randomProvider.equals("wolfJCE")) {
                throw new InvalidParameterException(
                    "SecureRandom provider must be wolfJCE if " +
                    "using wolfCrypt FIPS, current = " + randomProvider);
            }
        }
    }

    /**
     * Initialize the KeyGenerator.
     *
     * @param random SecureRandom object used for key generation.
     */
    @Override
    protected void engineInit(SecureRandom random) {
        this.random = random;
    }

    /**
     * Initialize the KeyGenerator with given AlgorithmParameterSpec and
     * SecureRandom object.
     *
     * @param params AlgorithmParameterSpec object used for key generation.
     * @param random SecureRandom object used for key generation.
     *
     * @throws InvalidAlgorithmParameterException if params is invalid or
     *        not supported by this KeyGenerator.
     */
    @Override
    protected void engineInit(AlgorithmParameterSpec params,
        SecureRandom random) throws InvalidAlgorithmParameterException {

        throw new InvalidAlgorithmParameterException(
            "Key generation (" + algString + ") does not support " +
            "AlgorithmParameterSpec");
    }

    /**
     * Initialize the KeyGenerator with given key size and SecureRandom object.
     *
     * @param keysize key size used for key generation, provided in bits.
     * @param random SecureRandom object used for key generation.
     *
     * @throws InvalidParameterException if key size is invalid or
     *         not supported.
     */
    @Override
    protected void engineInit(int keysize, SecureRandom random)
        throws InvalidParameterException {

        /* Sanitize key size, will throw exception if invalid for algo */
        sanitizeKeySize(keysize);

        /* If using wolfCrypt FIPS, make sure this is our SecureRandom */
        sanitizeSecureRandom(random);

        this.keySizeBits = keysize;
        this.random = random;
    }

    /**
     * Generate a secret key.
     *
     * @return newly generated SecretKey object.
     */
    @Override
    protected SecretKey engineGenerateKey() {

        byte[] keyArr = null;

        try {
            if (this.random == null) {
                this.random = SecureRandom.getInstance("HashDRBG", "wolfJCE");
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            log("Failed to get wolfJCE SecureRandom(HashDRBG)");
            return null;
        }

        keyArr = new byte[(this.keySizeBits + 7) / 8];
        this.random.nextBytes(keyArr);

        log("Generating key: " + keyArr.length + " bytes");

        switch (this.algoType) {
            case WC_AES:
            case WC_HMAC_SHA1:
            case WC_HMAC_SHA256:
            case WC_HMAC_SHA384:
            case WC_HMAC_SHA512:
                return new SecretKeySpec(keyArr, this.algString);
            default:
                return null;
        }
    }

    /**
     * KeyGenerator(AES) class, called by WolfCryptProvider.
     */
    public static final class wcAESKeyGenerator
        extends WolfCryptKeyGenerator {

        /**
         * Constructor for wcAESKeyGenerator.
         */
        public wcAESKeyGenerator() {
            super(AlgoType.WC_AES);
        }
    }

    /**
     * KeyGenerator(HmacSHA1) class, called by WolfCryptProvider.
     */
    public static final class wcHMACSha1KeyGenerator
        extends WolfCryptKeyGenerator {

        /**
         * Constructor for wcHMACSha1KeyGenerator.
         */
        public wcHMACSha1KeyGenerator() {
            super(AlgoType.WC_HMAC_SHA1);
        }
    }

    /**
     * KeyGenerator(HmacSHA256) class, called by WolfCryptProvider.
     */
    public static final class wcHMACSha256KeyGenerator
        extends WolfCryptKeyGenerator {

        /**
         * Constructor for wcHMACSha256KeyGenerator.
         */
        public wcHMACSha256KeyGenerator() {
            super(AlgoType.WC_HMAC_SHA256);
        }
    }

    /**
     * KeyGenerator(HmacSHA384) class, called by WolfCryptProvider.
     */
    public static final class wcHMACSha384KeyGenerator
        extends WolfCryptKeyGenerator {

        /**
         * Constructor for wcHMACSha384KeyGenerator.
         */
        public wcHMACSha384KeyGenerator() {
            super(AlgoType.WC_HMAC_SHA384);
        }
    }

    /**
     * Key Generator(HmacSHA512) class, called by WolfCryptProvider.
     */
    public static final class wcHMACSha512KeyGenerator
        extends WolfCryptKeyGenerator {

        /**
         * Constructor for wcHMACSha512KeyGenerator.
         */
        public wcHMACSha512KeyGenerator() {
            super(AlgoType.WC_HMAC_SHA512);
        }
    }
}

