/* WolfCryptSecretKeyFactory.java
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

import java.util.Arrays;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.interfaces.PBEKey;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.spec.KeySpec;
import java.security.spec.InvalidKeySpecException;

import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.Pwdbased;

/**
 * wolfCrypt JCE SecretKeyFactory implementation.
 */
public class WolfCryptSecretKeyFactory extends SecretKeyFactorySpi {

    private enum FactoryType {
        WC_SKF_PBKDF2_HMAC_SHA1,
        WC_SKF_PBKDF2_HMAC_SHA224,
        WC_SKF_PBKDF2_HMAC_SHA256,
        WC_SKF_PBKDF2_HMAC_SHA384,
        WC_SKF_PBKDF2_HMAC_SHA512,
        WC_SKF_PBKDF2_HMAC_SHA3_224,
        WC_SKF_PBKDF2_HMAC_SHA3_256,
        WC_SKF_PBKDF2_HMAC_SHA3_384,
        WC_SKF_PBKDF2_HMAC_SHA3_512
    }

    /* PBKDF2/HMAC type of this factory */
    private FactoryType factoryType;

    /* String representation of this factory type */
    private String typeString;

    /* wolfCrypt int representing hash used in this factory */
    private int hashType;

    private WolfCryptSecretKeyFactory(FactoryType type)
        throws NoSuchAlgorithmException {

        this.factoryType = type;

        switch (type) {
            case WC_SKF_PBKDF2_HMAC_SHA1:
                this.hashType = WolfCrypt.WC_HASH_TYPE_SHA;
                break;

            case WC_SKF_PBKDF2_HMAC_SHA224:
                this.hashType = WolfCrypt.WC_HASH_TYPE_SHA224;
                break;

            case WC_SKF_PBKDF2_HMAC_SHA256:
                this.hashType = WolfCrypt.WC_HASH_TYPE_SHA256;
                break;

            case WC_SKF_PBKDF2_HMAC_SHA384:
                this.hashType = WolfCrypt.WC_HASH_TYPE_SHA384;
                break;

            case WC_SKF_PBKDF2_HMAC_SHA512:
                this.hashType = WolfCrypt.WC_HASH_TYPE_SHA512;
                break;

            case WC_SKF_PBKDF2_HMAC_SHA3_224:
                this.hashType = WolfCrypt.WC_HASH_TYPE_SHA3_224;
                break;

            case WC_SKF_PBKDF2_HMAC_SHA3_256:
                this.hashType = WolfCrypt.WC_HASH_TYPE_SHA3_256;
                break;

            case WC_SKF_PBKDF2_HMAC_SHA3_384:
                this.hashType = WolfCrypt.WC_HASH_TYPE_SHA3_384;
                break;

            case WC_SKF_PBKDF2_HMAC_SHA3_512:
                this.hashType = WolfCrypt.WC_HASH_TYPE_SHA3_512;
                break;

            default:
                throw new NoSuchAlgorithmException(
                    "Unsupported SecretKeyFactory type");
        }

        typeString = typeToString(type);

        log("created new SecretKeyFactory");
    }

    /**
     * Internal method for logging output.
     *
     * @param msg message to be logged
     */
    private void log(String msg) {
        WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO,
            () -> "[" + typeString + "] " + msg);
    }

    /**
     * Return String name of provided FactoryType.
     *
     * @param type FactoryType to return corresponding name String for
     *
     * @return String name matching provided FactoryType
     */
    private String typeToString(FactoryType type) {
        switch (type) {
            case WC_SKF_PBKDF2_HMAC_SHA1:
                return "PBKDF2WithHmacSHA1";
            case WC_SKF_PBKDF2_HMAC_SHA224:
                return "PBKDF2WithHmacSHA224";
            case WC_SKF_PBKDF2_HMAC_SHA256:
                return "PBKDF2WithHmacSHA256";
            case WC_SKF_PBKDF2_HMAC_SHA384:
                return "PBKDF2WithHmacSHA384";
            case WC_SKF_PBKDF2_HMAC_SHA512:
                return "PBKDF2WithHmacSHA512";
            case WC_SKF_PBKDF2_HMAC_SHA3_224:
                return "PBKDF2WithHmacSHA3-224";
            case WC_SKF_PBKDF2_HMAC_SHA3_256:
                return "PBKDF2WithHmacSHA3-256";
            case WC_SKF_PBKDF2_HMAC_SHA3_384:
                return "PBKDF2WithHmacSHA3-384";
            case WC_SKF_PBKDF2_HMAC_SHA3_512:
                return "PBKDF2WithHmacSHA3-512";
            default:
                return "None";
        }
    }

    /**
     * Test if this SecretKeyFactory is PBKDF2.
     *
     * @return true if PBKDF2 factory, otherwise false
     */
    private boolean isFactoryPBKDF() {

        switch (this.factoryType) {
            case WC_SKF_PBKDF2_HMAC_SHA1:
            case WC_SKF_PBKDF2_HMAC_SHA224:
            case WC_SKF_PBKDF2_HMAC_SHA256:
            case WC_SKF_PBKDF2_HMAC_SHA384:
            case WC_SKF_PBKDF2_HMAC_SHA512:
            case WC_SKF_PBKDF2_HMAC_SHA3_224:
            case WC_SKF_PBKDF2_HMAC_SHA3_256:
            case WC_SKF_PBKDF2_HMAC_SHA3_384:
            case WC_SKF_PBKDF2_HMAC_SHA3_512:
                return true;
            default:
                return false;
        }
    }

    /**
     * Test if provided algorithm String is supported by this
     * SecretKeyFactory.
     *
     * @param algorithm String to test for support
     *
     * @return true if supported, otherwise false
     */
    private boolean isAlgorithmSupported(String algo) {

        if (algo == null) {
            return false;
        }

        switch (algo) {
            case "PBKDF2WithHmacSHA1":
            case "PBKDF2WithHmacSHA224":
            case "PBKDF2WithHmacSHA256":
            case "PBKDF2WithHmacSHA384":
            case "PBKDF2WithHmacSHA512":
            case "PBKDF2WithHmacSHA3-224":
            case "PBKDF2WithHmacSHA3-256":
            case "PBKDF2WithHmacSHA3-384":
            case "PBKDF2WithHmacSHA3-512":
                return true;
            default:
                return false;
        }
    }

    /**
     * Check if provided KeySpec is supported by this SecretKeyFactory.
     *
     * @throws InvalidKeySpecException if KeySpec is invalid or incompatible
     *         with this factory
     */
    private void checkKeySpecSupported(KeySpec spec)
        throws InvalidKeySpecException {

        if (spec == null) {
            throw new InvalidKeySpecException("KeySpec cannot be null");
        }

        if (isFactoryPBKDF()) {
            if (!(spec instanceof PBEKeySpec)) {
                throw new InvalidKeySpecException(
                    "KeySpec must be type PBEKeySpec");
            }
        } else {
            throw new InvalidKeySpecException(
                "Unsupported SecretKeyFactory type");
        }
    }

    /**
     * Convert password from char[] to byte[].
     *
     * RFC 2898 (PBKDF2) considers password to be an octet string and
     * recommends for interop ASCII or UTF-8 encoding is used. SunJCE uses
     * UTF-8 for PBKDF2 SecretKeyFactory, so we do the same here for interop
     * compatibility.
     *
     * @param pass password as char array
     *
     * @return password as UTF-8 encoded byte array, or null if input password
     *         is null or zero length
     */
    protected static byte[] passwordToByteArray(char[] pass) {

        byte[] passBytes = null;
        CharBuffer passBuf = null;
        ByteBuffer utf8Buf = null;

        if (pass == null || pass.length == 0) {
            return null;
        }

        passBuf = CharBuffer.wrap(pass);
        utf8Buf = StandardCharsets.UTF_8.encode(passBuf);
        passBytes = new byte[utf8Buf.limit()];
        utf8Buf.get(passBytes);

        return passBytes;
    }

    /**
     * Generate SecretKey (PBEKey) from provided PBEKeySpec.
     *
     * @param spec PBEKeySpec to use for generating SecretKey
     *
     * @throws InvalidKeySpecException if SecretKey generation fails
     */
    private SecretKey genSecretKeyFromPBEKeySpec(PBEKeySpec spec)
        throws InvalidKeySpecException {

        int iterations;
        int kLen;
        byte[] salt = null;
        char[] pass = null;
        byte[] derivedKey = null;
        SecretKey key = null;

        try {
            iterations = spec.getIterationCount();
            kLen = spec.getKeyLength();
            salt = spec.getSalt();
            pass = spec.getPassword();

            if (salt == null || salt.length == 0) {
                throw new InvalidKeySpecException(
                    "Null or zero length salt not allowed");
            }

            if (kLen < 8) {
                throw new InvalidKeySpecException(
                    "Key length must be at least one byte (8 bits)");
            }
            if ((kLen % 8) != 0) {
                throw new InvalidKeySpecException(
                    "Key length bits is not divisible by 8 (byte conversion)");
            }

            /* Key length is given in bits, convert to bytes */
            kLen = kLen / 8;

            log("generating PBEKey (iterations: " + iterations +
                ", key len: " + kLen + " bytes)");

            derivedKey = Pwdbased.PBKDF2(passwordToByteArray(pass),
                salt, iterations, kLen, this.hashType);

            if (derivedKey == null || derivedKey.length == 0) {
                throw new InvalidKeySpecException(
                    "Error deriving key with PBKDF2");
            }

            key = new WolfCryptPBEKey(pass, salt, iterations,
                this.typeString, derivedKey);

        } finally {

            iterations = 0;
            kLen = 0;

            if (salt != null) {
                Arrays.fill(salt, (byte)0);
            }
            if (pass != null) {
                Arrays.fill(pass, (char)0);
            }
            if (derivedKey != null) {
                Arrays.fill(derivedKey, (byte)0);
            }
        }

        return key;
    }

    /**
     * Generate a SecretKey object from the provided KeySpec.
     *
     * @param spec specification of the secret key
     *
     * @return SecretKey generated from KeySpec
     *
     * @throws InvalidKeySpecException if provided KeySpec is incorrect
     *         or incomplete for generating a SecretKey
     */
    @Override
    protected synchronized SecretKey engineGenerateSecret(KeySpec spec)
        throws InvalidKeySpecException {

        log("generating SecretKey from KeySpec");

        checkKeySpecSupported(spec);

        return genSecretKeyFromPBEKeySpec((PBEKeySpec)spec);
    }

    /**
     * Return a KeySpec from the provided PBEKey in the requested format.
     *
     * Called by engineGetKeySpec().
     *
     * @param key PBEKey for which to return KeySpec
     * @param keSpec the requested format that the KeySpec should be returned in
     *
     * @return KeySpec for the PBEKey, in the requested format
     *
     * @throws InvalidKeySpecException if the requested format is not
     *         appropriate for the given key, or the provided PBEKey
     *         cannot be used.
     */
    private KeySpec getKeySpecFromPBEKeyByType(PBEKey key, Class<?> keySpec)
        throws InvalidKeySpecException {

        int iterations = 0;
        char[] password = null;
        byte[] salt = null;
        byte[] encoded = null;
        PBEKeySpec pbSpec = null;

        if (key != null && keySpec != null) {

            if (keySpec.isAssignableFrom(PBEKeySpec.class)) {

                try {
                    password = key.getPassword();
                    salt = key.getSalt();
                    iterations = key.getIterationCount();
                    encoded = key.getEncoded();

                    if (encoded == null) {
                        throw new InvalidKeySpecException(
                            "Error getting encoded key from PBEKey");
                    }

                    pbSpec = new PBEKeySpec(password, salt, iterations,
                        encoded.length);

                } finally {
                    if (password != null) {
                        Arrays.fill(password, (char)0);
                    }
                    if (salt != null) {
                        Arrays.fill(salt, (byte)0);
                    }
                    if (encoded != null) {
                        Arrays.fill(encoded, (byte)0);
                    }
                }
            }
        }

        return pbSpec;
    }

    /**
     * Return a KeySpec (key material) of the provided SecretKey in the
     * requested format.
     *
     * @param key SecretKey for which to return KeySpec
     * @param keySpec the requested format that the  KeySpec should be
     *                returned in
     *
     * @return the KeySpec for the SecretKey in the requested format
     *
     * @throws InvalidKeySpecException if the requested format is not
     *         appropriate for the given key, or the provided SecretKey
     *         cannot be used.
     */
    @Override
    protected synchronized KeySpec engineGetKeySpec(SecretKey key,
        Class<?> keySpec) throws InvalidKeySpecException {

        log("returning KeySpec from SecretKey in requested type");

        if (key == null) {
            throw new InvalidKeySpecException("SecretKey cannot be null");
        }

        if (keySpec == null) {
            throw new InvalidKeySpecException(
                "Requested KeySpec format cannot be null");
        }

        if (key instanceof PBEKey) {
            return getKeySpecFromPBEKeyByType((PBEKey)key, keySpec);
        }
        else {
            throw new InvalidKeySpecException(
                "Only SecretKey of type PBEKey currently supported");
        }
    }

    /**
     * Translates PBEKey to one generated by this SecretKeyFactory.
     *
     * Called by engineTranslateKey().
     *
     * @param PBEKey (SecretKey) to translate
     *
     * @return New/translated SecretKey (PBEKey) generated by this
     *         SecretKeyFactory.
     *
     * @throws InvalidKeyException if the provided SecretKey can not be
     *         used or converted
     */
    private SecretKey translatePBEKey(PBEKey key)
        throws InvalidKeyException {

        char[] password = null;
        byte[] salt = null;
        byte[] enc = null;
        int iterations = 0;
        PBEKeySpec spec = null;
        SecretKey sKey = null;

        if (key != null) {

            if (!isAlgorithmSupported(key.getAlgorithm())) {
                throw new InvalidKeyException(
                    "SecretKey algorithm not supported: " + key.getAlgorithm());
            }

            try {
                iterations = key.getIterationCount();
                salt = key.getSalt();
                password = key.getPassword();
                enc = key.getEncoded();

                if (enc == null) {
                    throw new InvalidKeySpecException(
                        "Error getting encoded key from PBEKey");
                }

                /* PBEKeySpec holds key length in bits */
                spec = new PBEKeySpec(password, salt, iterations,
                    enc.length * 8);
                sKey = genSecretKeyFromPBEKeySpec(spec);

            } catch (InvalidKeySpecException e) {
                throw new InvalidKeyException(e);

            } finally {
                spec.clearPassword();

                if (password != null) {
                    Arrays.fill(password, (char)0);
                }
                if (salt != null) {
                    Arrays.fill(salt, (byte)0);
                }
                if (enc != null) {
                    Arrays.fill(enc, (byte)0);
                }
            }
        }

        return sKey;
    }

    /**
     * Translate a SecretKey object from another provider (or unknown source)
     * into a SecretKey object from this SecretKeyFactory.
     *
     * This method will extract necessary parameters from the original
     * SecretKey then re-generate the SecretKey using this factory.
     *
     * @param key SecretKey to translate
     *
     * @return Translated SecretKey object from this SecretKeyFactory
     *
     * @throws InvalidKeyException if the provided SecretKey can not be
     *         used or converted
     */
    @Override
    protected synchronized SecretKey engineTranslateKey(SecretKey key)
        throws InvalidKeyException {

        log("translating SecretKey to wolfJCE SecretKeyFactory type");

        if (key == null) {
            throw new InvalidKeyException("SecretKey cannot be null");
        }

        if (key instanceof PBEKey) {
            return translatePBEKey((PBEKey)key);
        }
        else {
            throw new InvalidKeyException(
                "Only SecretKey of type PBEKey currently supported");
        }
    }

    /**
     * wolfJCE PBKDF2WithHmacSHA1 SecretKeyFactory class.
     */
    public static final class wcPBKDF2WithHmacSHA1
        extends WolfCryptSecretKeyFactory {

        /**
         * Create new wcPBKDF2WithHmacSHA1 object.
         *
         * @throws NoSuchAlgorithmException if PBKDF2-HMAC-SHA1 is not
         *         available in native wolfCrypt.
         */
        public wcPBKDF2WithHmacSHA1() throws NoSuchAlgorithmException {
            super(FactoryType.WC_SKF_PBKDF2_HMAC_SHA1);
        }
    }

    /**
     * wolfJCE PBKDF2WithHmacSHA224 SecretKeyFactory class.
     */
    public static final class wcPBKDF2WithHmacSHA224
        extends WolfCryptSecretKeyFactory {

        /**
         * Create new wcPBKDF2WithHmacSHA224 object.
         *
         * @throws NoSuchAlgorithmException if PBKDF2-HMAC-SHA224 is not
         *         available in native wolfCrypt.
         */
        public wcPBKDF2WithHmacSHA224() throws NoSuchAlgorithmException {
            super(FactoryType.WC_SKF_PBKDF2_HMAC_SHA224);
        }
    }

    /**
     * wolfJCE PBKDF2WithHmacSHA256 SecretKeyFactory class.
     */
    public static final class wcPBKDF2WithHmacSHA256
        extends WolfCryptSecretKeyFactory {

        /**
         * Create new wcPBKDF2WithHmacSHA256 object.
         *
         * @throws NoSuchAlgorithmException if PBKDF2-HMAC-SHA256 is not
         *         available in native wolfCrypt.
         */
        public wcPBKDF2WithHmacSHA256() throws NoSuchAlgorithmException {
            super(FactoryType.WC_SKF_PBKDF2_HMAC_SHA256);
        }
    }

    /**
     * wolfJCE PBKDF2WithHmacSHA384 SecretKeyFactory class.
     */
    public static final class wcPBKDF2WithHmacSHA384
        extends WolfCryptSecretKeyFactory {

        /**
         * Create new wcPBKDF2WithHmacSHA384 object.
         *
         * @throws NoSuchAlgorithmException if PBKDF2-HMAC-SHA384 is not
         *         available in native wolfCrypt.
         */
        public wcPBKDF2WithHmacSHA384() throws NoSuchAlgorithmException {
            super(FactoryType.WC_SKF_PBKDF2_HMAC_SHA384);
        }
    }

    /**
     * wolfJCE PBKDF2WithHmacSHA512 SecretKeyFactory class.
     */
    public static final class wcPBKDF2WithHmacSHA512
        extends WolfCryptSecretKeyFactory {

        /**
         * Create new wcPBKDF2WithHmacSHA512 object.
         *
         * @throws NoSuchAlgorithmException if PBKDF2-HMAC-SHA512 is not
         *         available in native wolfCrypt.
         */
        public wcPBKDF2WithHmacSHA512() throws NoSuchAlgorithmException {
            super(FactoryType.WC_SKF_PBKDF2_HMAC_SHA512);
        }
    }

    /**
     * wolfJCE PBKDF2WithHmacSHA3_224 SecretKeyFactory class.
     */
    public static final class wcPBKDF2WithHmacSHA3_224
        extends WolfCryptSecretKeyFactory {

        /**
         * Create new wcPBKDF2WithHmacSHA3_224 object.
         *
         * @throws NoSuchAlgorithmException if PBKDF2-HMAC-SHA3-224 is not
         *         available in native wolfCrypt.
         */
        public wcPBKDF2WithHmacSHA3_224() throws NoSuchAlgorithmException {
            super(FactoryType.WC_SKF_PBKDF2_HMAC_SHA3_224);
        }
    }

    /**
     * wolfJCE PBKDF2WithHmacSHA3_256 SecretKeyFactory class.
     */
    public static final class wcPBKDF2WithHmacSHA3_256
        extends WolfCryptSecretKeyFactory {

        /**
         * Create new wcPBKDF2WithHmacSHA3_256 object.
         *
         * @throws NoSuchAlgorithmException if PBKDF2-HMAC-SHA3-256 is not
         *         available in native wolfCrypt.
         */
        public wcPBKDF2WithHmacSHA3_256() throws NoSuchAlgorithmException {
            super(FactoryType.WC_SKF_PBKDF2_HMAC_SHA3_256);
        }
    }

    /**
     * wolfJCE PBKDF2WithHmacSHA3_384 SecretKeyFactory class.
     */
    public static final class wcPBKDF2WithHmacSHA3_384
        extends WolfCryptSecretKeyFactory {

        /**
         * Create new wcPBKDF2WithHmacSHA3_384 object.
         *
         * @throws NoSuchAlgorithmException if PBKDF2-HMAC-SHA3-384 is not
         *         available in native wolfCrypt.
         */
        public wcPBKDF2WithHmacSHA3_384() throws NoSuchAlgorithmException {
            super(FactoryType.WC_SKF_PBKDF2_HMAC_SHA3_384);
        }
    }

    /**
     * wolfJCE PBKDF2WithHmacSHA3_512 SecretKeyFactory class.
     */
    public static final class wcPBKDF2WithHmacSHA3_512
        extends WolfCryptSecretKeyFactory {

        /**
         * Create new wcPBKDF2WithHmacSHA3_512 object.
         *
         * @throws NoSuchAlgorithmException if PBKDF2-HMAC-SHA3-512 is not
         *         available in native wolfCrypt.
         */
        public wcPBKDF2WithHmacSHA3_512() throws NoSuchAlgorithmException {
            super(FactoryType.WC_SKF_PBKDF2_HMAC_SHA3_512);
        }
    }
}

