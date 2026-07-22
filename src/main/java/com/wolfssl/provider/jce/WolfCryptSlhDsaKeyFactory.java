/* WolfCryptSlhDsaKeyFactory.java
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

package com.wolfssl.provider.jce;

import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.wolfssl.wolfcrypt.SlhDsa;

/**
 * wolfJCE SLH-DSA (FIPS 205) KeyFactory implementation.
 *
 * <p>Converts between encoded forms ({@link PKCS8EncodedKeySpec} for private
 * keys, {@link X509EncodedKeySpec} for public keys) and
 * {@link WolfCryptSlhDsaPrivateKey} / {@link WolfCryptSlhDsaPublicKey}
 * objects. The parameter set is carried in the encoded AlgorithmIdentifier
 * OID (RFC 9909).</p>
 *
 * <p>The per-parameter-set factories (e.g. {@code SLH-DSA-SHA2-128f}) reject
 * keys of a different parameter set. The generic {@code SLH-DSA} factory
 * accepts keys of any parameter set.</p>
 */
public class WolfCryptSlhDsaKeyFactory extends KeyFactorySpi {

    /** No required parameter set, accept any. */
    private static final int PARAM_ANY = -1;

    /** Required SLH-DSA parameter set for keys produced by this factory, one
     * of {@code SlhDsa.SLH_DSA_*} (0-11), or {@link #PARAM_ANY} to accept any
     * parameter set. */
    private final int requiredParam;

    /**
     * Create a new wolfJCE SLH-DSA KeyFactory accepting any parameter set.
     */
    public WolfCryptSlhDsaKeyFactory() {
        this(PARAM_ANY);
    }

    /**
     * Create a new wolfJCE SLH-DSA KeyFactory with a required parameter set.
     *
     * @param requiredParam {@link #PARAM_ANY} to accept any parameter set,
     *        otherwise one of {@code SlhDsa.SLH_DSA_*}
     */
    protected WolfCryptSlhDsaKeyFactory(int requiredParam) {

        this.requiredParam = requiredParam;

        log("created new SLH-DSA KeyFactory (requiredParam: " +
            requiredParam + ")");
    }

    /** SLH-DSA-SHAKE-128s only KeyFactory. */
    public static final class wcSlhDsaShake_128s
        extends WolfCryptSlhDsaKeyFactory {
        /** Default constructor. */
        public wcSlhDsaShake_128s() {
            super(SlhDsa.SLH_DSA_SHAKE_128S);
        }
    }

    /** SLH-DSA-SHAKE-128f only KeyFactory. */
    public static final class wcSlhDsaShake_128f
        extends WolfCryptSlhDsaKeyFactory {
        /** Default constructor. */
        public wcSlhDsaShake_128f() {
            super(SlhDsa.SLH_DSA_SHAKE_128F);
        }
    }

    /** SLH-DSA-SHAKE-192s only KeyFactory. */
    public static final class wcSlhDsaShake_192s
        extends WolfCryptSlhDsaKeyFactory {
        /** Default constructor. */
        public wcSlhDsaShake_192s() {
            super(SlhDsa.SLH_DSA_SHAKE_192S);
        }
    }

    /** SLH-DSA-SHAKE-192f only KeyFactory. */
    public static final class wcSlhDsaShake_192f
        extends WolfCryptSlhDsaKeyFactory {
        /** Default constructor. */
        public wcSlhDsaShake_192f() {
            super(SlhDsa.SLH_DSA_SHAKE_192F);
        }
    }

    /** SLH-DSA-SHAKE-256s only KeyFactory. */
    public static final class wcSlhDsaShake_256s
        extends WolfCryptSlhDsaKeyFactory {
        /** Default constructor. */
        public wcSlhDsaShake_256s() {
            super(SlhDsa.SLH_DSA_SHAKE_256S);
        }
    }

    /** SLH-DSA-SHAKE-256f only KeyFactory. */
    public static final class wcSlhDsaShake_256f
        extends WolfCryptSlhDsaKeyFactory {
        /** Default constructor. */
        public wcSlhDsaShake_256f() {
            super(SlhDsa.SLH_DSA_SHAKE_256F);
        }
    }

    /** SLH-DSA-SHA2-128s only KeyFactory. */
    public static final class wcSlhDsaSha2_128s
        extends WolfCryptSlhDsaKeyFactory {
        /** Default constructor. */
        public wcSlhDsaSha2_128s() {
            super(SlhDsa.SLH_DSA_SHA2_128S);
        }
    }

    /** SLH-DSA-SHA2-128f only KeyFactory. */
    public static final class wcSlhDsaSha2_128f
        extends WolfCryptSlhDsaKeyFactory {
        /** Default constructor. */
        public wcSlhDsaSha2_128f() {
            super(SlhDsa.SLH_DSA_SHA2_128F);
        }
    }

    /** SLH-DSA-SHA2-192s only KeyFactory. */
    public static final class wcSlhDsaSha2_192s
        extends WolfCryptSlhDsaKeyFactory {
        /** Default constructor. */
        public wcSlhDsaSha2_192s() {
            super(SlhDsa.SLH_DSA_SHA2_192S);
        }
    }

    /** SLH-DSA-SHA2-192f only KeyFactory. */
    public static final class wcSlhDsaSha2_192f
        extends WolfCryptSlhDsaKeyFactory {
        /** Default constructor. */
        public wcSlhDsaSha2_192f() {
            super(SlhDsa.SLH_DSA_SHA2_192F);
        }
    }

    /** SLH-DSA-SHA2-256s only KeyFactory. */
    public static final class wcSlhDsaSha2_256s
        extends WolfCryptSlhDsaKeyFactory {
        /** Default constructor. */
        public wcSlhDsaSha2_256s() {
            super(SlhDsa.SLH_DSA_SHA2_256S);
        }
    }

    /** SLH-DSA-SHA2-256f only KeyFactory. */
    public static final class wcSlhDsaSha2_256f
        extends WolfCryptSlhDsaKeyFactory {
        /** Default constructor. */
        public wcSlhDsaSha2_256f() {
            super(SlhDsa.SLH_DSA_SHA2_256F);
        }
    }

    /**
     * Check a key parameter set against this factory's required parameter set.
     *
     * @param param parameter set of the key being produced or inspected
     *
     * @throws InvalidKeySpecException if the factory is parameter-set specific
     *         and the key parameter set does not match
     */
    private void checkParamMatchesRequired(int param)
        throws InvalidKeySpecException {

        if ((requiredParam != PARAM_ANY) && (param != requiredParam)) {
            throw new InvalidKeySpecException(
                "Key parameter set does not match KeyFactory: expected " +
                WolfPQCJdkCompat.slhDsaParamToName(requiredParam) +
                ", got " + WolfPQCJdkCompat.slhDsaParamToName(param));
        }
    }

    private void log(String msg) {
        WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO,
            () -> "[SLH-DSA KeyFactory] " + msg);
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
        throws InvalidKeySpecException {

        byte[] encoded;

        if (keySpec == null) {
            throw new InvalidKeySpecException("KeySpec cannot be null");
        }

        if (!(keySpec instanceof PKCS8EncodedKeySpec)) {
            throw new InvalidKeySpecException(
                "Unsupported KeySpec type for SLH-DSA private key: " +
                keySpec.getClass().getName() +
                " (expected PKCS8EncodedKeySpec)");
        }

        encoded = ((PKCS8EncodedKeySpec) keySpec).getEncoded();
        if (encoded == null || encoded.length == 0) {
            throw new InvalidKeySpecException(
                "PKCS8EncodedKeySpec is empty");
        }

        try {
            WolfCryptSlhDsaPrivateKey key =
                new WolfCryptSlhDsaPrivateKey(encoded);
            checkParamMatchesRequired(key.getParam());
            return key;
        }
        catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException(e.getMessage(), e);
        }
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec)
        throws InvalidKeySpecException {

        byte[] encoded;

        if (keySpec == null) {
            throw new InvalidKeySpecException("KeySpec cannot be null");
        }

        if (!(keySpec instanceof X509EncodedKeySpec)) {
            throw new InvalidKeySpecException(
                "Unsupported KeySpec type for SLH-DSA public key: " +
                keySpec.getClass().getName() +
                " (expected X509EncodedKeySpec)");
        }

        encoded = ((X509EncodedKeySpec) keySpec).getEncoded();
        if (encoded == null || encoded.length == 0) {
            throw new InvalidKeySpecException(
                "X509EncodedKeySpec is empty");
        }

        try {
            WolfCryptSlhDsaPublicKey key =
                new WolfCryptSlhDsaPublicKey(encoded);
            checkParamMatchesRequired(key.getParam());
            return key;
        }
        catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException(e.getMessage(), e);
        }
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
        throws InvalidKeySpecException {

        byte[] encoded;
        Key wolfKey;

        if (key == null) {
            throw new InvalidKeySpecException("Key cannot be null");
        }

        if (keySpec == null) {
            throw new InvalidKeySpecException(
                "Requested KeySpec class cannot be null");
        }

        /* Normalize key types, validates parameter set on wolfJCE keys and
         * encoding/DER/parameter set on foreign keys. */
        try {
            wolfKey = engineTranslateKey(key);
        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException(e.getMessage(), e);
        }

        if (wolfKey instanceof PrivateKey) {
            if (!keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
                throw new InvalidKeySpecException(
                    "SLH-DSA private keys can only be expressed as " +
                    "PKCS8EncodedKeySpec, got request for: " +
                    keySpec.getName());
            }
            encoded = WolfCryptUtil.requireEncoded(wolfKey, "PKCS#8");
            return keySpec.cast(new PKCS8EncodedKeySpec(encoded));
        }

        if (wolfKey instanceof PublicKey) {
            if (!keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
                throw new InvalidKeySpecException(
                    "SLH-DSA public keys can only be expressed as " +
                    "X509EncodedKeySpec, got request for: " +
                    keySpec.getName());
            }
            encoded = WolfCryptUtil.requireEncoded(wolfKey, "X.509");
            return keySpec.cast(new X509EncodedKeySpec(encoded));
        }

        throw new InvalidKeySpecException(
            "Unsupported Key type: " + key.getClass().getName());
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {

        byte[] encoded;

        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }

        try {
            /* Already one of ours, no translation needed but parameter set is
             * still checked for parameter-set specific factories. */
            if (key instanceof WolfCryptSlhDsaPrivateKey) {
                checkParamMatchesRequired(
                    ((WolfCryptSlhDsaPrivateKey)key).getParam());
                return key;
            }

            if (key instanceof WolfCryptSlhDsaPublicKey) {
                checkParamMatchesRequired(
                    ((WolfCryptSlhDsaPublicKey)key).getParam());
                return key;
            }

            if (key instanceof PrivateKey) {
                String fmt = key.getFormat();
                if (!"PKCS#8".equalsIgnoreCase(fmt)) {
                    throw new InvalidKeyException(
                        "Cannot translate SLH-DSA private key with format: " +
                        fmt + " (expected PKCS#8)");
                }

                encoded = key.getEncoded();
                if (encoded == null || encoded.length == 0) {
                    throw new InvalidKeyException(
                        "Source private key has no PKCS#8 encoding");
                }

                try {
                    WolfCryptSlhDsaPrivateKey translated =
                        new WolfCryptSlhDsaPrivateKey(encoded);
                    checkParamMatchesRequired(translated.getParam());
                    return translated;
                }
                catch (IllegalArgumentException e) {
                    throw new InvalidKeyException(
                        "Source key is not a valid SLH-DSA PKCS#8 key: " +
                        e.getMessage(), e);
                }
            }

            if (key instanceof PublicKey) {
                String fmt = key.getFormat();
                if (!"X.509".equalsIgnoreCase(fmt)) {
                    throw new InvalidKeyException(
                        "Cannot translate SLH-DSA public key with format: " +
                        fmt + " (expected X.509)");
                }

                encoded = key.getEncoded();
                if (encoded == null || encoded.length == 0) {
                    throw new InvalidKeyException(
                        "Source public key has no X.509 encoding");
                }

                try {
                    WolfCryptSlhDsaPublicKey translated =
                        new WolfCryptSlhDsaPublicKey(encoded);
                    checkParamMatchesRequired(translated.getParam());
                    return translated;
                }
                catch (IllegalArgumentException e) {
                    throw new InvalidKeyException(
                        "Source key is not a valid SLH-DSA X.509 SPKI: " +
                        e.getMessage(), e);
                }
            }
        }
        catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(e.getMessage(), e);
        }

        throw new InvalidKeyException(
            "Unsupported Key type: " + key.getClass().getName());
    }

}
