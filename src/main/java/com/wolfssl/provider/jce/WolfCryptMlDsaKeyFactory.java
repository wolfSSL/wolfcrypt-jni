/* WolfCryptMlDsaKeyFactory.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.wolfssl.wolfcrypt.MlDsa;

/**
 * wolfJCE ML-DSA (FIPS 204) KeyFactory implementation.
 *
 * <p>Converts between encoded forms ({@link PKCS8EncodedKeySpec} for
 * private keys, {@link X509EncodedKeySpec} for public keys) and
 * {@link WolfCryptMlDsaPrivateKey} / {@link WolfCryptMlDsaPublicKey}
 * objects. The parameter set (44/65/87) is carried in the encoded
 * AlgorithmIdentifier OID.</p>
 *
 * <p>The per-parameter-set factories ({@code ML-DSA-44/65/87}) reject keys of
 * a different parameter set, matching JDK 24+ SunJCE NamedKeyFactory
 * semantics. The generic {@code ML-DSA} factory accepts keys of any
 * parameter set.</p>
 */
public class WolfCryptMlDsaKeyFactory extends KeyFactorySpi {

    /** Required ML-DSA level for keys produced by this factory, one of
     * MlDsa.ML_DSA_44/65/87, or 0 to accept any parameter set. */
    private final int requiredLevel;

    /**
     * Create a new wolfJCE ML-DSA KeyFactory accepting any parameter set.
     */
    public WolfCryptMlDsaKeyFactory() {
        this(0);
    }

    /**
     * Create a new wolfJCE ML-DSA KeyFactory with a required level.
     *
     * @param requiredLevel 0 to accept any parameter set, otherwise one
     *        of MlDsa.ML_DSA_44/65/87
     */
    protected WolfCryptMlDsaKeyFactory(int requiredLevel) {
        this.requiredLevel = requiredLevel;
        log("created new ML-DSA KeyFactory (requiredLevel: " +
            requiredLevel + ")");
    }

    /**
     * ML-DSA-44 only KeyFactory.
     */
    public static final class wcMlDsa44 extends WolfCryptMlDsaKeyFactory {
        /** Default constructor. */
        public wcMlDsa44() {
            super(MlDsa.ML_DSA_44);
        }
    }

    /**
     * ML-DSA-65 only KeyFactory.
     */
    public static final class wcMlDsa65 extends WolfCryptMlDsaKeyFactory {
        /** Default constructor. */
        public wcMlDsa65() {
            super(MlDsa.ML_DSA_65);
        }
    }

    /**
     * ML-DSA-87 only KeyFactory.
     */
    public static final class wcMlDsa87 extends WolfCryptMlDsaKeyFactory {
        /** Default constructor. */
        public wcMlDsa87() {
            super(MlDsa.ML_DSA_87);
        }
    }

    /**
     * Check a key level against this factory's required level.
     *
     * @param level level of the key being produced or inspected
     *
     * @throws InvalidKeySpecException if the factory is parameter-set
     *         specific and the key level does not match
     */
    private void checkLevelMatchesRequired(int level)
        throws InvalidKeySpecException {

        if (requiredLevel != 0 && level != requiredLevel) {
            throw new InvalidKeySpecException(
                "Key parameter set does not match KeyFactory: expected " +
                WolfPQCJdkCompat.levelToParamName(requiredLevel) +
                ", got " + WolfPQCJdkCompat.levelToParamName(level));
        }
    }

    private void log(String msg) {
        WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO,
            () -> "[ML-DSA KeyFactory] " + msg);
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
        throws InvalidKeySpecException {

        if (keySpec == null) {
            throw new InvalidKeySpecException("KeySpec cannot be null");
        }
        if (!(keySpec instanceof PKCS8EncodedKeySpec)) {
            throw new InvalidKeySpecException(
                "Unsupported KeySpec type for ML-DSA private key: " +
                keySpec.getClass().getName() +
                " (expected PKCS8EncodedKeySpec)");
        }

        byte[] encoded = ((PKCS8EncodedKeySpec) keySpec).getEncoded();
        if (encoded == null || encoded.length == 0) {
            throw new InvalidKeySpecException(
                "PKCS8EncodedKeySpec is empty");
        }

        try {
            WolfCryptMlDsaPrivateKey key =
                new WolfCryptMlDsaPrivateKey(encoded);
            checkLevelMatchesRequired(key.getLevel());
            return key;
        }
        catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException(
                "Invalid ML-DSA PKCS#8 DER: " + e.getMessage(), e);
        }
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec)
        throws InvalidKeySpecException {

        if (keySpec == null) {
            throw new InvalidKeySpecException("KeySpec cannot be null");
        }
        if (!(keySpec instanceof X509EncodedKeySpec)) {
            throw new InvalidKeySpecException(
                "Unsupported KeySpec type for ML-DSA public key: " +
                keySpec.getClass().getName() +
                " (expected X509EncodedKeySpec)");
        }

        byte[] encoded = ((X509EncodedKeySpec) keySpec).getEncoded();
        if (encoded == null || encoded.length == 0) {
            throw new InvalidKeySpecException(
                "X509EncodedKeySpec is empty");
        }

        try {
            WolfCryptMlDsaPublicKey key =
                new WolfCryptMlDsaPublicKey(encoded);
            checkLevelMatchesRequired(key.getLevel());
            return key;
        }
        catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException(
                "Invalid ML-DSA X.509 SPKI DER: " + e.getMessage(), e);
        }
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
        throws InvalidKeySpecException {

        Key wolfKey;

        if (key == null) {
            throw new InvalidKeySpecException("Key cannot be null");
        }
        if (keySpec == null) {
            throw new InvalidKeySpecException(
                "Requested KeySpec class cannot be null");
        }

        /* Normalize key types, validates level on wolfJCE and
         * encoding/DER/level on foreign keys. */
        try {
            wolfKey = engineTranslateKey(key);
        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException(e.getMessage(), e);
        }

        if (wolfKey instanceof PrivateKey) {
            if (!keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
                throw new InvalidKeySpecException(
                    "ML-DSA private keys can only be expressed as " +
                    "PKCS8EncodedKeySpec, got request for: " +
                    keySpec.getName());
            }
            byte[] encoded = WolfCryptUtil.requireEncoded(wolfKey, "PKCS#8");
            return keySpec.cast(new PKCS8EncodedKeySpec(encoded));
        }

        if (wolfKey instanceof PublicKey) {
            if (!keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
                throw new InvalidKeySpecException(
                    "ML-DSA public keys can only be expressed as " +
                    "X509EncodedKeySpec, got request for: " +
                    keySpec.getName());
            }
            byte[] encoded = WolfCryptUtil.requireEncoded(wolfKey, "X.509");
            return keySpec.cast(new X509EncodedKeySpec(encoded));
        }

        throw new InvalidKeySpecException(
            "Unsupported Key type: " + key.getClass().getName());
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {

        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }

        try {
            /* Already one of ours, no translation needed but level is
             * still checked for parameter-set specific factories. */
            if (key instanceof WolfCryptMlDsaPrivateKey) {
                checkLevelMatchesRequired(
                    ((WolfCryptMlDsaPrivateKey)key).getLevel());
                return key;
            }
            if (key instanceof WolfCryptMlDsaPublicKey) {
                checkLevelMatchesRequired(
                    ((WolfCryptMlDsaPublicKey)key).getLevel());
                return key;
            }

            if (key instanceof PrivateKey) {
                String fmt = key.getFormat();
                if (!"PKCS#8".equalsIgnoreCase(fmt)) {
                    throw new InvalidKeyException(
                        "Cannot translate ML-DSA private key with format: " +
                        fmt + " (expected PKCS#8)");
                }
                byte[] encoded = key.getEncoded();
                if (encoded == null || encoded.length == 0) {
                    throw new InvalidKeyException(
                        "Source private key has no PKCS#8 encoding");
                }
                try {
                    WolfCryptMlDsaPrivateKey translated =
                        new WolfCryptMlDsaPrivateKey(encoded);
                    checkLevelMatchesRequired(translated.getLevel());
                    return translated;
                }
                catch (IllegalArgumentException e) {
                    throw new InvalidKeyException(
                        "Source key is not a valid ML-DSA PKCS#8 key: " +
                        e.getMessage(), e);
                }
            }

            if (key instanceof PublicKey) {
                String fmt = key.getFormat();
                if (!"X.509".equalsIgnoreCase(fmt)) {
                    throw new InvalidKeyException(
                        "Cannot translate ML-DSA public key with format: " +
                        fmt + " (expected X.509)");
                }
                byte[] encoded = key.getEncoded();
                if (encoded == null || encoded.length == 0) {
                    throw new InvalidKeyException(
                        "Source public key has no X.509 encoding");
                }
                try {
                    WolfCryptMlDsaPublicKey translated =
                        new WolfCryptMlDsaPublicKey(encoded);
                    checkLevelMatchesRequired(translated.getLevel());
                    return translated;
                }
                catch (IllegalArgumentException e) {
                    throw new InvalidKeyException(
                        "Source key is not a valid ML-DSA X.509 SPKI: " +
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
