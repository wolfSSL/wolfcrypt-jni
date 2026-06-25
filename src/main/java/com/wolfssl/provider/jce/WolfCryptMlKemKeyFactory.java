/* WolfCryptMlKemKeyFactory.java
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

import java.util.Arrays;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.InvalidKeyException;
import java.security.spec.KeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.wolfssl.wolfcrypt.MlKem;

/**
 * wolfCrypt JCE ML-KEM (FIPS 203) KeyFactory implementation.
 *
 * Converts between encoded key specifications (X.509 SubjectPublicKeyInfo and
 * PKCS#8 PrivateKeyInfo) and wolfJCE ML-KEM key objects. Foreign ML-KEM keys
 * (from JDK reference implementation) are accepted via their encoded form so
 * applications can migrate between providers.
 *
 * The base class accepts any ML-KEM parameter set. The level-specific inner
 * classes (wcMlKem512/768/1024) reject keys whose parameter set does not
 * match.
 */
public class WolfCryptMlKemKeyFactory extends KeyFactorySpi {

    /* Required parameter set level, or -1 to accept any level. */
    private final int requiredLevel;

    /**
     * Create a new ML-KEM KeyFactory accepting any parameter set.
     */
    public WolfCryptMlKemKeyFactory() {

        this.requiredLevel = -1;

        log("created new ML-KEM KeyFactory");
    }

    /**
     * Create a new ML-KEM KeyFactory restricted to a single parameter set.
     *
     * @param level required ML-KEM parameter set level
     */
    protected WolfCryptMlKemKeyFactory(int level) {

        this.requiredLevel = level;

        log("created new ML-KEM KeyFactory for level " + level);
    }

    private void log(String msg) {
        WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO,
            () -> "[ML-KEM KeyFactory] " + msg);
    }

    /**
     * Verify a parsed key level matches the required level for this factory.
     */
    private void checkLevel(int level) throws InvalidKeySpecException {

        if (this.requiredLevel >= 0 && level != this.requiredLevel) {
            throw new InvalidKeySpecException(
                "ML-KEM key level " + level +
                " does not match required level " + this.requiredLevel);
        }
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
        throws InvalidKeySpecException {

        byte[] der;
        WolfCryptMlKemPrivateKey key;

        if (keySpec == null) {
            throw new InvalidKeySpecException("KeySpec cannot be null");
        }

        if (!(keySpec instanceof PKCS8EncodedKeySpec)) {
            throw new InvalidKeySpecException(
                "Unsupported KeySpec type, expected PKCS8EncodedKeySpec: " +
                keySpec.getClass().getName());
        }

        der = ((PKCS8EncodedKeySpec)keySpec).getEncoded();
        if (der == null) {
            throw new InvalidKeySpecException(
                "PKCS8EncodedKeySpec contains null encoded key");
        }

        try {
            key = new WolfCryptMlKemPrivateKey(der);
        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException(
                "Invalid ML-KEM PKCS#8 private key: " + e.getMessage(), e);
        } finally {
            Arrays.fill(der, (byte)0);
        }

        checkLevel(key.getLevel());

        log("generated ML-KEM private key from PKCS#8");

        return key;
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec)
        throws InvalidKeySpecException {

        byte[] der;
        WolfCryptMlKemPublicKey key;

        if (keySpec == null) {
            throw new InvalidKeySpecException("KeySpec cannot be null");
        }

        if (!(keySpec instanceof X509EncodedKeySpec)) {
            throw new InvalidKeySpecException(
                "Unsupported KeySpec type, expected X509EncodedKeySpec: " +
                keySpec.getClass().getName());
        }

        der = ((X509EncodedKeySpec)keySpec).getEncoded();
        if (der == null) {
            throw new InvalidKeySpecException(
                "X509EncodedKeySpec contains null encoded key");
        }

        try {
            key = new WolfCryptMlKemPublicKey(der);
        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException(
                "Invalid ML-KEM X.509 public key: " + e.getMessage(), e);
        }

        checkLevel(key.getLevel());

        log("generated ML-KEM public key from X.509");

        return key;
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
        throws InvalidKeySpecException {

        byte[] encoded;

        if (key == null) {
            throw new InvalidKeySpecException("Key cannot be null");
        }

        if (keySpec == null) {
            throw new InvalidKeySpecException(
                "Requested KeySpec format cannot be null");
        }

        if (!WolfCryptMlKemUtil.isMlKemAlgorithm(key.getAlgorithm())) {
            throw new InvalidKeySpecException(
                "Key is not an ML-KEM key: " + key.getAlgorithm());
        }

        encoded = key.getEncoded();
        if (encoded == null) {
            throw new InvalidKeySpecException(
                "Key.getEncoded() returned null");
        }

        try {
            if (key instanceof PrivateKey) {
                if (!keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
                    throw new InvalidKeySpecException(
                        "Unsupported KeySpec for ML-KEM private key: " +
                        keySpec.getName());
                }
                return (T) new PKCS8EncodedKeySpec(encoded);
            }
            else if (key instanceof PublicKey) {
                if (!keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
                    throw new InvalidKeySpecException(
                        "Unsupported KeySpec for ML-KEM public key: " +
                        keySpec.getName());
                }
                return (T) new X509EncodedKeySpec(encoded);
            }
            else {
                throw new InvalidKeySpecException(
                    "Unsupported Key type: " + key.getClass().getName());
            }
        } finally {
            /* EncodedKeySpec copies input, clear copy of key */
            Arrays.fill(encoded, (byte)0);
        }
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {

        byte[] encoded;

        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }

        if (!WolfCryptMlKemUtil.isMlKemAlgorithm(key.getAlgorithm())) {
            throw new InvalidKeyException(
                "Key is not an ML-KEM key: " + key.getAlgorithm());
        }

        encoded = key.getEncoded();
        if (encoded == null) {
            throw new InvalidKeyException("Key.getEncoded() returned null");
        }

        try {
            if (key instanceof PrivateKey) {
                return engineGeneratePrivate(new PKCS8EncodedKeySpec(encoded));
            }
            else if (key instanceof PublicKey) {
                return engineGeneratePublic(new X509EncodedKeySpec(encoded));
            }
            else {
                throw new InvalidKeyException(
                    "Unsupported Key type: " + key.getClass().getName());
            }

        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(
                "Failed to translate ML-KEM key: " + e.getMessage(), e);

        } finally {
            /* EncodedKeySpec copies input, clear copy of key */
            Arrays.fill(encoded, (byte)0);
        }
    }

    /**
     * wolfCrypt ML-KEM-512 KeyFactory class.
     */
    public static final class wcMlKem512 extends WolfCryptMlKemKeyFactory {
        /**
         * Create new wcMlKem512 object.
         */
        public wcMlKem512() {
            super(MlKem.ML_KEM_512);
        }
    }

    /**
     * wolfCrypt ML-KEM-768 KeyFactory class.
     */
    public static final class wcMlKem768 extends WolfCryptMlKemKeyFactory {
        /**
         * Create new wcMlKem768 object.
         */
        public wcMlKem768() {
            super(MlKem.ML_KEM_768);
        }
    }

    /**
     * wolfCrypt ML-KEM-1024 KeyFactory class.
     */
    public static final class wcMlKem1024 extends WolfCryptMlKemKeyFactory {
        /**
         * Create new wcMlKem1024 object.
         */
        public wcMlKem1024() {
            super(MlKem.ML_KEM_1024);
        }
    }
}

