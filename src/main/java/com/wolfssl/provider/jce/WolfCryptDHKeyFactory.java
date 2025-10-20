/* WolfCryptDHKeyFactory.java
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
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.InvalidKeyException;
import java.security.spec.KeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

import com.wolfssl.wolfcrypt.Dh;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfCrypt JCE DH KeyFactory implementation.
 *
 * This class provides key conversion capabilities for Diffie-Hellman (DH)
 * keys, supporting conversion between various KeySpec formats and Key objects.
 */
public class WolfCryptDHKeyFactory extends KeyFactorySpi {

    /**
     * Create new WolfCryptDHKeyFactory object.
     */
    public WolfCryptDHKeyFactory() {
        log("created new DH KeyFactory");
    }

    /**
     * Internal method for logging output.
     *
     * @param msg message to be logged
     */
    private void log(String msg) {
        WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO,
            () -> "[DH KeyFactory] " + msg);
    }

    /**
     * Generate a private key object from the provided key specification.
     *
     * @param keySpec the KeySpec of the private key
     *
     * @return the private key object
     *
     * @throws InvalidKeySpecException if the given key specification
     *         is inappropriate for this KeyFactory to produce a private key.
     *         Currently supported KeySpec types are: PKCS8EncodedKeySpec
     *         and DHPrivateKeySpec
     */
    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
        throws InvalidKeySpecException {

        log("generating DHPrivateKey from KeySpec");

        if (keySpec == null) {
            throw new InvalidKeySpecException("KeySpec cannot be null");
        }

        if (keySpec instanceof PKCS8EncodedKeySpec) {
            return generatePrivateFromPKCS8((PKCS8EncodedKeySpec)keySpec);
        }
        else if (keySpec instanceof DHPrivateKeySpec) {
            return generatePrivateFromDHSpec((DHPrivateKeySpec)keySpec);
        }
        else {
            throw new InvalidKeySpecException(
                "Unsupported KeySpec type: " + keySpec.getClass().getName());
        }
    }

    /**
     * Generates a public key object from the provided key specification.
     *
     * @param keySpec the KeySpec of the public key
     *
     * @return the public key object
     *
     * @throws InvalidKeySpecException if the given key specification
     *         is inappropriate for this KeyFactory to produce a public key.
     *         Currently supported KeySpec types are: X509EncodedKeySpec
     *         and DHPublicKeySpec.
     */
    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec)
        throws InvalidKeySpecException {

        log("generating DHPublicKey from KeySpec");

        if (keySpec == null) {
            throw new InvalidKeySpecException("KeySpec cannot be null");
        }

        if (keySpec instanceof X509EncodedKeySpec) {
            return generatePublicFromX509((X509EncodedKeySpec)keySpec);
        }
        else if (keySpec instanceof DHPublicKeySpec) {
            return generatePublicFromDHSpec((DHPublicKeySpec)keySpec);
        }
        else {
            throw new InvalidKeySpecException(
                "Unsupported KeySpec type: " + keySpec.getClass().getName());
        }
    }

    /**
     * Returns a KeySpec of the given Key object in the requested format.
     *
     * @param key the Key object, must be one of DHPrivateKey or DHPublicKey
     * @param keySpec the requested format in which the key material shall
     *                be returned
     *
     * @return a KeySpec in the requested format matching the input Key
     *
     * @throws InvalidKeySpecException if the requested key specification
     *         is inappropriate for the given key, or the provided key cannot
     *         be processed by this key factory.
     */
    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key,
        Class<T> keySpec) throws InvalidKeySpecException {

        log("returning KeySpec from Key in requested type");

        if (key == null) {
            throw new InvalidKeySpecException("Key cannot be null");
        }

        if (keySpec == null) {
            throw new InvalidKeySpecException(
                "Requested KeySpec format cannot be null");
        }

        if (key instanceof DHPrivateKey) {
            return getPrivateKeySpec((DHPrivateKey)key, keySpec);
        }
        else if (key instanceof DHPublicKey) {
            return getPublicKeySpec((DHPublicKey)key, keySpec);
        }
        else {
            throw new InvalidKeySpecException(
                "Unsupported Key type: " + key.getClass().getName());
        }
    }

    /**
     * Translates a Key object, whose provider may be unknown or potentially
     * untrusted, into a corresponding Key object of this KeyFactory.
     *
     * @param key the Key to be translated, must be one of DHPrivateKey
     *        or DHPublicKey
     *
     * @return the translated Key
     *
     * @throws InvalidKeyException if the given key cannot be processed
     *         by this KeyFactory
     */
    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {

        log("translating Key to wolfJCE DH KeyFactory type");

        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }

        if (key instanceof DHPrivateKey) {
            return translatePrivateKey((DHPrivateKey)key);
        }
        else if (key instanceof DHPublicKey) {
            return translatePublicKey((DHPublicKey)key);
        }
        else {
            throw new InvalidKeyException(
                "Unsupported Key type: " + key.getClass().getName());
        }
    }

    /**
     * Private helper method for generating DHPrivateKey from
     * PKCS8EncodedKeySpec.
     *
     * @param keySpec the PKCS8EncodedKeySpec containing the private key
     *
     * @return the generated DHPrivateKey
     *
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    private PrivateKey generatePrivateFromPKCS8(PKCS8EncodedKeySpec keySpec)
        throws InvalidKeySpecException {

        if (keySpec == null) {
            throw new InvalidKeySpecException(
                "PKCS8EncodedKeySpec cannot be null");
        }

        /* Get DER-encoded PKCS#8 data from spec */
        byte[] pkcs8Der = keySpec.getEncoded();
        if (pkcs8Der == null) {
            throw new InvalidKeySpecException(
                "PKCS8EncodedKeySpec contains null encoded key");
        }

        log("generating DHPrivateKey from PKCS8EncodedKeySpec, length: " +
            pkcs8Der.length);

        try {
            /* Create wolfJCE DHPrivateKey object directly from PKCS#8 DER.
             * WolfCryptDHPrivateKey will parse the PKCS#8 DER in Java,
             * which works with all wolfSSL builds including FIPS without
             * requiring WOLFSSL_DH_EXTRA. */
            return new WolfCryptDHPrivateKey(pkcs8Der);

        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException(
                "Invalid PKCS#8 key data: " + e.getMessage(), e);
        }
    }

    /**
     * Private helper method for generating DHPrivateKey from
     * DHPrivateKeySpec.
     *
     * This method creates the key directly using WolfCryptDHPrivateKey,
     * which generates PKCS#8 DER in pure Java to support wolfCrypt FIPS
     * builds that do not define WOLFSSL_DH_EXTRA.
     *
     * If WOLFSSL_DH_EXTRA were available, we could use:
     *   - wc_DhImportKeyPair() to import the key
     *   - wc_DhPrivKeyToDer() to encode as PKCS#8
     *
     * @param keySpec the DHPrivateKeySpec containing the private key
     *
     * @return the generated DHPrivateKey
     *
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    private PrivateKey generatePrivateFromDHSpec(DHPrivateKeySpec keySpec)
        throws InvalidKeySpecException {

        log("generating DHPrivateKey from DHPrivateKeySpec");

        if (keySpec == null) {
            throw new InvalidKeySpecException(
                "DHPrivateKeySpec cannot be null");
        }
        if (keySpec.getX() == null) {
            throw new InvalidKeySpecException(
                "Private key value cannot be null");
        }
        if (keySpec.getP() == null) {
            throw new InvalidKeySpecException(
                "Parameter P cannot be null");
        }
        if (keySpec.getG() == null) {
            throw new InvalidKeySpecException(
                "Parameter G cannot be null");
        }

        /* Validate private key is positive */
        if (keySpec.getX().signum() <= 0) {
            throw new InvalidKeySpecException(
                "Private key value must be positive");
        }

        try {
            /* Create DHParameterSpec from p and g */
            DHParameterSpec paramSpec = new DHParameterSpec(
                keySpec.getP(), keySpec.getG());

            /* Create WolfCryptDHPrivateKey directly - it will generate
             * PKCS#8 DER using pure Java (no WOLFSSL_DH_EXTRA needed) */
            return new WolfCryptDHPrivateKey(keySpec.getX(), paramSpec);

        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException(
                "Failed to create DHPrivateKey from spec: " +
                e.getMessage(), e);
        }
    }

    /**
     * Private helper method for generating DHPublicKey from
     * X509EncodedKeySpec.
     *
     * @param keySpec the X509EncodedKeySpec containing the public key
     *
     * @return the generated DHPublicKey
     *
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    private PublicKey generatePublicFromX509(X509EncodedKeySpec keySpec)
        throws InvalidKeySpecException {

        if (keySpec == null) {
            throw new InvalidKeySpecException(
                "X509EncodedKeySpec cannot be null");
        }

        /* Get DER-encoded X.509 data from spec */
        byte[] x509Der = keySpec.getEncoded();
        if (x509Der == null) {
            throw new InvalidKeySpecException(
                "X509EncodedKeySpec contains null encoded key");
        }

        log("generating DHPublicKey from X509EncodedKeySpec, length: " +
            x509Der.length);

        try {
            return new WolfCryptDHPublicKey(x509Der);

        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException(
                "Invalid X.509 key data: " + e.getMessage(), e);
        }
    }

    /**
     * Private helper method for generating DHPublicKey from DHPublicKeySpec.
     *
     * This method creates the key directly using WolfCryptDHPublicKey,
     * which generates X.509 DER in pure Java to support wolfCrypt FIPS
     * builds that do not define WOLFSSL_DH_EXTRA.
     *
     * If WOLFSSL_DH_EXTRA were available, we could use:
     *   - wc_DhImportKeyPair() to import the key
     *   - wc_DhPubKeyToDer() to encode as DER
     *
     * @param keySpec the DHPublicKeySpec containing the public key
     *
     * @return the generated DHPublicKey
     *
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    private PublicKey generatePublicFromDHSpec(DHPublicKeySpec keySpec)
        throws InvalidKeySpecException {

        log("generating DHPublicKey from DHPublicKeySpec");

        if (keySpec == null) {
            throw new InvalidKeySpecException(
                "DHPublicKeySpec cannot be null");
        }
        if (keySpec.getY() == null) {
            throw new InvalidKeySpecException(
                "Public key value cannot be null");
        }
        if (keySpec.getP() == null) {
            throw new InvalidKeySpecException(
                "Parameter P cannot be null");
        }
        if (keySpec.getG() == null) {
            throw new InvalidKeySpecException(
                "Parameter G cannot be null");
        }

        /* Validate public key is positive */
        if (keySpec.getY().signum() <= 0) {
            throw new InvalidKeySpecException(
                "Public key value must be positive");
        }

        try {
            /* Create DHParameterSpec from p and g */
            DHParameterSpec paramSpec = new DHParameterSpec(
                keySpec.getP(), keySpec.getG());

            return new WolfCryptDHPublicKey(keySpec.getY(), paramSpec);

        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException(
                "Failed to create DHPublicKey from spec: " +
                e.getMessage(), e);
        }
    }

    /**
     * Private helper methods for extracting KeySpec from Key.
     *
     * @param <T> the type of KeySpec to be returned
     * @param key the DHPrivateKey from which to extract the KeySpec
     * @param keySpec the class object of the requested KeySpec type
     *
     * @return the extracted KeySpec of the requested type
     *
     * @throws InvalidKeySpecException if the KeySpec type is unsupported
     */
    @SuppressWarnings("unchecked")
    private <T extends KeySpec> T getPrivateKeySpec(DHPrivateKey key,
        Class<T> keySpec) throws InvalidKeySpecException {

        try {
            if (key == null) {
                throw new InvalidKeySpecException(
                    "DHPrivateKey cannot be null");
            }
            if (keySpec == null) {
                throw new InvalidKeySpecException(
                    "Requested KeySpec format cannot be null");
            }

            log("extracting private key spec of type: " + keySpec.getName());

            if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
                byte[] encoded = key.getEncoded();
                if (encoded == null) {
                    throw new InvalidKeySpecException(
                        "DHPrivateKey.getEncoded() returned null");
                }
                return (T) new PKCS8EncodedKeySpec(encoded);
            }
            else if (keySpec.isAssignableFrom(DHPrivateKeySpec.class)) {
                /* Extract private value and params directly from key */
                return (T) new DHPrivateKeySpec(key.getX(),
                    key.getParams().getP(), key.getParams().getG());
            }
            else {
                throw new InvalidKeySpecException(
                    "Unsupported KeySpec type: " + keySpec.getName());
            }

        } catch (Exception e) {
            throw new InvalidKeySpecException(
                "Failed to extract private key spec: " + e.getMessage(), e);
        }
    }

    /**
     * Private helper methods for extracting KeySpec from Key.
     *
     * @param <T> the type of KeySpec to be returned
     * @param key the DHPublicKey from which to extract the KeySpec
     * @param keySpec the class object of the requested KeySpec type
     *
     * @return the extracted KeySpec of the requested type
     *
     * @throws InvalidKeySpecException if the KeySpec type is unsupported
     */
    @SuppressWarnings("unchecked")
    private <T extends KeySpec> T getPublicKeySpec(DHPublicKey key,
        Class<T> keySpec) throws InvalidKeySpecException {

        byte[] encoded;

        try {
            if (key == null) {
                throw new InvalidKeySpecException(
                    "DHPublicKey cannot be null");
            }
            if (keySpec == null) {
                throw new InvalidKeySpecException(
                    "Requested KeySpec format cannot be null");
            }

            log("extracting public key spec of type: " + keySpec.getName());

            if (keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
                encoded = key.getEncoded();
                if (encoded == null) {
                    throw new InvalidKeySpecException(
                        "DHPublicKey.getEncoded() returned null");
                }
                return (T) new X509EncodedKeySpec(encoded);
            }
            else if (keySpec.isAssignableFrom(DHPublicKeySpec.class)) {
                /* Extract public value and parameters directly from key */
                return (T) new DHPublicKeySpec(key.getY(),
                    key.getParams().getP(), key.getParams().getG());
            }
            else {
                throw new InvalidKeySpecException(
                    "Unsupported KeySpec type: " + keySpec.getName());
            }

        } catch (Exception e) {
            throw new InvalidKeySpecException(
                "Failed to extract public key spec: " + e.getMessage(), e);
        }
    }

    /**
     * Translate DHPrivateKey from foreign provider into wolfJCE DHPrivateKey.
     *
     * @param key the DHPrivateKey to be translated
     *
     * @return the translated PrivateKey
     *
     * @throws InvalidKeyException if the key cannot be translated
     */
    private PrivateKey translatePrivateKey(DHPrivateKey key)
        throws InvalidKeyException {

        byte[] encoded;
        PKCS8EncodedKeySpec keySpec;

        try {
            log("translating DHPrivateKey from foreign provider");

            if (key == null) {
                throw new InvalidKeyException(
                    "DHPrivateKey cannot be null");
            }

            /* Get encoded format and convert through our KeyFactory */
            encoded = key.getEncoded();
            if (encoded == null) {
                throw new InvalidKeyException(
                    "DHPrivateKey.getEncoded() returned null");
            }

            keySpec = new PKCS8EncodedKeySpec(encoded);
            return engineGeneratePrivate(keySpec);

        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(
                "Failed to translate DHPrivateKey: " + e.getMessage(), e);
        }
    }

    /**
     * Translate DHPublicKey from foreign provider into wolfJCE DHPublicKey.
     *
     * @param key the DHPublicKey to be translated
     *
     * @return the translated PublicKey
     *
     * @throws InvalidKeyException if the key cannot be translated
     */
    private PublicKey translatePublicKey(DHPublicKey key)
        throws InvalidKeyException {

        byte[] encoded;
        X509EncodedKeySpec keySpec;

        try {
            log("translating DHPublicKey from foreign provider");

            if (key == null) {
                throw new InvalidKeyException(
                    "DHPublicKey cannot be null");
            }

            /* Get encoded format and convert through our KeyFactory */
            encoded = key.getEncoded();
            if (encoded == null) {
                throw new InvalidKeyException(
                    "DHPublicKey.getEncoded() returned null");
            }

            keySpec = new X509EncodedKeySpec(encoded);
            return engineGeneratePublic(keySpec);

        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(
                "Failed to translate DHPublicKey: " + e.getMessage(), e);
        }
    }
}

