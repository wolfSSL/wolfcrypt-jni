/* WolfCryptRSAKeyFactory.java
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
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.wolfssl.wolfcrypt.Rsa;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfCrypt JCE RSA KeyFactory implementation.
 *
 * This class provides key conversion capabilities for RSA keys, supporting
 * conversion between various KeySpec formats and Key objects.
 */
public class WolfCryptRSAKeyFactory extends KeyFactorySpi {

    /**
     * Create new WolfCryptRSAKeyFactory object.
     */
    public WolfCryptRSAKeyFactory() {
        log("created new RSA KeyFactory");
    }

    /**
     * Internal method for logging output.
     *
     * @param msg message to be logged
     */
    private void log(String msg) {
        WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO,
            () -> "[RSA KeyFactory] " + msg);
    }

    /**
     * Generate private key object from the provided key specification.
     *
     * @param keySpec the KeySpec of the private key
     *
     * @return the private key object
     *
     * @throws InvalidKeySpecException if the given key specification
     *         is inappropriate for this KeyFactory to produce a private key.
     *         Currently supported KeySpec types are: PKCS8EncodedKeySpec,
     *         RSAPrivateCrtKeySpec, and RSAPrivateKeySpec
     */
    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
        throws InvalidKeySpecException {

        log("generating RSAPrivateKey from KeySpec");

        if (keySpec == null) {
            throw new InvalidKeySpecException("KeySpec cannot be null");
        }

        if (keySpec instanceof PKCS8EncodedKeySpec) {
            return generatePrivateFromPKCS8((PKCS8EncodedKeySpec)keySpec);
        }
        else if (keySpec instanceof RSAPrivateCrtKeySpec) {
            return generatePrivateFromCrtSpec((RSAPrivateCrtKeySpec)keySpec);
        }
        else if (keySpec instanceof RSAPrivateKeySpec) {
            return generatePrivateFromRSASpec((RSAPrivateKeySpec)keySpec);
        }
        else {
            throw new InvalidKeySpecException(
                "Unsupported KeySpec type: " + keySpec.getClass().getName());
        }
    }

    /**
     * Generates public key object from the provided key specification.
     *
     * @param keySpec the KeySpec of the public key
     *
     * @return the public key object
     *
     * @throws InvalidKeySpecException if the given key specification
     *         is inappropriate for this KeyFactory to produce a public key.
     *         Currently supported KeySpec types are: X509EncodedKeySpec
     *         and RSAPublicKeySpec.
     */
    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec)
        throws InvalidKeySpecException {

        log("generating RSAPublicKey from KeySpec");

        if (keySpec == null) {
            throw new InvalidKeySpecException("KeySpec cannot be null");
        }

        if (keySpec instanceof X509EncodedKeySpec) {
            return generatePublicFromX509((X509EncodedKeySpec)keySpec);
        }
        else if (keySpec instanceof RSAPublicKeySpec) {
            return generatePublicFromRSASpec((RSAPublicKeySpec)keySpec);
        }
        else {
            throw new InvalidKeySpecException(
                "Unsupported KeySpec type: " + keySpec.getClass().getName());
        }
    }

    /**
     * Returns KeySpec of the given Key object in the requested format.
     *
     * @param key the Key object, must be one of RSAPrivateKey or RSAPublicKey
     * @param keySpec the requested format in which the key material shall
     *                be returned
     *
     * @return a KeySpec in the requested format matching the input Key
     *
     * @throws InvalidKeySpecException if the requested key specification
     *         is inappropriate for the given key, or the provided key cannot
     *         be processed by this KeyFactory.
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

        if (key instanceof RSAPrivateCrtKey) {
            return getPrivateCrtKeySpec((RSAPrivateCrtKey)key, keySpec);
        }
        else if (key instanceof RSAPrivateKey) {
            return getPrivateKeySpec((RSAPrivateKey)key, keySpec);
        }
        else if (key instanceof RSAPublicKey) {
            return getPublicKeySpec((RSAPublicKey)key, keySpec);
        }
        else {
            throw new InvalidKeySpecException(
                "Unsupported Key type: " + key.getClass().getName());
        }
    }

    /**
     * Translate a Key object, whose provider may be unknown or potentially
     * untrusted, into a corresponding Key object of this KeyFactory.
     *
     * @param key the Key to be translated, must be one of RSAPrivateKey
     *        or RSAPublicKey
     *
     * @return the translated Key
     *
     * @throws InvalidKeyException if the given key cannot be processed
     *         by this KeyFactory
     */
    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {

        log("translating Key to wolfJCE RSA KeyFactory type");

        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }

        if (key instanceof RSAPrivateKey) {
            return translatePrivateKey((RSAPrivateKey)key);
        }
        else if (key instanceof RSAPublicKey) {
            return translatePublicKey((RSAPublicKey)key);
        }
        else {
            throw new InvalidKeyException(
                "Unsupported Key type: " + key.getClass().getName());
        }
    }

    /**
     * Private helper method for generating RSAPrivateKey from
     * PKCS8EncodedKeySpec.
     *
     * @param keySpec the PKCS8EncodedKeySpec containing the private key
     *
     * @return the generated RSAPrivateKey
     *
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    private PrivateKey generatePrivateFromPKCS8(PKCS8EncodedKeySpec keySpec)
        throws InvalidKeySpecException {

        byte[] pkcs8Der = null;
        Rsa rsa = null;

        try {
            if (keySpec == null) {
                throw new InvalidKeySpecException(
                    "PKCS8EncodedKeySpec cannot be null");
            }

            /* Get DER PKCS#8 data from spec */
            pkcs8Der = keySpec.getEncoded();
            if (pkcs8Der == null) {
                throw new InvalidKeySpecException(
                    "PKCS8EncodedKeySpec contains null encoded key");
            }

            log("decoding PKCS8 private key, length: " + pkcs8Der.length);

            /* Read into Rsa object to validate PKCS#8 structure */
            rsa = new Rsa();
            rsa.decodePrivateKeyPKCS8(pkcs8Der);

            /* Create wolfJCE RSAPrivateKey object using original encoding.
             * Use original bytes rather than re-encoding to preserve
             * DER structure, which is important for equals(). */
            return new WolfCryptRSAPrivateCrtKey(pkcs8Der);

        } catch (WolfCryptException e) {
            throw new InvalidKeySpecException(
                "wolfCrypt error during PKCS8 key decode: " +
                e.getMessage(), e);

        } finally {
            if (rsa != null) {
                rsa.releaseNativeStruct();
            }
        }
    }

    /**
     * Private helper method for generating RSAPrivateKey from
     * RSAPrivateCrtKeySpec.
     *
     * @param keySpec the RSAPrivateCrtKeySpec containing the private key
     *
     * @return the generated RSAPrivateKey
     *
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    private PrivateKey generatePrivateFromCrtSpec(
        RSAPrivateCrtKeySpec keySpec) throws InvalidKeySpecException {

        if (keySpec == null) {
            throw new InvalidKeySpecException(
                "RSAPrivateCrtKeySpec cannot be null");
        }

        log("generating RSAPrivateKey from RSAPrivateCrtKeySpec");

        try {
            /* Create WolfCryptRSAPrivateCrtKey from CRT parameters */
            return new WolfCryptRSAPrivateCrtKey(
                keySpec.getModulus(),
                keySpec.getPublicExponent(),
                keySpec.getPrivateExponent(),
                keySpec.getPrimeP(),
                keySpec.getPrimeQ(),
                keySpec.getPrimeExponentP(),
                keySpec.getPrimeExponentQ(),
                keySpec.getCrtCoefficient());

        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException(
                "Failed to generate private key from RSAPrivateCrtKeySpec: " +
                e.getMessage(), e);
        }
    }

    /**
     * Private helper method for generating RSAPrivateKey from
     * RSAPrivateKeySpec.
     *
     * @param keySpec the RSAPrivateKeySpec containing the private key
     *
     * @return the generated RSAPrivateKey
     *
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    private PrivateKey generatePrivateFromRSASpec(RSAPrivateKeySpec keySpec)
        throws InvalidKeySpecException {

        if (keySpec == null) {
            throw new InvalidKeySpecException(
                "RSAPrivateKeySpec cannot be null");
        }

        log("generating RSAPrivateKey from RSAPrivateKeySpec");

        if (keySpec instanceof RSAPrivateCrtKeySpec) {

            log("detected RSAPrivateCrtKeySpec, using CRT parameters");
            return generatePrivateFromCrtSpec((RSAPrivateCrtKeySpec)keySpec);
        }

        /* If spec is not CRT, it only has modulus (n) and private exponent (d).
         * Create a RSAPrivateKey (not RSAPrivateCrtKey) with zero placeholder
         * values for CRT parameters. Matches SunJCE behavior. */
        try {
            log("creating non-CRT RSA private key from RSAPrivateKeySpec");

            return new WolfCryptRSAPrivateKey(keySpec.getModulus(),
                keySpec.getPrivateExponent());

        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException(
                "Failed to generate private key from RSAPrivateKeySpec: " +
                e.getMessage(), e);
        }
    }

    /**
     * Private helper method for generating RSAPublicKey from
     * X509EncodedKeySpec.
     *
     * @param keySpec the X509EncodedKeySpec containing the public key
     *
     * @return the generated RSAPublicKey
     *
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    private PublicKey generatePublicFromX509(X509EncodedKeySpec keySpec)
        throws InvalidKeySpecException {

        byte[] x509Der = null;
        Rsa rsa = null;

        try {
            if (keySpec == null) {
                throw new InvalidKeySpecException(
                    "X509EncodedKeySpec cannot be null");
            }

            x509Der = keySpec.getEncoded();
            if (x509Der == null) {
                throw new InvalidKeySpecException(
                    "X509EncodedKeySpec contains null encoded key");
            }

            log("decoding X509 public key, length: " + x509Der.length);

            /* Import X509 key into Rsa to validate DER structure */
            rsa = new Rsa();
            rsa.decodePublicKey(x509Der);

            /* Create wolfJCE RSAPublicKey object using original encoding */
            return new WolfCryptRSAPublicKey(x509Der);

        } catch (WolfCryptException e) {
            throw new InvalidKeySpecException(
                "wolfCrypt error during X509 key decode: " + e.getMessage(),
                e);

        } finally {
            if (rsa != null) {
                rsa.releaseNativeStruct();
            }
        }
    }

    /**
     * Private helper method for generating RSAPublicKey from
     * RSAPublicKeySpec.
     *
     * @param keySpec the RSAPublicKeySpec containing the public key
     *
     * @return the generated RSAPublicKey
     *
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    private PublicKey generatePublicFromRSASpec(RSAPublicKeySpec keySpec)
        throws InvalidKeySpecException {

        Rsa rsa = null;
        byte[] derData = null;
        byte[] n = null;
        byte[] e = null;

        try {
            log("generating RSAPublicKey from RSAPublicKeySpec");

            if (keySpec == null) {
                throw new InvalidKeySpecException(
                    "RSAPublicKeySpec cannot be null");
            }

            if (keySpec.getModulus() == null) {
                throw new InvalidKeySpecException("Modulus cannot be null");
            }
            if (keySpec.getPublicExponent() == null) {
                throw new InvalidKeySpecException(
                    "Public exponent cannot be null");
            }

            /* Validate modulus and exponent are positive */
            if (keySpec.getModulus().signum() <= 0) {
                throw new InvalidKeySpecException(
                    "Modulus must be positive");
            }
            if (keySpec.getPublicExponent().signum() <= 0) {
                throw new InvalidKeySpecException(
                    "Public exponent must be positive");
            }

            /* Convert BigInteger values to byte arrays */
            n = convertBigIntegerToUnsignedBytes(keySpec.getModulus());
            e = convertBigIntegerToUnsignedBytes(
                keySpec.getPublicExponent());

            /* Import public key {n, e} into Rsa object */
            rsa = new Rsa();
            rsa.decodeRawPublicKey(n, e);

            /* Export as DER encoded format */
            derData = rsa.exportPublicDer();
            if (derData == null) {
                throw new InvalidKeySpecException(
                    "Failed to export public key DER");
            }

            /* Create wolfJCE RSAPublicKey object */
            return new WolfCryptRSAPublicKey(derData);

        } catch (WolfCryptException ex) {
            throw new InvalidKeySpecException(
                "wolfCrypt error during RSAPublicKeySpec conversion: " +
                ex.getMessage(), ex);

        } finally {
            if (rsa != null) {
                rsa.releaseNativeStruct();
            }
            if (derData != null) {
                Arrays.fill(derData, (byte)0);
            }
            if (n != null) {
                Arrays.fill(n, (byte)0);
            }
            if (e != null) {
                Arrays.fill(e, (byte)0);
            }
        }
    }

    /**
     * Convert BigInteger to unsigned byte array without leading zeros.
     *
     * @param value the BigInteger value to convert
     *
     * @return byte array representation without sign byte
     */
    private byte[] convertBigIntegerToUnsignedBytes(BigInteger value) {
        byte[] bytes = value.toByteArray();

        /* Remove leading zero byte if present (sign byte) */
        if ((bytes.length > 0) && (bytes[0] == 0)) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }

        return bytes;
    }

    /**
     * Private helper methods for extracting KeySpec from RSAPrivateCrtKey.
     *
     * @param <T> the type of KeySpec to be returned
     * @param key the RSAPrivateCrtKey from which to extract the KeySpec
     * @param keySpec the class object of the requested KeySpec type
     *
     * @return the extracted KeySpec of the requested type
     *
     * @throws InvalidKeySpecException if the KeySpec type is unsupported
     */
    @SuppressWarnings("unchecked")
    private <T extends KeySpec> T getPrivateCrtKeySpec(RSAPrivateCrtKey key,
        Class<T> keySpec) throws InvalidKeySpecException {

        byte[] encoded;

        try {
            if (key == null) {
                throw new InvalidKeySpecException(
                    "RSAPrivateCrtKey cannot be null");
            }
            if (keySpec == null) {
                throw new InvalidKeySpecException(
                    "Requested KeySpec format cannot be null");
            }

            log("extracting private CRT key spec of type: " +
                keySpec.getName());

            if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
                encoded = key.getEncoded();
                if (encoded == null) {
                    throw new InvalidKeySpecException(
                        "RSAPrivateCrtKey.getEncoded() returned null");
                }
                return (T) new PKCS8EncodedKeySpec(encoded);
            }
            else if (keySpec.isAssignableFrom(RSAPrivateCrtKeySpec.class)) {
                /* Extract CRT parameters directly from key */
                return (T) new RSAPrivateCrtKeySpec(
                    key.getModulus(),
                    key.getPublicExponent(),
                    key.getPrivateExponent(),
                    key.getPrimeP(),
                    key.getPrimeQ(),
                    key.getPrimeExponentP(),
                    key.getPrimeExponentQ(),
                    key.getCrtCoefficient());
            }
            else if (keySpec.isAssignableFrom(RSAPrivateKeySpec.class)) {
                /* Extract basic private key parameters */
                return (T) new RSAPrivateKeySpec(
                    key.getModulus(),
                    key.getPrivateExponent());
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
     * Private helper methods for extracting KeySpec from RSAPrivateKey.
     *
     * @param <T> the type of KeySpec to be returned
     * @param key the RSAPrivateKey from which to extract the KeySpec
     * @param keySpec the class object of the requested KeySpec type
     *
     * @return the extracted KeySpec of the requested type
     *
     * @throws InvalidKeySpecException if the KeySpec type is unsupported
     */
    @SuppressWarnings("unchecked")
    private <T extends KeySpec> T getPrivateKeySpec(RSAPrivateKey key,
        Class<T> keySpec) throws InvalidKeySpecException {

        byte[] encoded;

        try {
            if (key == null) {
                throw new InvalidKeySpecException(
                    "RSAPrivateKey cannot be null");
            }
            if (keySpec == null) {
                throw new InvalidKeySpecException(
                    "Requested KeySpec format cannot be null");
            }

            log("extracting private key spec of type: " + keySpec.getName());

            if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
                encoded = key.getEncoded();
                if (encoded == null) {
                    throw new InvalidKeySpecException(
                        "RSAPrivateKey.getEncoded() returned null");
                }
                return (T) new PKCS8EncodedKeySpec(encoded);
            }
            else if (keySpec.isAssignableFrom(RSAPrivateKeySpec.class)) {
                /* Extract basic private key parameters */
                return (T) new RSAPrivateKeySpec(
                    key.getModulus(),
                    key.getPrivateExponent());
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
     * Private helper methods for extracting KeySpec from RSAPublicKey.
     *
     * @param <T> the type of KeySpec to be returned
     * @param key the RSAPublicKey from which to extract the KeySpec
     * @param keySpec the class object of the requested KeySpec type
     *
     * @return the extracted KeySpec of the requested type
     *
     * @throws InvalidKeySpecException if the KeySpec type is unsupported
     */
    @SuppressWarnings("unchecked")
    private <T extends KeySpec> T getPublicKeySpec(RSAPublicKey key,
        Class<T> keySpec) throws InvalidKeySpecException {

        byte[] encoded;

        try {
            if (key == null) {
                throw new InvalidKeySpecException(
                    "RSAPublicKey cannot be null");
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
                        "RSAPublicKey.getEncoded() returned null");
                }
                return (T) new X509EncodedKeySpec(encoded);
            }
            else if (keySpec.isAssignableFrom(RSAPublicKeySpec.class)) {
                /* Extract public key parameters directly from key */
                return (T) new RSAPublicKeySpec(
                    key.getModulus(),
                    key.getPublicExponent());
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
     * Translate RSAPrivateKey from foreign provider into wolfJCE
     * RSAPrivateKey.
     *
     * @param key the RSAPrivateKey to be translated
     *
     * @return the translated PrivateKey
     *
     * @throws InvalidKeyException if the key cannot be translated
     */
    private PrivateKey translatePrivateKey(RSAPrivateKey key)
        throws InvalidKeyException {

        byte[] encoded;
        PKCS8EncodedKeySpec keySpec;

        try {
            log("translating RSAPrivateKey from foreign provider");

            if (key == null) {
                throw new InvalidKeyException(
                    "RSAPrivateKey cannot be null");
            }

            /* Get encoded format and convert through our KeyFactory */
            encoded = key.getEncoded();
            if (encoded == null) {
                throw new InvalidKeyException(
                    "RSAPrivateKey.getEncoded() returned null");
            }

            keySpec = new PKCS8EncodedKeySpec(encoded);

            return engineGeneratePrivate(keySpec);

        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(
                "Failed to translate RSAPrivateKey: " + e.getMessage(), e);
        }
    }

    /**
     * Translate RSAPublicKey from foreign provider into wolfJCE RSAPublicKey.
     *
     * @param key the RSAPublicKey to be translated
     *
     * @return the translated PublicKey
     *
     * @throws InvalidKeyException if the key cannot be translated
     */
    private PublicKey translatePublicKey(RSAPublicKey key)
        throws InvalidKeyException {

        byte[] encoded;
        X509EncodedKeySpec keySpec;

        try {
            log("translating RSAPublicKey from foreign provider");

            if (key == null) {
                throw new InvalidKeyException(
                    "RSAPublicKey cannot be null");
            }

            /* Get encoded format and convert through our KeyFactory */
            encoded = key.getEncoded();
            if (encoded == null) {
                throw new InvalidKeyException(
                    "RSAPublicKey.getEncoded() returned null");
            }

            keySpec = new X509EncodedKeySpec(encoded);

            return engineGeneratePublic(keySpec);

        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(
                "Failed to translate RSAPublicKey: " + e.getMessage(), e);
        }
    }
}

