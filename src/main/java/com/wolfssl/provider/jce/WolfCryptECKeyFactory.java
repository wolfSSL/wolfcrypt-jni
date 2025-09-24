/* WolfCryptECKeyFactory.java
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
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.InvalidAlgorithmParameterException;

import com.wolfssl.wolfcrypt.Ecc;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfCrypt JCE EC KeyFactory implementation.
 *
 * This class provides key conversion capabilities for Elliptic Curve (EC)
 * keys, supporting conversion between various KeySpec formats and Key objects.
 */
public class WolfCryptECKeyFactory extends KeyFactorySpi {

    /**
     * Create new WolfCryptECKeyFactory object.
     */
    public WolfCryptECKeyFactory() {
        log("created new EC KeyFactory");
    }

    /**
     * Internal method for logging output.
     *
     * @param msg message to be logged
     */
    private void log(String msg) {
        WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO,
            () -> "[EC KeyFactory] " + msg);
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
     *         and ECPrivateKeySpec
     */
    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
        throws InvalidKeySpecException {

        log("generating ECPrivateKey from KeySpec");

        if (keySpec == null) {
            throw new InvalidKeySpecException("KeySpec cannot be null");
        }

        if (keySpec instanceof PKCS8EncodedKeySpec) {
            return generatePrivateFromPKCS8((PKCS8EncodedKeySpec)keySpec);
        }
        else if (keySpec instanceof ECPrivateKeySpec) {
            return generatePrivateFromECSpec((ECPrivateKeySpec)keySpec);
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
     *         and ECPublicKeySpec.
     */
    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec)
        throws InvalidKeySpecException {

        log("generating ECPublicKey from KeySpec");

        if (keySpec == null) {
            throw new InvalidKeySpecException("KeySpec cannot be null");
        }

        if (keySpec instanceof X509EncodedKeySpec) {
            return generatePublicFromX509((X509EncodedKeySpec)keySpec);
        }
        else if (keySpec instanceof ECPublicKeySpec) {
            return generatePublicFromECSpec((ECPublicKeySpec)keySpec);
        }
        else {
            throw new InvalidKeySpecException(
                "Unsupported KeySpec type: " + keySpec.getClass().getName());
        }
    }

    /**
     * Returns a KeySpec of the given Key object in the requested format.
     *
     * @param key the Key object, must be one of ECPrivateKey or ECPublicKey
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

        if (key instanceof ECPrivateKey) {
            return getPrivateKeySpec((ECPrivateKey)key, keySpec);
        }
        else if (key instanceof ECPublicKey) {
            return getPublicKeySpec((ECPublicKey)key, keySpec);
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
     * @param key the Key to be translated, must be one of ECPrivateKey
     *        or ECPublicKey
     *
     * @return the translated Key
     *
     * @throws InvalidKeyException if the given key cannot be processed
     *         by this KeyFactory
     */
    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {

        log("translating Key to wolfJCE EC KeyFactory type");

        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }

        if (key instanceof ECPrivateKey) {
            return translatePrivateKey((ECPrivateKey)key);
        }
        else if (key instanceof ECPublicKey) {
            return translatePublicKey((ECPublicKey)key);
        }
        else {
            throw new InvalidKeyException(
                "Unsupported Key type: " + key.getClass().getName());
        }
    }

    /**
     * Private helper method for generating ECPrivateKey from
     * PKCS8EncodedKeySpec.
     *
     * @param keySpec the PKCS8EncodedKeySpec containing the private key
     *
     * @return the generated ECPrivateKey
     *
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    private PrivateKey generatePrivateFromPKCS8(PKCS8EncodedKeySpec keySpec)
        throws InvalidKeySpecException {

        byte[] pkcs8Der = null;
        byte[] privDer = null;
        Ecc ecc = null;

        try {
            if (keySpec == null) {
                throw new InvalidKeySpecException(
                    "PKCS8EncodedKeySpec cannot be null");
            }

            /* Get DER-encoded PKCS#8 data from spec */
            pkcs8Der = keySpec.getEncoded();
            if (pkcs8Der == null) {
                throw new InvalidKeySpecException(
                    "PKCS8EncodedKeySpec contains null encoded key");
            }

            log("decoding PKCS8 private key, length: " + pkcs8Der.length);

            /* Read into Ecc object, validates PKCS#8 structure via wolfCrypt */
            ecc = new Ecc();
            ecc.privateKeyDecode(pkcs8Der);

            /* Export as PKCS#8, ensures proper wolfCrypt DER encoding */
            privDer = ecc.privateKeyEncodePKCS8();
            if (privDer == null) {
                throw new InvalidKeySpecException(
                    "Failed to export private key as DER from Ecc");
            }

            /* Create wolfJCE ECPrivateKey object */
            return new WolfCryptECPrivateKey(privDer);

        } catch (WolfCryptException e) {
            throw new InvalidKeySpecException(
                "wolfCrypt error during PKCS8 key decode: " +
                e.getMessage(), e);

        } finally {
            if (ecc != null) {
                ecc.releaseNativeStruct();
            }
            if (privDer != null) {
                Arrays.fill(privDer, (byte)0);
            }
        }
    }

    /**
     * Private helper method for generating ECPrivateKey from
     * ECPrivateKeySpec.
     *
     * @param keySpec the ECPrivateKeySpec containing the private key
     *
     * @return the generated ECPrivateKey
     *
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    private PrivateKey generatePrivateFromECSpec(ECPrivateKeySpec keySpec)
        throws InvalidKeySpecException {

        Ecc ecc = null;
        byte[] pkcs8Data = null;
        byte[] privBytes = null;
        String curveName = null;

        try {
            log("generating ECPrivateKey from ECPrivateKeySpec");

            if (keySpec == null) {
                throw new InvalidKeySpecException(
                    "ECPrivateKeySpec cannot be null");
            }
            if (keySpec.getS() == null) {
                throw new InvalidKeySpecException(
                    "Private key value cannot be null");
            }
            if (keySpec.getParams() == null) {
                throw new InvalidKeySpecException(
                    "ECParameterSpec cannot be null");
            }

            /* Validate ECParameterSpec is supported by wolfCrypt,
             * throws WolfCryptException if invalid */
            WolfCryptECParameterSpec.validateParameters(keySpec.getParams());

            /* Get curve name from ECParameterSpec */
            try {
                curveName = WolfCryptECParameterSpec.getCurveName(
                    keySpec.getParams());

            } catch (InvalidAlgorithmParameterException e) {
                throw new InvalidKeySpecException(
                    "Unsupported curve parameters: " + e.getMessage(), e);
            }

            if (curveName == null || curveName.isEmpty()) {
                throw new InvalidKeySpecException(
                    "Unable to determine curve name from ECParameterSpec");
            }

            /* Convert BigInteger private key to byte[] */
            privBytes = convertPrivateValueToBytes(keySpec.getS(), curveName);

            /* Import private key into Ecc object */
            ecc = new Ecc();
            ecc.importPrivateRaw(privBytes, curveName);

            /* Export as PKCS#8 format */
            pkcs8Data = ecc.privateKeyEncodePKCS8();
            if (pkcs8Data == null) {
                throw new InvalidKeySpecException(
                    "Failed to export private key as PKCS#8");
            }

            /* Create wolfJCE ECPrivateKey object */
            return new WolfCryptECPrivateKey(pkcs8Data);

        } catch (WolfCryptException e) {
            throw new InvalidKeySpecException(
                "wolfCrypt error during ECPrivateKeySpec conversion: " +
                e.getMessage(), e);

        } finally {
            if (ecc != null) {
                ecc.releaseNativeStruct();
            }
            if (pkcs8Data != null) {
                Arrays.fill(pkcs8Data, (byte)0);
            }
            if (privBytes != null) {
                Arrays.fill(privBytes, (byte)0);
            }
        }
    }

    /**
     * Validates and converts BigInteger to byte array for wolfCrypt.
     *
     * Handles BigInteger.toByteArray() edge cases including:
     * - Leading zero byte for sign bit when MSB is set
     * - Padding with leading zeros if value is shorter than expected
     * - Validation that value does not exceed curve size
     *
     * @param value the BigInteger value to convert
     * @param fieldName description of the field for error messages
     * @param curveName curve name for size calculation and error messages
     * @return properly formatted byte array for wolfCrypt import
     * @throws InvalidKeySpecException if the value is invalid
     */
    private byte[] validateAndConvertBigIntegerToBytes(BigInteger value,
        String fieldName, String curveName) throws InvalidKeySpecException {

        int expectedSz = 0;
        byte[] bytes = null;
        byte[] result = null;

        try {
            /* Get expected byte array size for this curve */
            expectedSz = Ecc.getCurveSizeFromName(curveName);

            /* Validate value is non-negative */
            if (value.signum() < 0) {
                throw new InvalidKeySpecException(
                    fieldName + " cannot be negative");
            }

            /* Convert to byte array */
            bytes = value.toByteArray();

            /* Ensure result is exactly expected size, accounting for
             * BigInteger toByteArray() edge cases:
             *
             * If MSB is set, toByteArray() adds a leading 0x00 (sign bit)
             * Bytes can be up to expectedSz + 1 due to sign bit */
            if ((bytes.length > expectedSz + 1) ||
                (bytes.length == expectedSz + 1 && bytes[0] != 0)) {
                throw new InvalidKeySpecException(
                    fieldName + " too large for curve " + curveName);
            }

            /* Remove leading zero if present (sign bit from BigInteger) */
            if ((bytes.length == expectedSz + 1) && (bytes[0] == 0)) {
                result = new byte[expectedSz];
                System.arraycopy(bytes, 1, result, 0, expectedSz);
                /* Zero out original array */
                Arrays.fill(bytes, (byte)0);
            }
            /* If array is shorter than expected, pad with leading zeros */
            else if (bytes.length < expectedSz) {
                result = new byte[expectedSz];
                int offset = expectedSz - bytes.length;
                System.arraycopy(bytes, 0, result, offset, bytes.length);
                /* Zero out original array */
                Arrays.fill(bytes, (byte)0);
            }
            else {
                /* Array is correct size, use as-is */
                result = bytes;
                bytes = null; /* Prevent cleanup since we're returning this */
            }

            return result;

        } catch (WolfCryptException e) {
            /* Clean up any allocated arrays on error */
            if (bytes != null) {
                Arrays.fill(bytes, (byte)0);
            }
            if (result != null) {
                Arrays.fill(result, (byte)0);
            }
            throw new InvalidKeySpecException(
                "Error getting curve size for " + curveName + ": " +
                e.getMessage(), e);
        }
    }

    /**
     * Convert BigInteger private key to byte[].
     *
     * @param privateValue private key BigInteger
     * @param curveName curve name for size validation, used to get
     *        expected byte array size
     *
     * @return properly formatted byte array for wolfCrypt import
     *
     * @throws InvalidKeySpecException if the private value is invalid
     */
    private byte[] convertPrivateValueToBytes(BigInteger privateValue,
        String curveName) throws InvalidKeySpecException {

        /* Validate private key is positive. Other validation done at time of
         * use to match Sun behavior. */
        if (privateValue.signum() <= 0) {
            throw new InvalidKeySpecException(
                "Private key value must be positive");
        }

        /* Convert to byte array */
        return validateAndConvertBigIntegerToBytes(privateValue,
            "Private key value", curveName);
    }

    /**
     * Private helper method for generating ECPublicKey from
     * X509EncodedKeySpec.
     *
     * @param keySpec the X509EncodedKeySpec containing the public key
     *
     * @return the generated ECPublicKey
     *
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    private PublicKey generatePublicFromX509(X509EncodedKeySpec keySpec)
        throws InvalidKeySpecException {

        byte[] x509Der = null;
        byte[] pubDer = null;
        Ecc ecc = null;

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

            /* Import X509 key into Ecc, validates DER */
            ecc = new Ecc();
            ecc.publicKeyDecode(x509Der);

            /* Export as X509 to get wolfCrypt DER format */
            pubDer = ecc.publicKeyEncode();
            if (pubDer == null) {
                throw new InvalidKeySpecException(
                    "Failed to export public key as DER from Ecc object");
            }

            /* Create wolfJCE ECPublicKey object */
            return new WolfCryptECPublicKey(pubDer);

        } catch (WolfCryptException e) {
            throw new InvalidKeySpecException(
                "wolfCrypt error during X509 key decode: " + e.getMessage(), e);

        } finally {
            if (ecc != null) {
                ecc.releaseNativeStruct();
            }
            if (pubDer != null) {
                Arrays.fill(pubDer, (byte)0);
            }
        }
    }

    /**
     * Private helper method for generating ECPublicKey from
     * ECPublicKeySpec.
     *
     * @param keySpec the ECPublicKeySpec containing the public key
     *
     * @return the generated ECPublicKey
     *
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    private PublicKey generatePublicFromECSpec(ECPublicKeySpec keySpec)
        throws InvalidKeySpecException {

        Ecc ecc = null;
        byte[] derData = null;
        byte[] x = null;
        byte[] y = null;
        String curveName = null;

        try {
            log("generating ECPublicKey from ECPublicKeySpec");

            if (keySpec == null) {
                throw new InvalidKeySpecException(
                    "ECPublicKeySpec cannot be null");
            }

            if (keySpec.getW() == null) {
                throw new InvalidKeySpecException(
                    "Public key point cannot be null");
            }
            if (keySpec.getParams() == null) {
                throw new InvalidKeySpecException(
                    "ECParameterSpec cannot be null");
            }

            /* Validate ECParameterSpec is supported by wolfCrypt,
             * throws WolfCryptException if invalid */
            WolfCryptECParameterSpec.validateParameters(keySpec.getParams());

            /* Get curve name from ECParameterSpec */
            try {
                curveName = WolfCryptECParameterSpec.getCurveName(
                    keySpec.getParams());

            } catch (InvalidAlgorithmParameterException e) {
                throw new InvalidKeySpecException(
                    "Unsupported curve parameters: " + e.getMessage(), e);
            }
            if (curveName == null || curveName.isEmpty()) {
                throw new InvalidKeySpecException(
                    "Unable to determine curve name from ECParameterSpec");
            }

            /* Convert ECPoint to {x, y} coordinate byte arrays */
            x = validateAndConvertBigIntegerToBytes(
                keySpec.getW().getAffineX(), "X coordinate", curveName);
            y = validateAndConvertBigIntegerToBytes(
                keySpec.getW().getAffineY(), "Y coordinate", curveName);

            /* Import public key {x, y} into Ecc object */
            ecc = new Ecc();
            ecc.importPublicRaw(x, y, curveName);

            /* Export as DER encoded format */
            derData = ecc.publicKeyEncode();
            if (derData == null) {
                throw new InvalidKeySpecException(
                    "Failed to export public key DER");
            }

            /* Create wolfJCE ECPublicKey object */
            return new WolfCryptECPublicKey(derData);

        } catch (WolfCryptException e) {
            throw new InvalidKeySpecException(
                "wolfCrypt error during ECPublicKeySpec conversion: " +
                e.getMessage(), e);

        } finally {
            if (ecc != null) {
                ecc.releaseNativeStruct();
            }
            if (derData != null) {
                Arrays.fill(derData, (byte)0);
            }
            if (x != null) {
                Arrays.fill(x, (byte)0);
            }
            if (y != null) {
                Arrays.fill(y, (byte)0);
            }
        }
    }


    /**
     * Private helper methods for extracting KeySpec from Key.
     *
     * @param <T> the type of KeySpec to be returned
     * @param key the ECPrivateKey from which to extract the KeySpec
     * @param keySpec the class object of the requested KeySpec type
     *
     * @return the extracted KeySpec of the requested type
     *
     * @throws InvalidKeySpecException if the KeySpec type is unsupported
     */
    @SuppressWarnings("unchecked")
    private <T extends KeySpec> T getPrivateKeySpec(ECPrivateKey key,
        Class<T> keySpec) throws InvalidKeySpecException {

        try {
            if (key == null) {
                throw new InvalidKeySpecException(
                    "ECPrivateKey cannot be null");
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
                        "ECPrivateKey.getEncoded() returned null");
                }
                return (T) new PKCS8EncodedKeySpec(encoded);
            }
            else if (keySpec.isAssignableFrom(ECPrivateKeySpec.class)) {
                /* Extract private value and params directly from key */
                return (T) new ECPrivateKeySpec(key.getS(), key.getParams());
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
     * @param key the ECPublicKey from which to extract the KeySpec
     * @param keySpec the class object of the requested KeySpec type
     *
     * @return the extracted KeySpec of the requested type
     *
     * @throws InvalidKeySpecException if the KeySpec type is unsupported
     */
    @SuppressWarnings("unchecked")
    private <T extends KeySpec> T getPublicKeySpec(ECPublicKey key,
        Class<T> keySpec) throws InvalidKeySpecException {

        try {
            if (key == null) {
                throw new InvalidKeySpecException(
                    "ECPublicKey cannot be null");
            }
            if (keySpec == null) {
                throw new InvalidKeySpecException(
                    "Requested KeySpec format cannot be null");
            }

            log("extracting public key spec of type: " + keySpec.getName());

            if (keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
                byte[] encoded = key.getEncoded();
                if (encoded == null) {
                    throw new InvalidKeySpecException(
                        "ECPublicKey.getEncoded() returned null");
                }
                return (T) new X509EncodedKeySpec(encoded);
            }
            else if (keySpec.isAssignableFrom(ECPublicKeySpec.class)) {
                /* Extract public point and parameters directly from key */
                return (T) new ECPublicKeySpec(key.getW(), key.getParams());
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
     * Translate ECPrivateKey from foreign provider into wolfJCE ECPrivateKey.
     *
     * @param key the ECPrivateKey to be translated
     *
     * @return the translated PrivateKey
     *
     * @throws InvalidKeyException if the key cannot be translated
     */
    private PrivateKey translatePrivateKey(ECPrivateKey key)
        throws InvalidKeyException {

        try {
            log("translating ECPrivateKey from foreign provider");

            if (key == null) {
                throw new InvalidKeyException(
                    "ECPrivateKey cannot be null");
            }

            /* Get encoded format and convert through our KeyFactory */
            byte[] encoded = key.getEncoded();
            if (encoded == null) {
                throw new InvalidKeyException(
                    "ECPrivateKey.getEncoded() returned null");
            }

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            return engineGeneratePrivate(keySpec);

        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(
                "Failed to translate ECPrivateKey: " + e.getMessage(), e);
        }
    }

    /**
     * Translate ECPublicKey from foreign provider into wolfJCE ECPublicKey.
     *
     * @param key the ECPublicKey to be translated
     *
     * @return the translated PublicKey
     *
     * @throws InvalidKeyException if the key cannot be translated
     */
    private PublicKey translatePublicKey(ECPublicKey key)
        throws InvalidKeyException {

        try {
            log("translating ECPublicKey from foreign provider");

            if (key == null) {
                throw new InvalidKeyException(
                    "ECPublicKey cannot be null");
            }

            /* Get encoded format and convert through our KeyFactory */
            byte[] encoded = key.getEncoded();
            if (encoded == null) {
                throw new InvalidKeyException(
                    "ECPublicKey.getEncoded() returned null");
            }

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
            return engineGeneratePublic(keySpec);

        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(
                "Failed to translate ECPublicKey: " + e.getMessage(), e);
        }
    }
}

