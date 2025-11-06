/* WolfCryptECPrivateKey.java
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

import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

import com.wolfssl.wolfcrypt.Ecc;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfJCE ECPrivateKey implementation.
 * This class implements the ECPrivateKey interface using wolfCrypt.
 */
public class WolfCryptECPrivateKey implements ECPrivateKey {

    private static final long serialVersionUID = 1L;

    /** DER-encoded private key (PKCS#8 format) */
    private byte[] encoded = null;

    /** Cached ECParameterSpec, extracted on first access */
    private transient ECParameterSpec paramSpec = null;

    /** Cached private key value, extracted on first access */
    private transient BigInteger privateValue = null;

    /** Track if object has been destroyed */
    private boolean destroyed = false;

    /** Lock around use of destroyed boolean and cached values.
     * Note: Cannot be final because it needs to be reinitialized after
     * deserialization. */
    private transient Object stateLock = new Object();

    /**
     * Create new WolfCryptECPrivateKey from DER-encoded PKCS#8 data.
     *
     * @param encoded DER-encoded PKCS#8 private key
     *
     * @throws IllegalArgumentException if encoded data is null or invalid
     */
    public WolfCryptECPrivateKey(byte[] encoded)
        throws IllegalArgumentException {

        if (encoded == null || encoded.length == 0) {
            throw new IllegalArgumentException(
                "Encoded key data cannot be null or empty");
        }

        /* Validate DER format by importing into wolfCrypt */
        validateDerFormat(encoded);

        /* Store a copy of the encoded data */
        this.encoded = encoded.clone();
    }

    /**
     * Create new WolfCryptECPrivateKey from private value and parameters.
     *
     * @param privateValue the private key value
     * @param paramSpec the EC parameters
     *
     * @throws IllegalArgumentException if parameters are invalid
     */
    public WolfCryptECPrivateKey(BigInteger privateValue,
        ECParameterSpec paramSpec)  throws IllegalArgumentException {

        if (privateValue == null) {
            throw new IllegalArgumentException(
                "Private value cannot be null");
        }
        if (paramSpec == null) {
            throw new IllegalArgumentException(
                "ECParameterSpec cannot be null");
        }

        /* Store params */
        this.privateValue = privateValue;
        this.paramSpec = paramSpec;

        /* Generate DER-encoded form */
        this.encoded = generateDerFromParameters();
    }

    /**
     * Validate DER format by attempting to import into wolfCrypt Ecc.
     *
     * @param derData DER-encoded key data to validate
     *
     * @throws IllegalArgumentException if DER data is invalid
     */
    private void validateDerFormat(byte[] derData)
        throws IllegalArgumentException {

        Ecc ecc = null;

        try {
            ecc = new Ecc();
            ecc.privateKeyDecode(derData);

        } catch (WolfCryptException e) {
            throw new IllegalArgumentException(
                "Invalid DER-encoded private key: " + e.getMessage(), e);

        } finally {
            if (ecc != null) {
                ecc.releaseNativeStruct();
            }
        }
    }

    /**
     * Generate DER-encoded form from private value and parameters.
     *
     * @return DER-encoded PKCS#8 private key
     *
     * @throws IllegalArgumentException if key generation fails
     */
    private byte[] generateDerFromParameters()
        throws IllegalArgumentException {

        byte[] privKeyBytes = null;
        Ecc ecc = null;
        String curveName = null;

        try {

            log("generating DER from private value and ECParameterSpec");

            /* Get curve name from the ECParameterSpec */
            try {
                curveName =
                    WolfCryptECParameterSpec.getCurveName(this.paramSpec);

            } catch (InvalidAlgorithmParameterException e) {
                throw new IllegalArgumentException(
                    "Unsupported curve in ECParameterSpec: " + e.getMessage());
            }
            if (curveName == null) {
                throw new IllegalArgumentException(
                    "Unsupported curve in ECParameterSpec");
            }

            /* Convert private value to byte array */
            privKeyBytes =
                Ecc.bigIntToByteArrayNoLeadingZeros(this.privateValue);

            /* Import private key into Ecc using raw import */
            ecc = new Ecc();
            ecc.importPrivateRaw(privKeyBytes, curveName);

            /* Export as PKCS#8 DER */
            byte[] derEncoded = ecc.privateKeyEncodePKCS8();
            if (derEncoded == null) {
                throw new IllegalArgumentException(
                    "Failed to encode private key as DER");
            }

            log("successfully generated DER from raw parameters, length: " +
                derEncoded.length);

            return derEncoded;

        } catch (WolfCryptException e) {
            throw new IllegalArgumentException(
                "Failed to generate DER from parameters: " + e.getMessage(), e);

        } finally {
            if (ecc != null) {
                ecc.releaseNativeStruct();
            }
            if (privKeyBytes != null) {
                Arrays.fill(privKeyBytes, (byte) 0);
            }
        }
    }

    /**
     * Extract ECParameterSpec from the DER-encoded key.
     *
     * @return ECParameterSpec for this key
     *
     * @throws IllegalStateException if parameter extraction fails
     */
    private ECParameterSpec extractECParameterSpec()
        throws IllegalStateException {

        log("extracting ECParameterSpec from DER-encoded private key");

        return WolfCryptECParameterSpec.extractFromKey(this.encoded, true);
    }

    /**
     * Extract private key value from the DER-encoded key.
     *
     * @return BigInteger representing the private key value
     *
     * @throws IllegalStateException if private value extraction fails
     */
    private BigInteger extractPrivateValue() throws IllegalStateException {

        byte[] privKeyBytes = null;
        Ecc ecc = null;

        try {
            /* Load the private key into wolfCrypt and export raw private key */
            ecc = new Ecc();
            ecc.privateKeyDecode(this.encoded);

            /* Export the raw private key scalar */
            privKeyBytes = ecc.exportPrivateRaw();
            if ((privKeyBytes == null) || (privKeyBytes.length == 0)) {
                throw new IllegalStateException("Failed to export private key");
            }

            /* Convert to BigInteger (unsigned, positive) */
            return new BigInteger(1, privKeyBytes);

        } catch (WolfCryptException e) {
            throw new IllegalStateException(
                "Failed to extract private value: " + e.getMessage(), e);

        } finally {
            if (ecc != null) {
                ecc.releaseNativeStruct();
            }
            if (privKeyBytes != null) {
                Arrays.fill(privKeyBytes, (byte) 0);
            }
        }
    }

    /**
     * Internal method for logging output.
     *
     * @param msg message to be logged
     */
    private void log(String msg) {
        WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO,
            () -> "[WolfCryptECPrivateKey] " + msg);
    }

    @Override
    public BigInteger getS() {
        synchronized (stateLock) {
            if (destroyed) {
                throw new IllegalStateException("Key has been destroyed");
            }

            if (privateValue == null) {
                log("extracting private key value from DER");
                privateValue = extractPrivateValue();
            }
            return privateValue;
        }
    }

    @Override
    public ECParameterSpec getParams() {
        synchronized (stateLock) {
            if (destroyed) {
                throw new IllegalStateException("Key has been destroyed");
            }

            if (paramSpec == null) {
                log("extracting EC parameters from DER");
                paramSpec = extractECParameterSpec();
            }
            return paramSpec;
        }
    }

    @Override
    public String getAlgorithm() {
        return "EC";
    }

    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        synchronized (stateLock) {
            if (destroyed) {
                return null;
            }
            return encoded.clone();
        }
    }

    /**
     * Destroy this key by zeroing out sensitive data.
     */
    public void destroy() {
        synchronized (stateLock) {
            if (!destroyed) {
                if (encoded != null) {
                    Arrays.fill(encoded, (byte) 0);
                }
                privateValue = null;
                paramSpec = null;
                destroyed = true;
                log("key destroyed");
            }
        }
    }

    /**
     * Check if this key has been destroyed.
     *
     * @return true if key has been destroyed
     */
    public boolean isDestroyed() {
        synchronized (stateLock) {
            return destroyed;
        }
    }

    @Override
    public int hashCode() {
        synchronized (stateLock) {
            if (destroyed) {
                return 0;
            }
            return Arrays.hashCode(encoded);
        }
    }

    @Override
    public boolean equals(Object obj) {

        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ECPrivateKey)) {
            return false;
        }

        ECPrivateKey other = (ECPrivateKey) obj;

        synchronized (stateLock) {
            if (destroyed) {
                return false;
            }

            /* Compare encoded forms if both are WolfCryptECPrivateKey */
            if (obj instanceof WolfCryptECPrivateKey) {
                WolfCryptECPrivateKey otherWolf = (WolfCryptECPrivateKey) obj;
                synchronized (otherWolf.stateLock) {
                    if (otherWolf.destroyed) {
                        return false;
                    }
                    return Arrays.equals(this.encoded, otherWolf.encoded);
                }
            }

            /* Compare with other ECPrivateKey implementations */
            try {
                if (getS().equals(other.getS()) &&
                    getParams().equals(other.getParams())) {
                    return true;
                } else {
                    return false;
                }

            } catch (Exception e) {
                return false;
            }
        }
    }

    @Override
    public String toString() {
        synchronized (stateLock) {
            if (destroyed) {
                return "WolfCryptECPrivateKey[DESTROYED]";
            }
            return "WolfCryptECPrivateKey[algorithm=EC, format=PKCS#8, " +
                   "encoded.length=" + encoded.length + "]";
        }
    }

    /**
     * Deserialization routine to reinitialize transient fields.
     * The stateLock field is transient and needs to be recreated after
     * deserialization.
     *
     * @param in ObjectInputStream to read from
     * @throws IOException if an I/O error occurs
     * @throws ClassNotFoundException if class cannot be found
     */
    private void readObject(ObjectInputStream in)
        throws IOException, ClassNotFoundException {

        /* Default deserialization */
        in.defaultReadObject();

        /* Reinitialize transient lock object */
        stateLock = new Object();
    }
}

