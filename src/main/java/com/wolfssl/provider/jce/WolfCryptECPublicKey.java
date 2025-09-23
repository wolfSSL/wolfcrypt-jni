/* WolfCryptECPublicKey.java
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
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.InvalidAlgorithmParameterException;

import com.wolfssl.wolfcrypt.Ecc;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfJCE ECPublicKey implementation.
 * This class implements the ECPublicKey interface using wolfCrypt.
 */
public class WolfCryptECPublicKey implements ECPublicKey {

    private static final long serialVersionUID = 1L;

    /** DER-encoded public key (X.509 format) */
    private byte[] encoded = null;

    /** Cached ECParameterSpec, extracted on first access */
    private transient ECParameterSpec paramSpec = null;

    /** Cached public key point, extracted on first access */
    private transient ECPoint publicPoint = null;

    /** Track if object has been destroyed */
    private boolean destroyed = false;

    /** Lock around use of destroyed boolean and cached values */
    private transient final Object stateLock = new Object();

    /**
     * Create new WolfCryptECPublicKey from DER-encoded X.509 data.
     *
     * @param encoded DER-encoded X.509 public key
     *
     * @throws IllegalArgumentException if encoded data is null or invalid
     */
    public WolfCryptECPublicKey(byte[] encoded)
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
     * Create new WolfCryptECPublicKey from public point and parameters.
     *
     * @param publicPoint the public key point
     * @param paramSpec the EC parameters
     *
     * @throws IllegalArgumentException if parameters are invalid
     */
    public WolfCryptECPublicKey(ECPoint publicPoint,
        ECParameterSpec paramSpec) throws IllegalArgumentException {

        if (publicPoint == null) {
            throw new IllegalArgumentException(
                "Public point cannot be null");
        }
        if (paramSpec == null) {
            throw new IllegalArgumentException(
                "ECParameterSpec cannot be null");
        }

        /* Store params */
        this.publicPoint = publicPoint;
        this.paramSpec = paramSpec;

        /* Generate the DER-encoded form */
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
            ecc.publicKeyDecode(derData);

        } catch (WolfCryptException e) {
            throw new IllegalArgumentException(
                "Invalid DER-encoded public key: " + e.getMessage(), e);

        } finally {
            if (ecc != null) {
                ecc.releaseNativeStruct();
            }
        }
    }

    /**
     * Generate DER-encoded form from public point and parameters.
     *
     * @return DER-encoded X.509 public key
     *
     * @throws IllegalArgumentException if key generation fails
     */
    private byte[] generateDerFromParameters()
        throws IllegalArgumentException {

        byte[] xBytes = null;
        byte[] yBytes = null;
        Ecc ecc = null;

        try {
            log("generating DER from public point and ECParameterSpec");

            /* Get curve name from the ECParameterSpec */
            String curveName = null;
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

            /* Extract X and Y coordinates from the ECPoint */
            BigInteger x = this.publicPoint.getAffineX();
            BigInteger y = this.publicPoint.getAffineY();

            if (x == null || y == null) {
                throw new IllegalArgumentException(
                    "ECPoint must have affine coordinates");
            }

            /* Convert coordinates to byte[] */
            xBytes = Ecc.bigIntToByteArrayNoLeadingZeros(x);
            yBytes = Ecc.bigIntToByteArrayNoLeadingZeros(y);

            /* Import public key into Ecc using raw import */
            ecc = new Ecc();
            ecc.importPublicRaw(xBytes, yBytes, curveName);

            /* Export as X.509 DER */
            byte[] derEncoded = ecc.publicKeyEncode();
            if (derEncoded == null) {
                throw new IllegalArgumentException(
                    "Failed to encode public key as DER");
            }

            log("successfully generated DER from raw parameters, length: " +
                derEncoded.length);

            return derEncoded;

        } catch (WolfCryptException e) {
            throw new IllegalArgumentException(
                "Failed to generate DER from parameters: " +
                e.getMessage(), e);

        } finally {
            if (ecc != null) {
                ecc.releaseNativeStruct();
            }
            if (xBytes != null) {
                Arrays.fill(xBytes, (byte) 0);
            }
            if (yBytes != null) {
                Arrays.fill(yBytes, (byte) 0);
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

        log("extracting ECParameterSpec from DER-encoded public key");

        return WolfCryptECParameterSpec.extractFromKey(this.encoded, false);
    }

    /**
     * Extract public key point from the DER-encoded key.
     *
     * @return ECPoint representing the public key point
     *
     * @throws IllegalStateException if public point extraction fails
     */
    private ECPoint extractPublicPoint() throws IllegalStateException {

        byte[] xBytes = null;
        byte[] yBytes = null;
        Ecc ecc = null;

        try {
            /* Load public key into wolfCrypt */
            ecc = new Ecc();
            ecc.publicKeyDecode(this.encoded);

            /* Export the raw public key coordinates */
            byte[][] coords = ecc.exportPublicRaw();
            if (coords == null || coords.length != 2) {
                throw new IllegalStateException(
                    "Failed to export public key coordinates");
            }

            xBytes = coords[0];
            yBytes = coords[1];

            if (xBytes == null || yBytes == null) {
                throw new IllegalStateException("Invalid coordinate data");
            }

            /* Convert to BigInteger and create ECPoint */
            BigInteger x = new BigInteger(1, xBytes);
            BigInteger y = new BigInteger(1, yBytes);

            return new ECPoint(x, y);

        } catch (WolfCryptException e) {
            throw new IllegalStateException(
                "Failed to extract public point: " + e.getMessage(), e);

        } finally {
            if (ecc != null) {
                ecc.releaseNativeStruct();
            }
            if (xBytes != null) {
                Arrays.fill(xBytes, (byte) 0);
            }
            if (yBytes != null) {
                Arrays.fill(yBytes, (byte) 0);
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
            () -> "[WolfCryptECPublicKey] " + msg);
    }

    @Override
    public ECPoint getW() {
        synchronized (stateLock) {
            if (destroyed) {
                throw new IllegalStateException("Key has been destroyed");
            }

            if (publicPoint == null) {
                log("extracting public key point from DER");
                publicPoint = extractPublicPoint();
            }

            return publicPoint;
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
        return "X.509";
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
                publicPoint = null;
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
        if (!(obj instanceof ECPublicKey)) {
            return false;
        }

        ECPublicKey other = (ECPublicKey) obj;

        synchronized (stateLock) {
            if (destroyed) {
                return false;
            }

            /* Compare encoded forms if both are WolfCryptECPublicKey */
            if (obj instanceof WolfCryptECPublicKey) {
                WolfCryptECPublicKey otherWolf = (WolfCryptECPublicKey) obj;
                synchronized (otherWolf.stateLock) {
                    if (otherWolf.destroyed) {
                        return false;
                    }
                    return Arrays.equals(this.encoded, otherWolf.encoded);
                }
            }

            /* Compare with other ECPublicKey implementations */
            try {
                if (getW().equals(other.getW()) &&
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
                return "WolfCryptECPublicKey[DESTROYED]";
            }
            return "WolfCryptECPublicKey[algorithm=EC, format=X.509, " +
                   "encoded.length=" + encoded.length + "]";
        }
    }
}

