/* WolfCryptRSAPrivateKey.java
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
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import javax.security.auth.Destroyable;

import com.wolfssl.wolfcrypt.Rsa;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfJCE RSAPrivateKey implementation (non-CRT form).
 *
 * This class implements the RSAPrivateKey interface for non-CRT keys
 * (containing only modulus and private exponent). Separate from
 * WolfCryptRSAPrivateCrtKey to ensure correct behavior in instanceof checks.
 *
 * Note: Keys created with this class have zero/placeholder values for CRT
 * parameters (p, q, dP, dQ, u). This matches SunJCE behavior.
 */
public class WolfCryptRSAPrivateKey implements RSAPrivateKey, Destroyable {

    private static final long serialVersionUID = 1L;

    /** DER-encoded private key (PKCS#8 format) with zero CRT params */
    private byte[] encoded = null;

    /* Key components (only n and d) */
    private transient BigInteger modulus = null;
    private transient BigInteger privateExponent = null;

    /** Track if object has been destroyed */
    private boolean destroyed = false;

    /* Lock around use of destroyed boolean and cached values.
     * Note: Cannot be final because it needs to be reinitialized after
     * deserialization. */
    private transient Object stateLock = new Object();

    /**
     * Create new WolfCryptRSAPrivateKey from modulus and private exponent.
     *
     * This constructor creates a non-CRT key with zero placeholder values
     * for missing CRT parameters (e, p, q, dP, dQ, u).
     *
     * @param modulus the modulus n
     * @param privateExponent the private exponent d
     *
     * @throws IllegalArgumentException if parameters are invalid
     */
    public WolfCryptRSAPrivateKey(BigInteger modulus,
        BigInteger privateExponent) throws IllegalArgumentException {

        if (modulus == null || privateExponent == null) {
            throw new IllegalArgumentException(
                "Modulus and private exponent cannot be null");
        }

        /* Store parameters */
        this.modulus = modulus;
        this.privateExponent = privateExponent;

        /* Generate DER-encoded form */
        this.encoded = generateDerWithZeroCrtParams();
    }

    /**
     * Generate DER-encoded PKCS#1 form with zero CRT parameters.
     *
     * Creates a valid PKCS#1 RSAPrivateKey structure with modulus and
     * private exponent, but with zero values for publicExponent, p, q,
     * dP, dQ, and u.
     *
     * @return DER-encoded PKCS#8 private key
     *
     * @throws IllegalArgumentException if key generation fails
     */
    private byte[] generateDerWithZeroCrtParams()
        throws IllegalArgumentException {

        Rsa rsa = null;
        byte[] derKey = null;
        byte[] n = null, d = null, zero = null;

        try {
            /* Convert BigIntegers to byte arrays (unsigned, big-endian) */
            n = convertBigIntegerToUnsignedBytes(modulus);
            d = convertBigIntegerToUnsignedBytes(privateExponent);

            /* Use zero for all CRT parameters */
            zero = new byte[1];
            zero[0] = 0;

            /* Create Rsa object and import with zero CRT params */
            rsa = new Rsa();
            rsa.importRawPrivateKey(n, zero, d, zero, zero, zero, zero, zero);

            /* Export as PKCS#8 DER */
            derKey = rsa.privateKeyEncodePKCS8();
            if (derKey == null) {
                throw new IllegalArgumentException(
                    "Failed to encode private key as PKCS#8 DER");
            }

            return derKey;

        } catch (WolfCryptException ex) {
            throw new IllegalArgumentException(
                "Failed to generate DER from params: " + ex.getMessage(), ex);

        } finally {
            if (n != null) {
                Arrays.fill(n, (byte)0);
            }
            if (d != null) {
                Arrays.fill(d, (byte)0);
            }
            if (zero != null) {
                Arrays.fill(zero, (byte)0);
            }
            if (rsa != null) {
                rsa.releaseNativeStruct();
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
     * Internal method for logging output.
     *
     * @param msg message to be logged
     */
    private void log(String msg) {
        WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO,
            () -> "[RSA PrivateKey non-CRT] " + msg);
    }

    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    @Override
    public String getFormat() {
        synchronized (stateLock) {
            if (destroyed) {
                return null;
            }
            return "PKCS#8";
        }
    }

    @Override
    public byte[] getEncoded() {
        synchronized (stateLock) {
            if (destroyed) {
                return null;
            }

            if (this.encoded == null) {
                return null;
            }

            return this.encoded.clone();
        }
    }

    @Override
    public BigInteger getModulus() {
        synchronized (stateLock) {
            if (destroyed) {
                throw new IllegalStateException("Key has been destroyed");
            }
            return this.modulus;
        }
    }

    @Override
    public BigInteger getPrivateExponent() {
        synchronized (stateLock) {
            if (destroyed) {
                throw new IllegalStateException("Key has been destroyed");
            }
            return this.privateExponent;
        }
    }

    /**
     * Destroy this key by zeroing out sensitive data.
     */
    @Override
    public void destroy() {
        synchronized (stateLock) {
            if (!destroyed) {
                if (encoded != null) {
                    Arrays.fill(encoded, (byte)0);
                    encoded = null;
                }
                /* Clear cached values */
                modulus = null;
                privateExponent = null;
                destroyed = true;
            }
        }
    }

    /**
     * Check if this key has been destroyed.
     *
     * @return true if destroyed, false otherwise
     */
    @Override
    public boolean isDestroyed() {
        synchronized (stateLock) {
            return destroyed;
        }
    }

    /**
     * Custom deserialization handler to reinitialize transient fields.
     *
     * @param in the ObjectInputStream to read from
     *
     * @throws IOException if an I/O error occurs
     * @throws ClassNotFoundException if class cannot be found
     */
    private void readObject(ObjectInputStream in)
        throws IOException, ClassNotFoundException {

        in.defaultReadObject();

        /* Reinitialize transient lock */
        this.stateLock = new Object();
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
        /* Non-CRT key is not equal to a CRT key */
        if (obj instanceof RSAPrivateCrtKey) {
            return false;
        }

        if (!(obj instanceof RSAPrivateKey)) {
            return false;
        }

        RSAPrivateKey other = (RSAPrivateKey) obj;

        synchronized (stateLock) {
            if (destroyed) {
                return false;
            }

            /* Compare encoded forms if both are WolfCryptRSAPrivateKey */
            if (obj instanceof WolfCryptRSAPrivateKey) {
                WolfCryptRSAPrivateKey otherWolf =
                    (WolfCryptRSAPrivateKey) obj;

                synchronized (otherWolf.stateLock) {
                    if (otherWolf.destroyed) {
                        return false;
                    }

                    byte[] thisEnc = this.encoded;
                    byte[] otherEnc = otherWolf.encoded;

                    if (thisEnc == null || otherEnc == null) {
                        return (thisEnc == otherEnc);
                    }

                    return Arrays.equals(thisEnc, otherEnc);
                }
            }

            /* Compare with other RSAPrivateKey implementations */
            try {
                return (getModulus().equals(other.getModulus()) &&
                    getPrivateExponent().equals(other.getPrivateExponent()));

            } catch (Exception ex) {
                return false;
            }
        }
    }
}

