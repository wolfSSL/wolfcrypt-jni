/* WolfCryptRSAPublicKey.java
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

import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import javax.security.auth.Destroyable;

import com.wolfssl.wolfcrypt.Rsa;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfJCE RSAPublicKey implementation.
 * This class implements the RSAPublicKey interface using wolfCrypt.
 */
public class WolfCryptRSAPublicKey implements RSAPublicKey, Destroyable {

    private static final long serialVersionUID = 1L;

    /** DER-encoded public key (X.509 format) */
    private byte[] encoded = null;

    /* Cached key components, extracted on first access */
    private transient BigInteger modulus = null;
    private transient BigInteger publicExponent = null;

    /** Track if object has been destroyed */
    private boolean destroyed = false;

    /* Lock around use of destroyed boolean and cached values.
     * Note: Cannot be final because it needs to be reinitialized after
     * deserialization. */
    private transient Object stateLock = new Object();

    /**
     * Create new WolfCryptRSAPublicKey from DER-encoded X.509 data.
     *
     * @param encoded DER-encoded X.509 public key
     *
     * @throws IllegalArgumentException if encoded data is null or invalid
     */
    public WolfCryptRSAPublicKey(byte[] encoded)
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
     * Create new WolfCryptRSAPublicKey from modulus and public exponent.
     *
     * @param modulus the modulus n
     * @param publicExponent the public exponent e
     *
     * @throws IllegalArgumentException if parameters are invalid
     */
    public WolfCryptRSAPublicKey(BigInteger modulus,
        BigInteger publicExponent) throws IllegalArgumentException {

        if (modulus == null) {
            throw new IllegalArgumentException("Modulus cannot be null");
        }
        if (publicExponent == null) {
            throw new IllegalArgumentException(
                "Public exponent cannot be null");
        }

        /* Store parameters */
        this.modulus = modulus;
        this.publicExponent = publicExponent;

        /* Generate DER-encoded form */
        this.encoded = generateDerFromParameters();
    }

    /**
     * Validate DER format by attempting to import into wolfCrypt Rsa.
     *
     * @param derData DER-encoded key data to validate
     *
     * @throws IllegalArgumentException if DER data is invalid
     */
    private void validateDerFormat(byte[] derData)
        throws IllegalArgumentException {

        Rsa rsa = null;

        try {
            rsa = new Rsa();
            rsa.decodePublicKey(derData);

        } catch (WolfCryptException e) {
            throw new IllegalArgumentException(
                "Invalid DER-encoded public key: " + e.getMessage(), e);

        } finally {
            if (rsa != null) {
                rsa.releaseNativeStruct();
            }
        }
    }

    /**
     * Generate DER-encoded form from modulus and public exponent.
     *
     * @return DER-encoded X.509 public key
     *
     * @throws IllegalArgumentException if key generation fails
     */
    private byte[] generateDerFromParameters()
        throws IllegalArgumentException {

        byte[] nBytes = null;
        byte[] eBytes = null;
        byte[] derEncoded = null;
        Rsa rsa = null;

        try {
            log("generating DER from modulus and public exponent");

            /* Convert BigIntegers to byte arrays (unsigned, no leading 0s) */
            nBytes = this.modulus.toByteArray();
            eBytes = this.publicExponent.toByteArray();

            /* Remove leading zero byte if present (sign byte) */
            if ((nBytes.length > 0) && (nBytes[0] == 0)) {
                nBytes = Arrays.copyOfRange(nBytes, 1, nBytes.length);
            }
            if ((eBytes.length > 0) && (eBytes[0] == 0)) {
                eBytes = Arrays.copyOfRange(eBytes, 1, eBytes.length);
            }

            /* Import public key into Rsa using raw import */
            rsa = new Rsa();
            rsa.decodeRawPublicKey(nBytes, eBytes);

            /* Export as X.509 DER */
            derEncoded = rsa.exportPublicDer();
            if (derEncoded == null) {
                throw new IllegalArgumentException(
                    "Failed to encode public key as DER");
            }

            log("successfully generated DER from raw parameters, length: " +
                derEncoded.length);

            return derEncoded;

        } catch (WolfCryptException e) {
            throw new IllegalArgumentException(
                "Failed to generate DER from parameters: " + e.getMessage(),
                e);

        } finally {
            if (rsa != null) {
                rsa.releaseNativeStruct();
            }
            /* Zero out temporary buffers */
            if (nBytes != null) {
                Arrays.fill(nBytes, (byte)0);
            }
            if (eBytes != null) {
                Arrays.fill(eBytes, (byte)0);
            }
        }
    }

    /**
     * Extract key components from DER-encoded key.
     *
     * This method is called lazily when key components are first accessed.
     */
    private void extractKeyComponents() {

        int keySize = 0;
        Rsa rsa = null;
        byte[] n = null;
        byte[] e = null;
        long[] nSz, eSz;

        synchronized (stateLock) {
            if (destroyed) {
                throw new IllegalStateException("Key has been destroyed");
            }

            /* Return if already extracted */
            if (modulus != null) {
                return;
            }

            log("extracting RSA public key components from DER encoding");

            try {
                rsa = new Rsa();
                rsa.decodePublicKey(this.encoded);

                /* Get key size to allocate buffers */
                keySize = rsa.getEncryptSize();
                if (keySize <= 0) {
                    throw new IllegalStateException(
                        "Invalid RSA key size: " + keySize);
                }

                /* Allocate output buffers */
                n = new byte[keySize];
                e = new byte[keySize];

                nSz = new long[] { keySize };
                eSz = new long[] { keySize };

                /* Export public key components */
                rsa.exportRawPublicKey(n, nSz, e, eSz);

                /* Convert to BigInteger */
                this.modulus = new BigInteger(1,
                    Arrays.copyOf(n, (int)nSz[0]));
                this.publicExponent = new BigInteger(1,
                    Arrays.copyOf(e, (int)eSz[0]));

                log("successfully extracted RSA public key components");

            } catch (WolfCryptException ex) {
                throw new IllegalStateException(
                    "Failed to extract key components: " + ex.getMessage(),
                    ex);

            } finally {
                if (rsa != null) {
                    rsa.releaseNativeStruct();
                }
                /* Zero out sensitive data */
                if (n != null) {
                    Arrays.fill(n, (byte)0);
                }
                if (e != null) {
                    Arrays.fill(e, (byte)0);
                }
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
            () -> "[RSA PublicKey] " + msg);
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
            return "X.509";
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
        extractKeyComponents();
        synchronized (stateLock) {
            return this.modulus;
        }
    }

    @Override
    public BigInteger getPublicExponent() {
        extractKeyComponents();
        synchronized (stateLock) {
            return this.publicExponent;
        }
    }

    /**
     * Destroy this key by zeroing out data.
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
                publicExponent = null;
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
        if (!(obj instanceof RSAPublicKey)) {
            return false;
        }

        RSAPublicKey other = (RSAPublicKey) obj;

        synchronized (stateLock) {
            if (destroyed) {
                return false;
            }

            /* Compare encoded forms if both are WolfCryptRSAPublicKey */
            if (obj instanceof WolfCryptRSAPublicKey) {
                WolfCryptRSAPublicKey otherWolf =
                    (WolfCryptRSAPublicKey) obj;

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

            /* Compare with other RSAPublicKey implementations */
            try {
                return (getModulus().equals(other.getModulus()) &&
                    getPublicExponent().equals(other.getPublicExponent()));

            } catch (Exception ex) {
                return false;
            }
        }
    }
}

