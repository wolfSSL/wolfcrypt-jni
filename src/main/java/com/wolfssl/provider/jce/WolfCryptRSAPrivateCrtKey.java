/* WolfCryptRSAPrivateCrtKey.java
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
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Arrays;
import javax.security.auth.Destroyable;

import com.wolfssl.wolfcrypt.Rsa;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfJCE RSAPrivateCrtKey implementation.
 * This class implements the RSAPrivateCrtKey interface using wolfCrypt.
 */
public class WolfCryptRSAPrivateCrtKey implements RSAPrivateCrtKey,
    Destroyable {

    private static final long serialVersionUID = 1L;

    /** DER-encoded private key (PKCS#8 format) */
    private byte[] encoded = null;

    /* Cached key components, extracted on first access */
    private transient BigInteger modulus = null;
    private transient BigInteger publicExponent = null;
    private transient BigInteger privateExponent = null;
    private transient BigInteger primeP = null;
    private transient BigInteger primeQ = null;
    private transient BigInteger primeExponentP = null;
    private transient BigInteger primeExponentQ = null;
    private transient BigInteger crtCoefficient = null;

    /** Track if object has been destroyed */
    private boolean destroyed = false;

    /* Lock around use of destroyed boolean and cached values.
     * Note: Cannot be final because it needs to be reinitialized after
     * deserialization. */
    private transient Object stateLock = new Object();

    /**
     * Create new WolfCryptRSAPrivateCrtKey from DER-encoded PKCS#8 data.
     *
     * @param encoded DER-encoded PKCS#8 private key
     *
     * @throws IllegalArgumentException if encoded data is null or invalid
     */
    public WolfCryptRSAPrivateCrtKey(byte[] encoded)
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
     * Create new WolfCryptRSAPrivateCrtKey from CRT parameters.
     *
     * @param modulus the modulus n
     * @param publicExponent the public exponent e
     * @param privateExponent the private exponent d
     * @param primeP the prime factor p
     * @param primeQ the prime factor q
     * @param primeExponentP dP = d mod (p-1)
     * @param primeExponentQ dQ = d mod (q-1)
     * @param crtCoefficient qInv = q^-1 mod p
     *
     * @throws IllegalArgumentException if parameters are invalid
     */
    public WolfCryptRSAPrivateCrtKey(BigInteger modulus,
        BigInteger publicExponent, BigInteger privateExponent,
        BigInteger primeP, BigInteger primeQ, BigInteger primeExponentP,
        BigInteger primeExponentQ, BigInteger crtCoefficient)
        throws IllegalArgumentException {

        if (modulus == null || publicExponent == null ||
            privateExponent == null || primeP == null || primeQ == null ||
            primeExponentP == null || primeExponentQ == null ||
            crtCoefficient == null) {
            throw new IllegalArgumentException(
                "RSA key parameters cannot be null");
        }

        /* Store parameters */
        this.modulus = modulus;
        this.publicExponent = publicExponent;
        this.privateExponent = privateExponent;
        this.primeP = primeP;
        this.primeQ = primeQ;
        this.primeExponentP = primeExponentP;
        this.primeExponentQ = primeExponentQ;
        this.crtCoefficient = crtCoefficient;

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
            rsa.decodePrivateKeyPKCS8(derData);

        } catch (WolfCryptException e) {
            throw new IllegalArgumentException(
                "Invalid DER-encoded private key: " + e.getMessage(), e);

        } finally {
            if (rsa != null) {
                rsa.releaseNativeStruct();
            }
        }
    }

    /**
     * Generate DER-encoded form from RSA parameters.
     *
     * @return DER-encoded PKCS#8 private key
     *
     * @throws IllegalArgumentException if key generation fails
     */
    private byte[] generateDerFromParameters()
        throws IllegalArgumentException {

        Rsa rsa = null;
        byte[] derKey = null;
        byte[] n = null, e = null, d = null, p = null;
        byte[] q = null, dP = null, dQ = null, u = null;

        try {
            /* Convert BigIntegers to byte arrays first (unsigned, big-endian).
             * BigInteger.toByteArray() may add a leading 0 byte if the high
             * bit is set (to indicate positive sign). Remove it if there. */
            n = removeLeadingZero(modulus.toByteArray());
            e = removeLeadingZero(publicExponent.toByteArray());
            d = removeLeadingZero(privateExponent.toByteArray());
            p = removeLeadingZero(primeP.toByteArray());
            q = removeLeadingZero(primeQ.toByteArray());
            dP = removeLeadingZero(primeExponentP.toByteArray());
            dQ = removeLeadingZero(primeExponentQ.toByteArray());
            u = removeLeadingZero(crtCoefficient.toByteArray());

            /* Create Rsa object and import parameters */
            rsa = new Rsa();
            rsa.importRawPrivateKey(n, e, d, p, q, dP, dQ, u);

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
            if (e != null) {
                Arrays.fill(e, (byte)0);
            }
            if (d != null) {
                Arrays.fill(d, (byte)0);
            }
            if (p != null) {
                Arrays.fill(p, (byte)0);
            }
            if (q != null) {
                Arrays.fill(q, (byte)0);
            }
            if (dP != null) {
                Arrays.fill(dP, (byte)0);
            }
            if (dQ != null) {
                Arrays.fill(dQ, (byte)0);
            }
            if (u != null) {
                Arrays.fill(u, (byte)0);
            }
            if (rsa != null) {
                rsa.releaseNativeStruct();
            }
        }
    }

    /**
     * Remove leading zero byte from byte array if present.
     * BigInteger.toByteArray() adds a leading zero byte for positive numbers
     * when the high bit would otherwise be set.
     *
     * @param data byte array to process
     * @return byte array without leading zero, or original if no leading zero
     */
    private byte[] removeLeadingZero(byte[] data) {
        if ((data != null) && (data.length > 1) && (data[0] == 0)) {
            byte[] result = new byte[data.length - 1];
            System.arraycopy(data, 1, result, 0, data.length - 1);
            return result;
        }
        return data;
    }

    /**
     * Extract key components from DER-encoded key.
     *
     * This method is called when key components are first accessed.
     */
    private void extractKeyComponents() {

        Rsa rsa = null;
        byte[] n = null;
        byte[] e = null;
        byte[] d = null;
        byte[] p = null;
        byte[] q = null;
        byte[] dP = null;
        byte[] dQ = null;
        byte[] u = null;

        synchronized (stateLock) {
            if (destroyed) {
                throw new IllegalStateException("Key has been destroyed");
            }

            /* Return if already extracted */
            if (modulus != null) {
                return;
            }

            log("extracting RSA key components from DER encoding");

            try {
                rsa = new Rsa();
                rsa.decodePrivateKeyPKCS8(this.encoded);

                /* Get key size to allocate buffers */
                int keySize = rsa.getEncryptSize();
                if (keySize <= 0) {
                    throw new IllegalStateException(
                        "Invalid RSA key size: " + keySize);
                }

                /* Allocate output buffers (use key size for all) */
                n = new byte[keySize];
                e = new byte[keySize];
                d = new byte[keySize];
                p = new byte[keySize];
                q = new byte[keySize];
                dP = new byte[keySize];
                dQ = new byte[keySize];
                u = new byte[keySize];

                long[] nSz = new long[] { keySize };
                long[] eSz = new long[] { keySize };
                long[] dSz = new long[] { keySize };
                long[] pSz = new long[] { keySize };
                long[] qSz = new long[] { keySize };
                long[] dPSz = new long[] { keySize };
                long[] dQSz = new long[] { keySize };
                long[] uSz = new long[] { keySize };

                /* Export all key components */
                rsa.exportRawPrivateKey(n, nSz, e, eSz, d, dSz, p, pSz,
                                        q, qSz, dP, dPSz, dQ, dQSz, u, uSz);

                /* Convert to BigInteger */
                this.modulus = new BigInteger(1,
                    Arrays.copyOf(n, (int)nSz[0]));
                this.publicExponent = new BigInteger(1,
                    Arrays.copyOf(e, (int)eSz[0]));
                this.privateExponent = new BigInteger(1,
                    Arrays.copyOf(d, (int)dSz[0]));
                this.primeP = new BigInteger(1,
                    Arrays.copyOf(p, (int)pSz[0]));
                this.primeQ = new BigInteger(1,
                    Arrays.copyOf(q, (int)qSz[0]));
                this.primeExponentP = new BigInteger(1,
                    Arrays.copyOf(dP, (int)dPSz[0]));
                this.primeExponentQ = new BigInteger(1,
                    Arrays.copyOf(dQ, (int)dQSz[0]));
                this.crtCoefficient = new BigInteger(1,
                    Arrays.copyOf(u, (int)uSz[0]));

                log("successfully extracted RSA key components");

            } catch (WolfCryptException ex) {
                throw new IllegalStateException(
                    "Failed to extract key components: " + ex.getMessage(),
                    ex);

            } finally {
                if (rsa != null) {
                    rsa.releaseNativeStruct();
                }
                if (n != null) {
                    Arrays.fill(n, (byte)0);
                }
                if (e != null) {
                    Arrays.fill(e, (byte)0);
                }
                if (d != null) {
                    Arrays.fill(d, (byte)0);
                }
                if (p != null) {
                    Arrays.fill(p, (byte)0);
                }
                if (q != null) {
                    Arrays.fill(q, (byte)0);
                }
                if (dP != null) {
                    Arrays.fill(dP, (byte)0);
                }
                if (dQ != null) {
                    Arrays.fill(dQ, (byte)0);
                }
                if (u != null) {
                    Arrays.fill(u, (byte)0);
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
            () -> "[RSA PrivateKey] " + msg);
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

    @Override
    public BigInteger getPrivateExponent() {
        extractKeyComponents();
        synchronized (stateLock) {
            return this.privateExponent;
        }
    }

    @Override
    public BigInteger getPrimeP() {
        extractKeyComponents();
        synchronized (stateLock) {
            return this.primeP;
        }
    }

    @Override
    public BigInteger getPrimeQ() {
        extractKeyComponents();
        synchronized (stateLock) {
            return this.primeQ;
        }
    }

    @Override
    public BigInteger getPrimeExponentP() {
        extractKeyComponents();
        synchronized (stateLock) {
            return this.primeExponentP;
        }
    }

    @Override
    public BigInteger getPrimeExponentQ() {
        extractKeyComponents();
        synchronized (stateLock) {
            return this.primeExponentQ;
        }
    }

    @Override
    public BigInteger getCrtCoefficient() {
        extractKeyComponents();
        synchronized (stateLock) {
            return this.crtCoefficient;
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
                publicExponent = null;
                privateExponent = null;
                primeP = null;
                primeQ = null;
                primeExponentP = null;
                primeExponentQ = null;
                crtCoefficient = null;
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
        if (!(obj instanceof RSAPrivateCrtKey)) {
            return false;
        }

        RSAPrivateCrtKey other = (RSAPrivateCrtKey) obj;

        synchronized (stateLock) {
            if (destroyed) {
                return false;
            }

            /* Compare encoded forms if both are WolfCryptRSAPrivateCrtKey */
            if (obj instanceof WolfCryptRSAPrivateCrtKey) {
                WolfCryptRSAPrivateCrtKey otherWolf =
                    (WolfCryptRSAPrivateCrtKey) obj;

                synchronized (otherWolf.stateLock) {
                    if (otherWolf.destroyed) {
                        return false;
                    }

                    /* Get both encoded forms and compare. getEncoded()
                     * returns a clone, so we need to compare the actual
                     * encoded field */
                    byte[] thisEnc = this.encoded;
                    byte[] otherEnc = otherWolf.encoded;

                    if (thisEnc == null || otherEnc == null) {
                        return (thisEnc == otherEnc);
                    }

                    return Arrays.equals(thisEnc, otherEnc);
                }
            }

            /* Compare with other RSAPrivateCrtKey implementations */
            try {
                return (getModulus().equals(other.getModulus()) &&
                    getPublicExponent().equals(other.getPublicExponent()) &&
                    getPrivateExponent().equals(other.getPrivateExponent()) &&
                    getPrimeP().equals(other.getPrimeP()) &&
                    getPrimeQ().equals(other.getPrimeQ()) &&
                    getPrimeExponentP().equals(other.getPrimeExponentP()) &&
                    getPrimeExponentQ().equals(other.getPrimeExponentQ()) &&
                    getCrtCoefficient().equals(other.getCrtCoefficient()));

            } catch (Exception ex) {
                return false;
            }
        }
    }
}

