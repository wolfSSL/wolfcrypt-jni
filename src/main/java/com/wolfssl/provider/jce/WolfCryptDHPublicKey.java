/* WolfCryptDHPublicKey.java
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.util.Arrays;
import javax.security.auth.Destroyable;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import com.wolfssl.wolfcrypt.Dh;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfJCE DHPublicKey implementation.
 * This class implements the DHPublicKey interface using wolfCrypt.
 */
public class WolfCryptDHPublicKey implements DHPublicKey, Destroyable {

    private static final long serialVersionUID = 1L;

    /** DER-encoded public key (X.509 format) */
    private byte[] encoded = null;

    /** Cached DHParameterSpec, extracted on first access */
    private transient DHParameterSpec paramSpec = null;

    /** Cached public key value, extracted on first access */
    private transient BigInteger publicValue = null;

    /** Track if object has been destroyed */
    private boolean destroyed = false;

    /* Lock around use of destroyed boolean and cached values.
     * Note: Cannot be final because it needs to be reinitialized after
     * deserialization. */
    private transient Object stateLock = new Object();

    /**
     * Create new WolfCryptDHPublicKey from DER-encoded X.509 data.
     *
     * @param encoded DER-encoded X.509 public key
     *
     * @throws IllegalArgumentException if encoded data is null or invalid
     */
    public WolfCryptDHPublicKey(byte[] encoded)
        throws IllegalArgumentException {

        if (encoded == null || encoded.length == 0) {
            throw new IllegalArgumentException(
                "Encoded key data cannot be null or empty");
        }

        /* Parse X.509 DER to extract public value and parameters */
        parseX509Der(encoded);

        /* Store a copy of the encoded data */
        this.encoded = encoded.clone();
    }

    /**
     * Create new WolfCryptDHPublicKey from public value and parameters.
     *
     * @param publicValue the public key value (y)
     * @param paramSpec the DH parameters
     *
     * @throws IllegalArgumentException if parameters are invalid
     */
    public WolfCryptDHPublicKey(BigInteger publicValue,
        DHParameterSpec paramSpec) throws IllegalArgumentException {

        if (publicValue == null) {
            throw new IllegalArgumentException(
                "Public value cannot be null");
        }
        if (paramSpec == null) {
            throw new IllegalArgumentException(
                "DHParameterSpec cannot be null");
        }

        /* Store params */
        this.publicValue = publicValue;
        this.paramSpec = paramSpec;

        /* Generate X.509 DER-encoded form using pure Java */
        this.encoded = generateX509Der();
    }

    /**
     * Parse X.509 DER structure to extract public value and parameters.
     *
     * We are doing this in Java for now since wolfCrypt functionality to
     * decode DH parameters requires WOLFSSL_DH_EXTRA, which is not defined
     * for wolfCrypt FIPS bundles (one of the primary user categories of
     * wolfJCE).
     *
     * X.509 DH structure:
     * SEQUENCE {
     *   SEQUENCE {
     *     algorithm OID
     *     parameters SEQUENCE { p INTEGER, g INTEGER }
     *   }
     *   publicKey BIT STRING { INTEGER }
     * }
     *
     * If wolfCrypt FIPS does define WOLFSSL_DH_EXTRA, the following APIs
     * could be used instead of manual parsing here:
     *     wc_InitDecodedCert()
     *     wc_ParseCert()
     *     wc_GetPubKeyDerFromCert()
     *     wc_DhPublicKeyDecode()
     *     wc_DhExportParamsRaw()
     *     wc_DhExportKeyPair()
     *
     * @param derData DER-encoded X.509 public key
     *
     * @throws IllegalArgumentException if DER data is invalid
     */
    private void parseX509Der(byte[] derData)
        throws IllegalArgumentException {

        int idx = 0;
        int oidLen, pLen, gLen, pubLen;
        byte[] pBytes, gBytes, pubBytes;
        BigInteger p, g, publicVal;

        try {

            /* Outer SEQUENCE */
            if (derData[idx++] != 0x30) {
                throw new IllegalArgumentException(
                    "Invalid X.509: expected SEQUENCE tag");
            }
            WolfCryptASN1Util.getDERLength(derData, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(derData, idx);

            /* AlgorithmIdentifier SEQUENCE */
            if (derData[idx++] != 0x30) {
                throw new IllegalArgumentException(
                    "Invalid X.509: expected AlgorithmIdentifier SEQUENCE");
            }
            WolfCryptASN1Util.getDERLength(derData, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(derData, idx);

            /* Algorithm OID - skip it */
            if (derData[idx++] != 0x06) {
                throw new IllegalArgumentException(
                    "Invalid X.509: expected algorithm OID");
            }
            oidLen = WolfCryptASN1Util.getDERLength(derData, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(derData, idx);
            idx += oidLen;

            /* DH Parameters SEQUENCE { p, g } */
            if (derData[idx++] != 0x30) {
                throw new IllegalArgumentException(
                    "Invalid X.509: expected DH parameters SEQUENCE");
            }
            WolfCryptASN1Util.getDERLength(derData, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(derData, idx);

            /* p INTEGER */
            if (derData[idx++] != 0x02) {
                throw new IllegalArgumentException(
                    "Invalid X.509: expected p INTEGER");
            }
            pLen = WolfCryptASN1Util.getDERLength(derData, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(derData, idx);
            pBytes = new byte[pLen];
            System.arraycopy(derData, idx, pBytes, 0, pLen);
            p = new BigInteger(1, pBytes);
            idx += pLen;

            /* g INTEGER */
            if (derData[idx++] != 0x02) {
                throw new IllegalArgumentException(
                    "Invalid X.509: expected g INTEGER");
            }
            gLen = WolfCryptASN1Util.getDERLength(derData, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(derData, idx);
            gBytes = new byte[gLen];
            System.arraycopy(derData, idx, gBytes, 0, gLen);
            g = new BigInteger(1, gBytes);
            idx += gLen;

            /* PublicKey BIT STRING */
            if (derData[idx++] != 0x03) {
                throw new IllegalArgumentException(
                    "Invalid X.509: expected publicKey BIT STRING");
            }
            WolfCryptASN1Util.getDERLength(derData, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(derData, idx);

            /* Skip unused bits byte (should be 0) */
            idx++;

            /* Public key value is an INTEGER inside the BIT STRING */
            if (derData[idx++] != 0x02) {
                throw new IllegalArgumentException(
                    "Invalid X.509: expected public value INTEGER");
            }
            pubLen = WolfCryptASN1Util.getDERLength(derData, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(derData, idx);
            pubBytes = new byte[pubLen];
            System.arraycopy(derData, idx, pubBytes, 0, pubLen);
            publicVal = new BigInteger(1, pubBytes);

            /* Store extracted values */
            this.publicValue = publicVal;
            this.paramSpec = new DHParameterSpec(p, g);

            log("parsed X.509 DER: p.bitLength=" + p.bitLength() +
                ", g=" + g + ", pub.bitLength=" + publicVal.bitLength());

        } catch (ArrayIndexOutOfBoundsException e) {
            throw new IllegalArgumentException(
                "Invalid X.509 encoding: " + e.getMessage(), e);

        } catch (Exception e) {
            throw new IllegalArgumentException(
                "Failed to parse X.509: " + e.getMessage(), e);
        }
    }

    /**
     * Generate X.509 DER-encoded form from public value and parameters.
     *
     * This method generates the DER encoding in pure Java to support
     * wolfCrypt FIPS builds that do not define WOLFSSL_DH_EXTRA.
     *
     * If WOLFSSL_DH_EXTRA were available, we could use these native APIs:
     *   - wc_DhImportKeyPair() to import the key
     *   - wc_DhPubKeyToDer() to encode as X.509
     *
     * X.509 DH SubjectPublicKeyInfo structure:
     * SEQUENCE {
     *   AlgorithmIdentifier SEQUENCE {
     *     algorithm OBJECT IDENTIFIER (1.2.840.113549.1.3.1)
     *     parameters SEQUENCE { p INTEGER, g INTEGER }
     *   }
     *   publicKey BIT STRING {
     *     unused_bits (0x00)
     *     INTEGER (public value)
     *   }
     * }
     *
     * @return DER-encoded X.509 public key
     *
     * @throws IllegalArgumentException if key generation fails
     */
    private byte[] generateX509Der()
        throws IllegalArgumentException {

        byte[] pubKeyInteger;
        byte[] x509Der;

        try {
            log("generating X.509 DER manually from public value and " +
                "DHParameterSpec");

            ByteArrayOutputStream out = new ByteArrayOutputStream();

            /* AlgorithmIdentifier: SEQUENCE { OID, parameters } */
            out.write(WolfCryptASN1Util.encodeDHAlgorithmIdentifier(
                this.paramSpec.getP(), this.paramSpec.getG()));

            /* PublicKey: BIT STRING containing INTEGER */
            pubKeyInteger =
                WolfCryptASN1Util.encodeDERInteger(this.publicValue);
            out.write(WolfCryptASN1Util.encodeDERBitString(pubKeyInteger));

            /* Wrap everything in outer SEQUENCE */
            x509Der = WolfCryptASN1Util.encodeDERSequence(out.toByteArray());

            log("successfully generated X.509 DER manually, length: " +
                x509Der.length);

            return x509Der;

        } catch (IOException e) {
            throw new IllegalArgumentException(
                "Failed to generate X.509 DER: " + e.getMessage(), e);
        }
    }

    /**
     * Extract DHParameterSpec from the DER-encoded key.
     *
     * @return DHParameterSpec for this key
     *
     * @throws IllegalStateException if parameter extraction fails
     */
    private DHParameterSpec extractDHParameterSpec()
        throws IllegalStateException {

        int idx = 0;
        int oidLen, pLen, gLen;
        byte[] pBytes, gBytes;
        BigInteger p, g;

        try {
            log("extracting DHParameterSpec from DER-encoded public key");

            /* Outer SEQUENCE */
            if (this.encoded[idx++] != 0x30) {
                throw new IllegalStateException(
                    "Invalid X.509: expected SEQUENCE tag");
            }
            WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);

            /* AlgorithmIdentifier SEQUENCE */
            if (this.encoded[idx++] != 0x30) {
                throw new IllegalStateException(
                    "Invalid X.509: expected AlgorithmIdentifier SEQUENCE");
            }
            WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);

            /* Algorithm OID - skip it */
            if (this.encoded[idx++] != 0x06) {
                throw new IllegalStateException(
                    "Invalid X.509: expected algorithm OID");
            }
            oidLen = WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);
            idx += oidLen;

            /* DH Parameters SEQUENCE { p, g } */
            if (this.encoded[idx++] != 0x30) {
                throw new IllegalStateException(
                    "Invalid X.509: expected DH parameters SEQUENCE");
            }
            WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);

            /* p INTEGER */
            if (this.encoded[idx++] != 0x02) {
                throw new IllegalStateException(
                    "Invalid X.509: expected p INTEGER");
            }
            pLen = WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);
            pBytes = new byte[pLen];
            System.arraycopy(this.encoded, idx, pBytes, 0, pLen);
            p = new BigInteger(1, pBytes);
            idx += pLen;

            /* g INTEGER */
            if (this.encoded[idx++] != 0x02) {
                throw new IllegalStateException(
                    "Invalid X.509: expected g INTEGER");
            }
            gLen = WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);
            gBytes = new byte[gLen];
            System.arraycopy(this.encoded, idx, gBytes, 0, gLen);
            g = new BigInteger(1, gBytes);

            return new DHParameterSpec(p, g);

        } catch (ArrayIndexOutOfBoundsException e) {
            throw new IllegalStateException(
                "Invalid X.509 encoding: " + e.getMessage(), e);

        } catch (Exception e) {
            throw new IllegalStateException(
                "Failed to extract DHParameterSpec: " + e.getMessage(), e);
        }
    }

    /**
     * Extract public key value from the DER-encoded key.
     *
     * @return BigInteger representing the public key value
     *
     * @throws IllegalStateException if public value extraction fails
     */
    private BigInteger extractPublicValue() throws IllegalStateException {

        int idx = 0;
        int paramsSeqLen;
        int oidLen, pubLen;
        byte[] pubBytes;
        BigInteger publicVal;

        try {
            log("extracting public key value from DER-encoded public key");

            /* Outer SEQUENCE */
            if (this.encoded[idx++] != 0x30) {
                throw new IllegalStateException(
                    "Invalid X.509: expected SEQUENCE tag");
            }
            WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);

            /* AlgorithmIdentifier SEQUENCE */
            if (this.encoded[idx++] != 0x30) {
                throw new IllegalStateException(
                    "Invalid X.509: expected AlgorithmIdentifier SEQUENCE");
            }
            WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);

            /* Algorithm OID - skip it */
            if (this.encoded[idx++] != 0x06) {
                throw new IllegalStateException(
                    "Invalid X.509: expected algorithm OID");
            }
            oidLen = WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);
            idx += oidLen;

            /* DH Parameters SEQUENCE { p, g } - skip */
            if (this.encoded[idx++] != 0x30) {
                throw new IllegalStateException(
                    "Invalid X.509: expected DH parameters SEQUENCE");
            }
            paramsSeqLen = WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);
            idx += paramsSeqLen;

            /* PublicKey BIT STRING */
            if (this.encoded[idx++] != 0x03) {
                throw new IllegalStateException(
                    "Invalid X.509: expected publicKey BIT STRING");
            }
            WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);

            /* Skip unused bits byte (should be 0) */
            idx++;

            /* Public key value is an INTEGER inside the BIT STRING */
            if (this.encoded[idx++] != 0x02) {
                throw new IllegalStateException(
                    "Invalid X.509: expected public value INTEGER");
            }
            pubLen = WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);
            pubBytes = new byte[pubLen];
            System.arraycopy(this.encoded, idx, pubBytes, 0, pubLen);
            publicVal = new BigInteger(1, pubBytes);

            return publicVal;

        } catch (ArrayIndexOutOfBoundsException e) {
            throw new IllegalStateException(
                "Invalid X.509 encoding: " + e.getMessage(), e);

        } catch (Exception e) {
            throw new IllegalStateException(
                "Failed to extract public value: " + e.getMessage(), e);
        }
    }

    /**
     * Internal method for logging output.
     *
     * @param msg message to be logged
     */
    private void log(String msg) {
        WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO,
            () -> "[WolfCryptDHPublicKey] " + msg);
    }

    @Override
    public BigInteger getY() {

        synchronized (stateLock) {
            if (destroyed) {
                throw new IllegalStateException("Key has been destroyed");
            }

            if (publicValue == null) {
                log("extracting public key value from DER");
                publicValue = extractPublicValue();
            }
            return publicValue;
        }
    }

    @Override
    public DHParameterSpec getParams() {

        synchronized (stateLock) {
            if (destroyed) {
                throw new IllegalStateException("Key has been destroyed");
            }

            if (paramSpec == null) {
                log("extracting DH parameters from DER");
                paramSpec = extractDHParameterSpec();
            }
            return paramSpec;
        }
    }

    @Override
    public String getAlgorithm() {
        return "DH";
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
    @Override
    public void destroy() {

        synchronized (stateLock) {
            if (!destroyed) {
                if (encoded != null) {
                    Arrays.fill(encoded, (byte) 0);
                }
                publicValue = null;
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
    @Override
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
        if (!(obj instanceof DHPublicKey)) {
            return false;
        }

        DHPublicKey other = (DHPublicKey) obj;

        synchronized (stateLock) {
            if (destroyed) {
                return false;
            }

            /* Compare encoded forms if both are WolfCryptDHPublicKey */
            if (obj instanceof WolfCryptDHPublicKey) {
                WolfCryptDHPublicKey otherWolf = (WolfCryptDHPublicKey) obj;

                synchronized (otherWolf.stateLock) {
                    if (otherWolf.destroyed) {
                        return false;
                    }
                    return Arrays.equals(this.encoded, otherWolf.encoded);
                }
            }

            /* Compare with other DHPublicKey implementations */
            try {
                if (getY().equals(other.getY()) &&
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
                return "WolfCryptDHPublicKey[DESTROYED]";
            }
            return "WolfCryptDHPublicKey[algorithm=DH, format=X.509, " +
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

