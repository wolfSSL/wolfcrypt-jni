/* WolfCryptDHPrivateKey.java
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

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;

import com.wolfssl.wolfcrypt.Dh;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfJCE DHPrivateKey implementation.
 * This class implements the DHPrivateKey interface using wolfCrypt.
 */
public class WolfCryptDHPrivateKey implements DHPrivateKey, Destroyable {

    private static final long serialVersionUID = 1L;

    /** DER-encoded private key (PKCS#8 format) */
    private byte[] encoded = null;

    /** Cached DHParameterSpec, extracted on first access */
    private transient DHParameterSpec paramSpec = null;

    /** Cached private key value, extracted on first access */
    private transient BigInteger privateValue = null;

    /** Track if object has been destroyed */
    private boolean destroyed = false;

    /* Lock around use of destroyed boolean and cached values.
     * Note: Cannot be final because it needs to be reinitialized after
     * deserialization. */
    private transient Object stateLock = new Object();

    /**
     * Create new WolfCryptDHPrivateKey from DER-encoded PKCS#8 data.
     *
     * @param encoded DER-encoded PKCS#8 private key
     *
     * @throws IllegalArgumentException if encoded data is null or invalid
     */
    public WolfCryptDHPrivateKey(byte[] encoded)
        throws IllegalArgumentException {

        if (encoded == null || encoded.length == 0) {
            throw new IllegalArgumentException(
                "Encoded key data cannot be null or empty");
        }

        /* Parse PKCS#8 DER to extract private value and parameters */
        parsePKCS8Der(encoded);

        /* Store a copy of the encoded data */
        this.encoded = encoded.clone();
    }

    /**
     * Create new WolfCryptDHPrivateKey from private value and parameters.
     *
     * @param privateValue the private key value (x)
     * @param paramSpec the DH parameters
     *
     * @throws IllegalArgumentException if parameters are invalid
     */
    public WolfCryptDHPrivateKey(BigInteger privateValue,
        DHParameterSpec paramSpec) throws IllegalArgumentException {

        if (privateValue == null) {
            throw new IllegalArgumentException(
                "Private value cannot be null");
        }
        if (paramSpec == null) {
            throw new IllegalArgumentException(
                "DHParameterSpec cannot be null");
        }

        /* Store params */
        this.privateValue = privateValue;
        this.paramSpec = paramSpec;

        /* Generate PKCS#8 DER-encoded form using pure Java */
        this.encoded = generatePKCS8Der();
    }

    /**
     * Parse PKCS#8 DER structure to extract private value and parameters.
     *
     * We are doing this in Java for now since wolfCrypt functionality to
     * decode PKCS#8 DER and extract DH parameters requires WOLFSSL_DH_EXTRA,
     * which is not defined for wolfCrypt FIPS bundles (one of the primary
     * user categories of wolfJCE).
     *
     * PKCS#8 DH structure:
     * SEQUENCE {
     *   version INTEGER
     *   SEQUENCE {
     *     algorithm OID
     *     parameters SEQUENCE { p INTEGER, g INTEGER }
     *   }
     *   privateKey OCTET STRING { INTEGER }
     * }
     *
     *
     * If wolfCrypt FIPS does define WOLFSSL_DH_EXTRA, the following APIs
     * could be used instead of manual parsing here:
     *     wc_InitDhKey()
     *     wc_DhKeyDecode()
     *     wc_DhExportParamsRaw()
     *     wc_DhExportKeyPair()
     *
     * @param derData DER-encoded PKCS#8 private key
     *
     * @throws IllegalArgumentException if DER data is invalid
     */
    private void parsePKCS8Der(byte[] derData)
        throws IllegalArgumentException {

        int idx = 0;
        int versionLen, oidLen, pLen, gLen, privLen;
        byte[] pBytes, gBytes, privBytes;
        BigInteger p, g, privateVal;

        try {

            /* Outer SEQUENCE */
            if (derData[idx++] != 0x30) {
                throw new IllegalArgumentException(
                    "Invalid PKCS#8: expected SEQUENCE tag");
            }
            WolfCryptASN1Util.getDERLength(derData, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(derData, idx);

            /* Version INTEGER (should be 0) */
            if (derData[idx++] != 0x02) {
                throw new IllegalArgumentException(
                    "Invalid PKCS#8: expected version INTEGER");
            }
            versionLen = WolfCryptASN1Util.getDERLength(derData, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(derData, idx);
            idx += versionLen; /* Skip version value */

            /* AlgorithmIdentifier SEQUENCE */
            if (derData[idx++] != 0x30) {
                throw new IllegalArgumentException(
                    "Invalid PKCS#8: expected AlgorithmIdentifier SEQUENCE");
            }
            WolfCryptASN1Util.getDERLength(derData, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(derData, idx);

            /* Algorithm OID - skip it */
            if (derData[idx++] != 0x06) {
                throw new IllegalArgumentException(
                    "Invalid PKCS#8: expected algorithm OID");
            }
            oidLen = WolfCryptASN1Util.getDERLength(derData, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(derData, idx);
            idx += oidLen;

            /* DH Parameters SEQUENCE { p, g } */
            if (derData[idx++] != 0x30) {
                throw new IllegalArgumentException(
                    "Invalid PKCS#8: expected DH parameters SEQUENCE");
            }
            WolfCryptASN1Util.getDERLength(derData, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(derData, idx);

            /* p INTEGER */
            if (derData[idx++] != 0x02) {
                throw new IllegalArgumentException(
                    "Invalid PKCS#8: expected p INTEGER");
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
                    "Invalid PKCS#8: expected g INTEGER");
            }
            gLen = WolfCryptASN1Util.getDERLength(derData, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(derData, idx);
            gBytes = new byte[gLen];
            System.arraycopy(derData, idx, gBytes, 0, gLen);
            g = new BigInteger(1, gBytes);
            idx += gLen;

            /* PrivateKey OCTET STRING */
            if (derData[idx++] != 0x04) {
                throw new IllegalArgumentException(
                    "Invalid PKCS#8: expected privateKey OCTET STRING");
            }
            WolfCryptASN1Util.getDERLength(derData, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(derData, idx);

            /* Private key value is an INTEGER inside the OCTET STRING */
            if (derData[idx++] != 0x02) {
                throw new IllegalArgumentException(
                    "Invalid PKCS#8: expected private value INTEGER");
            }
            privLen = WolfCryptASN1Util.getDERLength(derData, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(derData, idx);
            privBytes = new byte[privLen];
            System.arraycopy(derData, idx, privBytes, 0, privLen);
            privateVal = new BigInteger(1, privBytes);

            /* Store extracted values */
            this.privateValue = privateVal;
            this.paramSpec = new DHParameterSpec(p, g);

            log("parsed PKCS#8 DER: p.bitLength=" + p.bitLength() +
                ", g=" + g + ", priv.bitLength=" + privateVal.bitLength());

        } catch (ArrayIndexOutOfBoundsException e) {
            throw new IllegalArgumentException(
                "Invalid PKCS#8 encoding: " + e.getMessage(), e);

        } catch (Exception e) {
            throw new IllegalArgumentException(
                "Failed to parse PKCS#8: " + e.getMessage(), e);
        }
    }

    /**
     * Generate PKCS#8 DER-encoded form from private value and parameters.
     *
     * This method generates the DER encoding in pure Java to support
     * wolfCrypt FIPS builds that do not define WOLFSSL_DH_EXTRA.
     *
     * If WOLFSSL_DH_EXTRA were available, we could use these native APIs:
     *   - wc_DhImportKeyPair() to import the key
     *   - wc_DhPrivKeyToDer() to encode as PKCS#8
     *
     * PKCS#8 DH PrivateKeyInfo structure:
     * SEQUENCE {
     *   version INTEGER (0)
     *   AlgorithmIdentifier SEQUENCE {
     *     algorithm OBJECT IDENTIFIER (1.2.840.113549.1.3.1)
     *     parameters SEQUENCE { p INTEGER, g INTEGER }
     *   }
     *   privateKey OCTET STRING {
     *     INTEGER (private value)
     *   }
     * }
     *
     * @return DER-encoded PKCS#8 private key
     *
     * @throws IllegalArgumentException if key generation fails
     */
    private byte[] generatePKCS8Der()
        throws IllegalArgumentException {

        byte[] privKeyInteger;
        byte[] pkcs8Der;

        try {
            log("generating PKCS#8 DER manually from private value and " +
                "DHParameterSpec");

            ByteArrayOutputStream out = new ByteArrayOutputStream();

            /* Version: INTEGER 0 */
            out.write(WolfCryptASN1Util.encodeDERInteger(BigInteger.ZERO));

            /* AlgorithmIdentifier: SEQUENCE { OID, parameters } */
            out.write(WolfCryptASN1Util.encodeDHAlgorithmIdentifier(
                this.paramSpec.getP(), this.paramSpec.getG()));

            /* PrivateKey: OCTET STRING containing INTEGER */
            privKeyInteger =
                WolfCryptASN1Util.encodeDERInteger(this.privateValue);
            out.write(WolfCryptASN1Util.encodeDEROctetString(privKeyInteger));

            /* Wrap everything in outer SEQUENCE */
            pkcs8Der = WolfCryptASN1Util.encodeDERSequence(out.toByteArray());

            log("successfully generated PKCS#8 DER manually, length: " +
                pkcs8Der.length);

            return pkcs8Der;

        } catch (IOException e) {
            throw new IllegalArgumentException(
                "Failed to generate PKCS#8 DER: " + e.getMessage(), e);
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
        int versionLen, oidLen, pLen, gLen;
        byte[] pBytes, gBytes;
        BigInteger p, g;

        try {
            log("extracting DHParameterSpec from DER-encoded private key");

            /* Outer SEQUENCE */
            if (this.encoded[idx++] != 0x30) {
                throw new IllegalStateException(
                    "Invalid PKCS#8: expected SEQUENCE tag");
            }
            WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);

            /* Version INTEGER (should be 0) */
            if (this.encoded[idx++] != 0x02) {
                throw new IllegalStateException(
                    "Invalid PKCS#8: expected version INTEGER");
            }
            versionLen = WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);
            idx += versionLen;

            /* AlgorithmIdentifier SEQUENCE */
            if (this.encoded[idx++] != 0x30) {
                throw new IllegalStateException(
                    "Invalid PKCS#8: expected AlgorithmIdentifier SEQUENCE");
            }
            WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);

            /* Algorithm OID - skip it */
            if (this.encoded[idx++] != 0x06) {
                throw new IllegalStateException(
                    "Invalid PKCS#8: expected algorithm OID");
            }
            oidLen = WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);
            idx += oidLen;

            /* DH Parameters SEQUENCE { p, g } */
            if (this.encoded[idx++] != 0x30) {
                throw new IllegalStateException(
                    "Invalid PKCS#8: expected DH parameters SEQUENCE");
            }
            WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);

            /* p INTEGER */
            if (this.encoded[idx++] != 0x02) {
                throw new IllegalStateException(
                    "Invalid PKCS#8: expected p INTEGER");
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
                    "Invalid PKCS#8: expected g INTEGER");
            }
            gLen = WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);
            gBytes = new byte[gLen];
            System.arraycopy(this.encoded, idx, gBytes, 0, gLen);
            g = new BigInteger(1, gBytes);

            return new DHParameterSpec(p, g);

        } catch (ArrayIndexOutOfBoundsException e) {
            throw new IllegalStateException(
                "Invalid PKCS#8 encoding: " + e.getMessage(), e);

        } catch (Exception e) {
            throw new IllegalStateException(
                "Failed to extract DHParameterSpec: " + e.getMessage(), e);
        }
    }

    /**
     * Extract private key value from the DER-encoded key.
     *
     * @return BigInteger representing the private key value
     *
     * @throws IllegalStateException if private value extraction fails
     */
    private BigInteger extractPrivateValue() throws IllegalStateException {

        int idx = 0;
        int paramsSeqLen;
        int versionLen, oidLen, privLen;
        byte[] privBytes;
        BigInteger privateVal;

        try {
            log("extracting private key value from DER-encoded private key");

            /* Outer SEQUENCE */
            if (this.encoded[idx++] != 0x30) {
                throw new IllegalStateException(
                    "Invalid PKCS#8: expected SEQUENCE tag");
            }
            WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);

            /* Version INTEGER (should be 0) */
            if (this.encoded[idx++] != 0x02) {
                throw new IllegalStateException(
                    "Invalid PKCS#8: expected version INTEGER");
            }
            versionLen = WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);
            idx += versionLen;

            /* AlgorithmIdentifier SEQUENCE */
            if (this.encoded[idx++] != 0x30) {
                throw new IllegalStateException(
                    "Invalid PKCS#8: expected AlgorithmIdentifier SEQUENCE");
            }
            WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);

            /* Algorithm OID - skip it */
            if (this.encoded[idx++] != 0x06) {
                throw new IllegalStateException(
                    "Invalid PKCS#8: expected algorithm OID");
            }
            oidLen = WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);
            idx += oidLen;

            /* DH Parameters SEQUENCE { p, g } - skip */
            if (this.encoded[idx++] != 0x30) {
                throw new IllegalStateException(
                    "Invalid PKCS#8: expected DH parameters SEQUENCE");
            }
            paramsSeqLen = WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);
            idx += paramsSeqLen;

            /* PrivateKey OCTET STRING */
            if (this.encoded[idx++] != 0x04) {
                throw new IllegalStateException(
                    "Invalid PKCS#8: expected privateKey OCTET STRING");
            }
            WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);

            /* Private key value is an INTEGER inside the OCTET STRING */
            if (this.encoded[idx++] != 0x02) {
                throw new IllegalStateException(
                    "Invalid PKCS#8: expected private value INTEGER");
            }
            privLen = WolfCryptASN1Util.getDERLength(this.encoded, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(this.encoded, idx);
            privBytes = new byte[privLen];
            System.arraycopy(this.encoded, idx, privBytes, 0, privLen);
            privateVal = new BigInteger(1, privBytes);

            return privateVal;

        } catch (ArrayIndexOutOfBoundsException e) {
            throw new IllegalStateException(
                "Invalid PKCS#8 encoding: " + e.getMessage(), e);

        } catch (Exception e) {
            throw new IllegalStateException(
                "Failed to extract private value: " + e.getMessage(), e);
        }
    }

    /**
     * Internal method for logging output.
     *
     * @param msg message to be logged
     */
    private void log(String msg) {
        WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO,
            () -> "[WolfCryptDHPrivateKey] " + msg);
    }

    @Override
    public BigInteger getX() {

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
    @Override
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
        if (!(obj instanceof DHPrivateKey)) {
            return false;
        }

        DHPrivateKey other = (DHPrivateKey) obj;

        synchronized (stateLock) {
            if (destroyed) {
                return false;
            }

            /* Compare encoded forms if both are WolfCryptDHPrivateKey */
            if (obj instanceof WolfCryptDHPrivateKey) {
                WolfCryptDHPrivateKey otherWolf =
                    (WolfCryptDHPrivateKey) obj;

                synchronized (otherWolf.stateLock) {
                    if (otherWolf.destroyed) {
                        return false;
                    }
                    return Arrays.equals(this.encoded, otherWolf.encoded);
                }
            }

            /* Compare with other DHPrivateKey implementations */
            try {
                if (getX().equals(other.getX()) &&
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
                return "WolfCryptDHPrivateKey[DESTROYED]";
            }
            return "WolfCryptDHPrivateKey[algorithm=DH, format=PKCS#8, " +
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

