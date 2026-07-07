/* WolfCryptXmssPublicKey.java
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
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.util.Arrays;
import java.security.PublicKey;
import javax.security.auth.Destroyable;

import com.wolfssl.wolfcrypt.Xmss;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfJCE XMSS/XMSS^MT (RFC 8391) public key.
 *
 * <p>{@link #getAlgorithm()} returns {@code "XMSS"} for a single-tree key or
 * {@code "XMSSMT"} for a multi-tree key. {@link #getEncoded()} returns the
 * X.509 SubjectPublicKeyInfo DER (RFC 9802 form). The DER is validated, and
 * its XMSS parameter set derived, by importing through wolfCrypt at
 * construction.</p>
 */
public class WolfCryptXmssPublicKey implements PublicKey, Destroyable {

    private static final long serialVersionUID = 1L;

    /** X.509 SubjectPublicKeyInfo DER. */
    private byte[] encoded = null;

    /** Cached raw XMSS public key (BIT STRING contents) so verify-init
     * does not re-parse the SPKI. Transient: recomputed on deserialization. */
    private transient byte[] rawPublicKey = null;

    /** Parameter set string (ex: "XMSS-SHA2_10_256"), from the public key. */
    private final String paramStr;

    /** True if this is a multi-tree XMSS^MT key, from the public key. */
    private final boolean isXmssMt;

    /** Track if object has been destroyed. */
    private boolean destroyed = false;

    /** Lock around destroyed flag and encoded buffer. Not final because it is
     * reinitialized after deserialization. */
    private transient Object stateLock = new Object();

    /**
     * Create from an X.509 SubjectPublicKeyInfo DER.
     *
     * @param x509Der X.509 SubjectPublicKeyInfo DER (RFC 9802 form)
     *
     * @throws IllegalArgumentException if the DER is malformed or not a
     *         recognized XMSS/XMSS^MT SubjectPublicKeyInfo
     */
    public WolfCryptXmssPublicKey(byte[] x509Der)
        throws IllegalArgumentException {

        byte[] rawPub;
        WolfCryptSpkiUtil.ParsedXmssPub parsed;
        Xmss key = null;

        if (x509Der == null || x509Der.length == 0) {
            throw new IllegalArgumentException(
                "Encoded key data cannot be null or empty");
        }

        /* Extract the raw XMSS public key and the family (XMSS vs XMSS^MT,
         * from the SPKI OID), then validate it by importing through wolfCrypt,
         * which derives the specific parameter set. */
        parsed = WolfCryptSpkiUtil.parseXmssPublicKeyDer(x509Der);
        rawPub = parsed.raw;

        try {
            key = new Xmss();
            key.importPublicRaw(rawPub, parsed.isXmssMt);
            this.paramStr = key.getParamStr();
            this.isXmssMt = key.isXmssMt();
        }
        catch (WolfCryptException e) {
            throw new IllegalArgumentException(
                "Not a valid XMSS X.509 SPKI DER: " + e.getMessage(), e);
        }
        finally {
            if (key != null) {
                key.releaseNativeStruct();
            }
        }

        /* Normalize to the canonical RFC 9802 SubjectPublicKeyInfo, so
         * getEncoded() and equals() are stable across input encodings. */
        this.encoded = WolfCryptSpkiUtil.encodeXmssPublicKeyDer(rawPub,
            this.isXmssMt);
        this.rawPublicKey = rawPub.clone();
    }

    /**
     * Get the raw XMSS public key bytes for use with the native verifier.
     *
     * @return raw public key bytes, or null if destroyed
     */
    byte[] getRawPublicKey() {
        synchronized (stateLock) {
            if (destroyed || rawPublicKey == null) {
                return null;
            }
            return rawPublicKey.clone();
        }
    }

    /**
     * @return {@code "XMSS"} single-tree key, {@code "XMSSMT"} for multi-tree
     */
    @Override
    public String getAlgorithm() {
        return this.isXmssMt ? "XMSSMT" : "XMSS";
    }

    /**
     * @return {@code "X.509"}
     */
    @Override
    public String getFormat() {
        return "X.509";
    }

    /**
     * @return X.509 SubjectPublicKeyInfo DER, or null if destroyed
     */
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
     * Get the parameter set string for this key.
     *
     * @return the RFC 8391 parameter set name (for example
     *         "XMSS-SHA2_10_256" or "XMSSMT-SHA2_20/2_256")
     */
    public String getParamStr() {
        return this.paramStr;
    }

    /**
     * Whether this is a multi-tree XMSS^MT key. Used by the Signature engine
     * to re-import the raw key with the correct family.
     *
     * @return true for XMSS^MT, false for single-tree XMSS
     */
    boolean isMultiTree() {
        return this.isXmssMt;
    }

    /**
     * Destroy this key by zeroing the encoded buffer.
     */
    @Override
    public void destroy() {
        synchronized (stateLock) {
            if (!destroyed) {
                if (encoded != null) {
                    Arrays.fill(encoded, (byte) 0);
                }
                if (rawPublicKey != null) {
                    Arrays.fill(rawPublicKey, (byte) 0);
                    rawPublicKey = null;
                }
                destroyed = true;
            }
        }
    }

    /**
     * @return true if destroyed, false otherwise
     */
    @Override
    public boolean isDestroyed() {
        synchronized (stateLock) {
            return destroyed;
        }
    }

    /**
     * @return hash code over the encoded key, or 0 if destroyed
     */
    @Override
    public int hashCode() {
        synchronized (stateLock) {
            if (destroyed) {
                return 0;
            }
            return Arrays.hashCode(encoded);
        }
    }

    /**
     * Equality based on algorithm name and X.509 encoding. The parameter set
     * is carried in the encoded public key, so byte equality of the encoding
     * implies the same parameter set.
     *
     * @param obj object to compare
     *
     * @return true if obj is an XMSS PublicKey with the same algorithm and
     *         X.509 encoding
     */
    @Override
    public boolean equals(Object obj) {

        byte[] thisEncoded;
        PublicKey other;

        if (this == obj) {
            return true;
        }

        if (!(obj instanceof PublicKey)) {
            return false;
        }
        other = (PublicKey) obj;

        synchronized (stateLock) {
            if (destroyed) {
                return false;
            }
            thisEncoded = encoded.clone();
        }

        /* Call the other key's getEncoded() outside our own stateLock to
         * avoid a lock-ordering deadlock when two WolfCryptXmssPublicKey
         * instances are compared concurrently in opposite order. */
        byte[] otherEncoded = other.getEncoded();
        return otherEncoded != null &&
            getAlgorithm().equals(other.getAlgorithm()) &&
            Arrays.equals(thisEncoded, otherEncoded);
    }

    /**
     * @return string representation, or a destroyed marker
     */
    @Override
    public String toString() {
        synchronized (stateLock) {
            if (destroyed) {
                return "WolfCryptXmssPublicKey[DESTROYED]";
            }
            return "WolfCryptXmssPublicKey[algorithm=" + getAlgorithm() +
                ", params=" + paramStr + ", format=X.509, encoded.length=" +
                encoded.length + "]";
        }
    }

    /**
     * Custom deserialization to reinitialize transient state.
     *
     * @param in ObjectInputStream to read from
     *
     * @throws IOException if an I/O error occurs
     * @throws ClassNotFoundException if a class cannot be found
     */
    private void readObject(ObjectInputStream in)
        throws IOException, ClassNotFoundException {

        in.defaultReadObject();
        stateLock = new Object();
        if (!destroyed && encoded != null) {
            WolfCryptSpkiUtil.ParsedXmssPub parsed;
            try {
                parsed = WolfCryptSpkiUtil.parseXmssPublicKeyDer(encoded);
            }
            catch (IllegalArgumentException e) {
                throw new InvalidObjectException(
                    "Invalid XMSS public key encoding: " + e.getMessage());
            }
            /* The family (XMSS vs XMSS^MT) is serialized in isXmssMt as well
             * as carried by the encoded AlgorithmIdentifier OID. Reject a
             * stream where the two disagree, so getAlgorithm()/isMultiTree()
             * cannot desync from getEncoded(). */
            if (parsed.isXmssMt != this.isXmssMt) {
                throw new InvalidObjectException(
                    "XMSS family flag does not match encoded " +
                    "AlgorithmIdentifier");
            }
            this.rawPublicKey = parsed.raw;
        }
    }
}
