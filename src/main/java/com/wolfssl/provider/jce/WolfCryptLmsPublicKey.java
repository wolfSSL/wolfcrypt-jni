/* WolfCryptLmsPublicKey.java
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

import com.wolfssl.wolfcrypt.Lms;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfJCE LMS/HSS (RFC 8554) public key.
 *
 * <p>{@link #getAlgorithm()} returns the JDK standard name {@code "HSS/LMS"};
 * the alias {@code "LMS"} is also registered. {@link #getEncoded()} returns the
 * X.509 SubjectPublicKeyInfo DER (RFC 9708 unwrapped form). The DER is
 * validated, and its LMS/HSS parameter set derived, by importing through
 * wolfCrypt at construction.</p>
 */
public class WolfCryptLmsPublicKey implements PublicKey, Destroyable {

    private static final long serialVersionUID = 1L;

    /** X.509 SubjectPublicKeyInfo DER. */
    private byte[] encoded = null;

    /** Cached raw HSS/LMS public key (the BIT STRING contents) so verify-init
     * does not re-parse the SPKI. Transient: recomputed on deserialization. */
    private transient byte[] rawPublicKey = null;

    /** Number of HSS levels (1 for single-tree LMS), from the public key. */
    private final int levels;
    /** Per-level Merkle tree height, from the public key. */
    private final int height;
    /** LM-OTS Winternitz parameter, from the public key. */
    private final int winternitz;
    /** Hash-family selector ({@code Lms.LMS_*}), from the public key. */
    private final int hashType;

    /** Track if object has been destroyed. */
    private boolean destroyed = false;

    /** Lock around destroyed flag and encoded buffer. Not final because it is
     * reinitialized after deserialization. */
    private transient Object stateLock = new Object();

    /**
     * Create from an X.509 SubjectPublicKeyInfo DER.
     *
     * @param x509Der X.509 SubjectPublicKeyInfo DER (RFC 9708 or RFC 8708 form)
     *
     * @throws IllegalArgumentException if the DER is malformed or not a
     *         recognized LMS/HSS SubjectPublicKeyInfo, or if LMS/HSS is not
     *         compiled into native wolfCrypt
     */
    public WolfCryptLmsPublicKey(byte[] x509Der)
        throws IllegalArgumentException {

        byte[] rawPub;
        Lms key = null;

        if (x509Der == null || x509Der.length == 0) {
            throw new IllegalArgumentException(
                "Encoded key data cannot be null or empty");
        }

        /* Extract the raw HSS public key (accepts both SPKI body forms) and
         * validate it by importing through wolfCrypt, which also derives the
         * parameter set. */
        rawPub = WolfCryptSpkiUtil.parseLmsPublicKeyDer(x509Der);

        try {
            key = new Lms();
            key.importPublicRaw(rawPub);
            this.levels = key.getLevels();
            this.height = key.getHeight();
            this.winternitz = key.getWinternitz();
            this.hashType = key.getHashType();
        }
        catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                throw new IllegalArgumentException(
                    "LMS/HSS is not compiled into native wolfCrypt", e);
            }
            throw new IllegalArgumentException(
                "Not a valid LMS/HSS X.509 SPKI DER: " + e.getMessage(), e);
        }
        finally {
            if (key != null) {
                key.releaseNativeStruct();
            }
        }

        /* Normalize to the canonical RFC 9708 unwrapped SubjectPublicKeyInfo,
         * so getEncoded() and equals() are stable across both input
         * encodings. */
        this.encoded = WolfCryptSpkiUtil.encodeLmsPublicKeyDer(rawPub);
        this.rawPublicKey = rawPub;
    }

    /**
     * Get the raw HSS/LMS public key bytes for use with the native verifier.
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
     * @return {@code "HSS/LMS"}, the JDK standard algorithm name (the alias
     *         {@code "LMS"} is also registered by this provider)
     */
    @Override
    public String getAlgorithm() {
        return "HSS/LMS";
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
     * Get the number of HSS levels in this key's parameter set.
     *
     * @return number of HSS levels (1 for single-tree LMS)
     */
    public int getLevels() {
        return this.levels;
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
     * Equality based on algorithm name and X.509 encoding. The algorithm name
     * may be either {@code "LMS"} or the JDK standard name {@code "HSS/LMS"}
     * (both registered by this provider), compared case-insensitively, so a
     * byte-identical key from another provider reporting either name compares
     * equal. The parameter set is carried in the encoded public key, so byte
     * equality of the encoding implies the same parameter set.
     *
     * @param obj object to compare
     *
     * @return true if obj is an LMS/HSS PublicKey with the same X.509 encoding
     */
    @Override
    public boolean equals(Object obj) {

        if (this == obj) {
            return true;
        }

        if (!(obj instanceof PublicKey)) {
            return false;
        }

        PublicKey other = (PublicKey) obj;

        synchronized (stateLock) {
            if (destroyed) {
                return false;
            }

            byte[] otherEncoded = other.getEncoded();
            String otherAlg = other.getAlgorithm();
            return otherEncoded != null &&
                ("LMS".equalsIgnoreCase(otherAlg) ||
                 "HSS/LMS".equalsIgnoreCase(otherAlg)) &&
                Arrays.equals(this.encoded, otherEncoded);
        }
    }

    /**
     * @return string representation, or a destroyed marker
     */
    @Override
    public String toString() {
        synchronized (stateLock) {
            if (destroyed) {
                return "WolfCryptLmsPublicKey[DESTROYED]";
            }
            return "WolfCryptLmsPublicKey[algorithm=HSS/LMS, levels=" + levels +
                ", height=" + height + ", winternitz=" + winternitz +
                ", format=X.509, encoded.length=" + encoded.length + "]";
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
            try {
                this.rawPublicKey =
                    WolfCryptSpkiUtil.parseLmsPublicKeyDer(encoded);
            }
            catch (IllegalArgumentException e) {
                throw (InvalidObjectException) new InvalidObjectException(
                    "Invalid serialized LMS public key: " +
                    e.getMessage()).initCause(e);
            }
        }
    }
}
