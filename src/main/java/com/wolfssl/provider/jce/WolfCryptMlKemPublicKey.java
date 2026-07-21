/* WolfCryptMlKemPublicKey.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
import java.util.Arrays;
import java.security.PublicKey;
import javax.security.auth.Destroyable;

/**
 * wolfCrypt JCE ML-KEM (FIPS 203) public key.
 *
 * Holds the ML-KEM parameter set level and the raw encapsulation key bytes.
 * getEncoded() returns an X.509 SubjectPublicKeyInfo (RFC 9935), encoded in
 * Java via {@link WolfCryptMlKemUtil} since native wolfSSL does not have some
 * needed ML-KEM ASN.1 support yet. getAlgorithm() returns "ML-KEM" (the family
 * name) to match JDK reference implementation regardless of parameter set.
 */
public class WolfCryptMlKemPublicKey implements PublicKey, Destroyable {

    private static final long serialVersionUID = 1L;

    /** ML-KEM parameter set (MlKem.ML_KEM_512/768/1024). */
    private int level;

    /** Raw encapsulation key bytes. */
    private byte[] rawPublic = null;

    /** Cached X.509 SubjectPublicKeyInfo encoding. */
    private byte[] encoded = null;

    /** True once this key has been destroyed. */
    private boolean destroyed = false;

    /** Lock around object state. */
    private transient Object stateLock = new Object();

    /**
     * Create an ML-KEM public key from a parameter set and raw key bytes.
     *
     * @param level ML-KEM parameter set
     * @param rawPublic raw encapsulation key bytes
     *
     * @throws IllegalArgumentException if inputs are invalid
     */
    public WolfCryptMlKemPublicKey(int level, byte[] rawPublic)
        throws IllegalArgumentException {

        if (rawPublic == null || rawPublic.length == 0) {
            throw new IllegalArgumentException(
                "ML-KEM public key bytes cannot be null or empty");
        }

        WolfCryptMlKemUtil.checkPublicKeyLength(level, rawPublic.length);

        this.level = level;
        this.rawPublic = rawPublic.clone();
        this.encoded = WolfCryptMlKemUtil.encodePublicKey(level,
            this.rawPublic);
    }

    /**
     * Create an ML-KEM public key from an X.509 SubjectPublicKeyInfo encoding.
     *
     * @param x509Der DER-encoded SubjectPublicKeyInfo
     *
     * @throws IllegalArgumentException if the encoding is invalid
     */
    public WolfCryptMlKemPublicKey(byte[] x509Der)
        throws IllegalArgumentException {

        WolfCryptMlKemUtil.ParsedPublic parsed;

        if (x509Der == null) {
            throw new IllegalArgumentException("Encoded key cannot be null");
        }

        parsed = WolfCryptMlKemUtil.parsePublicKey(x509Der);
        this.level = parsed.level;
        this.rawPublic = parsed.rawPublic.clone();
        /* Re-encode so getEncoded() is consistent regardless of any
         * non-canonical input. */
        this.encoded = WolfCryptMlKemUtil.encodePublicKey(this.level,
            this.rawPublic);
    }

    /**
     * Get the ML-KEM parameter set of this key.
     *
     * @return one of MlKem.ML_KEM_512/768/1024
     */
    int getLevel() {
        synchronized (stateLock) {
            return this.level;
        }
    }

    /**
     * Get the raw encapsulation key bytes.
     *
     * @return clone of the raw public key bytes, or null if destroyed
     */
    byte[] getRawPublicKey() {
        synchronized (stateLock) {
            if (destroyed || rawPublic == null) {
                return null;
            }
            return rawPublic.clone();
        }
    }

    @Override
    public String getAlgorithm() {
        return "ML-KEM";
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        synchronized (stateLock) {
            if (destroyed || encoded == null) {
                return null;
            }
            return encoded.clone();
        }
    }

    @Override
    public void destroy() {
        synchronized (stateLock) {
            if (!destroyed) {
                if (rawPublic != null) {
                    Arrays.fill(rawPublic, (byte) 0);
                    rawPublic = null;
                }
                if (encoded != null) {
                    Arrays.fill(encoded, (byte) 0);
                    encoded = null;
                }
                destroyed = true;
            }
        }
    }

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

        byte[] mine;
        PublicKey other;

        if (this == obj) {
            return true;
        }

        if (!(obj instanceof PublicKey)) {
            return false;
        }
        other = (PublicKey) obj;

        synchronized (stateLock) {
            if (destroyed || encoded == null) {
                return false;
            }
            mine = this.encoded.clone();
        }

        return Arrays.equals(mine, other.getEncoded());
    }

    /**
     * Custom deserialization to reinitialize transient state after
     * deserialization.
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
    }
}
