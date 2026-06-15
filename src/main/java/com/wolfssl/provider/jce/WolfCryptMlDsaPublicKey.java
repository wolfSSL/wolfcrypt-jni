/* WolfCryptMlDsaPublicKey.java
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
import java.util.Arrays;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import javax.security.auth.Destroyable;

import com.wolfssl.wolfcrypt.MlDsa;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfJCE ML-DSA (FIPS 204) public key.
 *
 * <p>{@link #getAlgorithm()} returns the family name {@code "ML-DSA"} to match
 * match SunJCE / JDK 24 conventions. The parameter set (44/65/87) is exposed
 * via {@link #getParams()}.</p>
 *
 * <p>{@link #getEncoded()} returns the X.509 SubjectPublicKeyInfo DER
 * generated via wolfCrypt {@code wc_Dilithium_PublicKeyToDer}.</p>
 */
public class WolfCryptMlDsaPublicKey implements PublicKey, Destroyable {

    private static final long serialVersionUID = 1L;

    /** X.509 SubjectPublicKeyInfo DER. */
    private byte[] encoded = null;

    /** ML-DSA level: {@code MlDsa.ML_DSA_44/65/87}. */
    private final int level;

    /** Track if object has been destroyed. */
    private boolean destroyed = false;

    /** Lock around use of destroyed boolean and encoded buffer. Cannot be
     * final because it is reinitialized after deserialization. */
    private transient Object stateLock = new Object();

    /**
     * Create from X.509 SubjectPublicKeyInfo DER. The level is auto-detected
     * by wolfCrypt (post PR 10310 native wolfssl), or via per-level fallback
     * on older wolfSSL versions.
     *
     * @param x509Der X.509 SubjectPublicKeyInfo DER
     *
     * @throws IllegalArgumentException if DER is malformed or not a
     *         recognized ML-DSA SPKI
     */
    public WolfCryptMlDsaPublicKey(byte[] x509Der)
        throws IllegalArgumentException {

        if (x509Der == null || x509Der.length == 0) {
            throw new IllegalArgumentException(
                "Encoded key data cannot be null or empty");
        }

        try {
            this.level = MlDsa.parseAndValidateMlDsaPublicKeyDer(x509Der);
        }
        catch (WolfCryptException e) {
            throw new IllegalArgumentException(
                "Not a valid ML-DSA X.509 SPKI DER: " + e.getMessage(), e);
        }

        this.encoded = x509Der.clone();
    }

    /**
     * Create from X.509 SubjectPublicKeyInfo DER with explicit level. The
     * DER is validated by importing through wolfCrypt at construction.
     * Use this when the level is known to skip auto detection overhead.
     *
     * @param x509Der X.509 SubjectPublicKeyInfo DER
     * @param level ML-DSA level: {@link MlDsa#ML_DSA_44},
     *              {@link MlDsa#ML_DSA_65}, or {@link MlDsa#ML_DSA_87}
     *
     * @throws IllegalArgumentException if level is invalid, DER is
     *         malformed, or doesn't match the given level.
     */
    public WolfCryptMlDsaPublicKey(byte[] x509Der, int level)
        throws IllegalArgumentException {

        validateLevel(level);

        if (x509Der == null || x509Der.length == 0) {
            throw new IllegalArgumentException(
                "Encoded key data cannot be null or empty");
        }

        validateDer(level, x509Der);

        this.level = level;
        this.encoded = x509Der.clone();
    }

    /**
     * Validates ML-DSA level.
     *
     * @param level ML-DSA level to validate
     *
     * @throws IllegalArgumentException if level is not recognized
     */
    private static void validateLevel(int level)
        throws IllegalArgumentException {

        if (level != MlDsa.ML_DSA_44 &&
            level != MlDsa.ML_DSA_65 &&
            level != MlDsa.ML_DSA_87) {

            throw new IllegalArgumentException(
                "Invalid ML-DSA level: " + level);
        }
    }

    /**
     * Validates public key DER by importing through wolfCrypt.
     *
     * @param level ML-DSA level to validate against
     * @param der X.509 SubjectPublicKeyInfo DER to validate
     *
     * @throws IllegalArgumentException if DER is invalid for the given level
     */
    private static void validateDer(int level, byte[] der)
        throws IllegalArgumentException {

        MlDsa key = null;
        try {
            key = new MlDsa(level);
            key.importPublicKeyDer(der);

        } catch (WolfCryptException e) {
            throw new IllegalArgumentException(
                "Invalid ML-DSA SPKI DER for level " + level + ": " +
                e.getMessage(), e);

        } finally {
            if (key != null) {
                key.releaseNativeStruct();
            }
        }
    }

    /**
     * Get the standard algorithm name for this key.
     *
     * @return "ML-DSA"
     */
    @Override
    public String getAlgorithm() {
        return "ML-DSA";
    }

    /**
     * Get the name of the primary encoding format for this key.
     *
     * @return "X.509"
     */
    @Override
    public String getFormat() {
        return "X.509";
    }

    /**
     * Get the X.509 SubjectPublicKeyInfo DER encoding of this key.
     *
     * @return X.509 DER, or null if the key has been destroyed
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
     * Get the AlgorithmParameterSpec for this key.
     *
     * @return AlgorithmParameterSpec or null
     */
    public AlgorithmParameterSpec getParams() {
        return WolfPQCJdkCompat.namedParameterSpec(this.level);
    }

    /**
     * Get the ML-DSA parameter-set level.
     *
     * @return level value, e.g. {@link MlDsa#ML_DSA_44},
     *         {@link MlDsa#ML_DSA_65}, or {@link MlDsa#ML_DSA_87}
     */
    public int getLevel() {
        return this.level;
    }

    /**
     * Destroy this key, by zero encoded buffer and mark as destroyed.
     */
    @Override
    public void destroy() {
        synchronized (stateLock) {
            if (!destroyed) {
                if (encoded != null) {
                    Arrays.fill(encoded, (byte) 0);
                }
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
     * Hash code based on encoded key and level.
     *
     * @return hash code, or 0 if destroyed
     */
    @Override
    public int hashCode() {
        synchronized (stateLock) {
            if (destroyed) {
                return 0;
            }
            return Arrays.hashCode(encoded) ^ level;
        }
    }

    /**
     * Equality based on algorithm and encoded key. The ML-DSA parameter
     * set is carried in the X.509 SPKI AlgorithmIdentifier OID, so byte
     * equality of the encoded form also implies same level.
     *
     * @return true if obj is a PublicKey with algorithm "ML-DSA" and the
     *         same X.509 SPKI encoding, false otherwise or if destroyed.
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
            return otherEncoded != null &&
                "ML-DSA".equals(other.getAlgorithm()) &&
                Arrays.equals(this.encoded, otherEncoded);
        }
    }

    /**
     * String representation of this key.
     *
     * @return string describing this key, or indicating it is destroyed
     */
    @Override
    public String toString() {
        synchronized (stateLock) {
            if (destroyed) {
                return "WolfCryptMlDsaPublicKey[DESTROYED]";
            }
            return "WolfCryptMlDsaPublicKey[algorithm=ML-DSA, " +
                "params=" + WolfPQCJdkCompat.levelToParamName(level) +
                ", format=X.509, encoded.length=" + encoded.length + "]";
        }
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
