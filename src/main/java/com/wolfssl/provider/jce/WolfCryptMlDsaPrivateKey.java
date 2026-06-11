/* WolfCryptMlDsaPrivateKey.java
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
import java.security.PrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import javax.security.auth.Destroyable;

import com.wolfssl.wolfcrypt.MlDsa;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfJCE ML-DSA (FIPS 204) private key.
 *
 * <p>{@link #getAlgorithm()} returns the family name {@code "ML-DSA"};
 * the parameter set is exposed via {@link #getParams()}.</p>
 *
 * <p>{@link #getEncoded()} returns PKCS#8 PrivateKeyInfo DER generated via
 * wolfCrypt {@code wc_Dilithium_KeyToDer}. The encoded buffer is zeroed on
 * {@link #destroy()}.</p>
 */
public class WolfCryptMlDsaPrivateKey implements PrivateKey, Destroyable {

    private static final long serialVersionUID = 1L;

    /** PKCS#8 PrivateKeyInfo DER. Zeroed on destroy(). */
    private byte[] encoded = null;

    /** ML-DSA level: {@code MlDsa.ML_DSA_44/65/87}. */
    private final int level;

    /** Track if object has been destroyed. */
    private boolean destroyed = false;

    /** Lock around use of destroyed boolean and encoded buffer. */
    private transient Object stateLock = new Object();

    /**
     * Create from PKCS#8 PrivateKeyInfo DER. The level is auto detected by
     * wolfCrypt, or via per-level fallback on older native.
     *
     * ML-DSA level auto detection for PKCS#8 DER was added in native
     * wolfssl pull request 10310 (May 2026).
     *
     * @param pkcs8Der PKCS#8 PrivateKeyInfo DER
     *
     * @throws IllegalArgumentException if DER is malformed or not a
     *         recognized ML-DSA PKCS#8
     */
    public WolfCryptMlDsaPrivateKey(byte[] pkcs8Der)
        throws IllegalArgumentException {

        if (pkcs8Der == null || pkcs8Der.length == 0) {
            throw new IllegalArgumentException(
                "Encoded key data cannot be null or empty");
        }

        try {
            /* Parses PKCS#8 DER to both verify correctness and extract level */
            this.level = MlDsa.parseAndValidateMlDsaPrivateKeyDer(pkcs8Der);
        }
        catch (WolfCryptException e) {
            throw new IllegalArgumentException(
                "Not a valid ML-DSA PKCS#8 DER: " + e.getMessage(), e);
        }

        this.encoded = pkcs8Der.clone();
    }

    /**
     * Create from PKCS#8 PrivateKeyInfo DER with explicit level. The DER
     * is validated by importing through wolfCrypt at construction. Use this
     * when the level is already known and you want to skip auto detection
     * overhead.
     *
     * @param pkcs8Der PKCS#8 PrivateKeyInfo DER
     * @param level ML-DSA level: {@link MlDsa#ML_DSA_44},
     *              {@link MlDsa#ML_DSA_65}, or {@link MlDsa#ML_DSA_87}
     *
     * @throws IllegalArgumentException on invalid level or DER
     */
    public WolfCryptMlDsaPrivateKey(byte[] pkcs8Der, int level)
        throws IllegalArgumentException {

        validateLevel(level);

        if (pkcs8Der == null || pkcs8Der.length == 0) {
            throw new IllegalArgumentException(
                "Encoded key data cannot be null or empty");
        }

        validateDer(level, pkcs8Der);

        this.level = level;
        this.encoded = pkcs8Der.clone();
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
     * Validates PKCS#8 DER by importing through wolfCrypt.
     *
     * @param level ML-DSA level to validate against
     * @param der PKCS#8 DER to validate
     *
     * @throws IllegalArgumentException if DER is invalid for the given level
     */
    private static void validateDer(int level, byte[] der)
        throws IllegalArgumentException {

        MlDsa key = null;
        try {
            key = new MlDsa(level);
            key.importPrivateKeyDer(der);

        } catch (WolfCryptException e) {
            throw new IllegalArgumentException(
                "Invalid ML-DSA PKCS#8 DER for level " + level + ": " +
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
     * @return "PKCS#8"
     */
    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    /**
     * Get the PKCS#8 DER encoding of this key.
     *
     * @return PKCS#8 DER byte array, or null if the key has been destroyed
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
     * @return JDK {@code NamedParameterSpec} on JDK 11+, else null
     */
    public AlgorithmParameterSpec getParams() {
        return WolfPQCJdkCompat.namedParameterSpec(this.level);
    }

    /**
     * Get the ML-DSA parameter-set level.
     *
     * @return level value (matches {@link MlDsa#ML_DSA_44} etc.)
     */
    public int getLevel() {
        return this.level;
    }

    /**
     * Destroy this key, zero the encoded buffer and mark destroyed.
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
     * Equality based on encoded key and level.
     *
     * @return true if obj is a WolfCryptMlDsaPrivateKey with the same level and
     *         same encoded key, false otherwise or if destroyed.
     */
    @Override
    public boolean equals(Object obj) {

        if (this == obj) {
            return true;
        }

        if (!(obj instanceof PrivateKey)) {
            return false;
        }

        PrivateKey other = (PrivateKey) obj;

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
     * @return string describing this key, or indicating destroyed state
     */
    @Override
    public String toString() {
        synchronized (stateLock) {
            if (destroyed) {
                return "WolfCryptMlDsaPrivateKey[DESTROYED]";
            }
            return "WolfCryptMlDsaPrivateKey[algorithm=ML-DSA, " +
                "params=" + WolfPQCJdkCompat.levelToParamName(level) +
                ", format=PKCS#8]";
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
