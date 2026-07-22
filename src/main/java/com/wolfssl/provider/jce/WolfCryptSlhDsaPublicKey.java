/* WolfCryptSlhDsaPublicKey.java
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
import java.security.spec.AlgorithmParameterSpec;
import javax.security.auth.Destroyable;

import com.wolfssl.wolfcrypt.SlhDsa;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfJCE SLH-DSA (FIPS 205) public key.
 *
 * <p>{@link #getAlgorithm()} returns the family name {@code "SLH-DSA"}. The
 * parameter set is exposed via {@link #getParams()}.</p>
 *
 * <p>{@link #getEncoded()} returns the X.509 SubjectPublicKeyInfo DER
 * (RFC 9909) generated via wolfCrypt {@code wc_SlhDsaKey_PublicKeyToDer}.</p>
 */
public class WolfCryptSlhDsaPublicKey implements PublicKey, Destroyable {

    private static final long serialVersionUID = 1L;

    /** X.509 SubjectPublicKeyInfo DER. */
    private byte[] encoded = null;

    /** SLH-DSA parameter set, one of {@code SlhDsa.SLH_DSA_*} (0-11). */
    private final int param;

    /** Track if object has been destroyed. */
    private boolean destroyed = false;

    /** Lock around use of destroyed boolean and encoded buffer. Cannot be
     * final because it is reinitialized after deserialization. */
    private transient Object stateLock = new Object();

    /**
     * Create from X.509 SubjectPublicKeyInfo DER. The parameter set is
     * detected from the AlgorithmIdentifier OID by wolfCrypt.
     *
     * @param x509Der X.509 SubjectPublicKeyInfo DER
     *
     * @throws IllegalArgumentException if DER is malformed, not a
     *         recognized SLH-DSA SPKI, or its parameter set is not
     *         compiled into native wolfSSL
     */
    public WolfCryptSlhDsaPublicKey(byte[] x509Der)
        throws IllegalArgumentException {

        if (x509Der == null || x509Der.length == 0) {
            throw new IllegalArgumentException(
                "Encoded key data cannot be null or empty");
        }

        /* Remove NULL AlgorithmIdentifier (JDK re-encoding) if present */
        x509Der = WolfCryptSpkiUtil.stripNullAlgIdParams(x509Der);

        try {
            this.param = SlhDsa.parseAndValidateSlhDsaPublicKeyDer(x509Der);
        }
        catch (WolfCryptException e) {
            throw decodeFailure(e);
        }

        this.encoded = x509Der.clone();
    }

    /**
     * Create from X.509 SubjectPublicKeyInfo DER with explicit parameter set.
     * The DER is validated by importing through wolfCrypt at construction and
     * the detected parameter set must match {@code param}.
     *
     * @param x509Der X.509 SubjectPublicKeyInfo DER
     * @param param SLH-DSA parameter set, one of {@code SlhDsa.SLH_DSA_*}
     *
     * @throws IllegalArgumentException if param is invalid, DER is malformed,
     *         its parameter set does not match {@code param}, or its
     *         parameter set is not compiled into native wolfSSL.
     */
    public WolfCryptSlhDsaPublicKey(byte[] x509Der, int param)
        throws IllegalArgumentException {

        int detected;

        validateParam(param);

        if (x509Der == null || x509Der.length == 0) {
            throw new IllegalArgumentException(
                "Encoded key data cannot be null or empty");
        }

        /* Remove NULL AlgorithmIdentifier (JDK re-encoding) if present */
        x509Der = WolfCryptSpkiUtil.stripNullAlgIdParams(x509Der);

        try {
            detected = SlhDsa.parseAndValidateSlhDsaPublicKeyDer(x509Der);
        }
        catch (WolfCryptException e) {
            throw decodeFailure(e);
        }

        if (detected != param) {
            throw new IllegalArgumentException(
                "SLH-DSA SPKI parameter set " +
                WolfPQCJdkCompat.slhDsaParamToName(detected) +
                " does not match requested " +
                WolfPQCJdkCompat.slhDsaParamToName(param));
        }

        this.param = param;
        this.encoded = x509Der.clone();
    }

    /**
     * Map an SPKI decode failure to an IllegalArgumentException.
     *
     * @param e decode exception from parseAndValidateSlhDsaPublicKeyDer
     *
     * @return IllegalArgumentException for the caller to throw
     */
    private static IllegalArgumentException decodeFailure(
        WolfCryptException e) {

        if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
            return new IllegalArgumentException(
                "SLH-DSA parameter set is not compiled into native wolfSSL", e);
        }

        return new IllegalArgumentException(
            "Not a valid SLH-DSA X.509 SPKI DER: " + e.getMessage(), e);
    }

    /**
     * Validates SLH-DSA parameter set.
     *
     * @param param SLH-DSA parameter set to validate
     *
     * @throws IllegalArgumentException if param is not in range 0-11
     */
    private static void validateParam(int param)
        throws IllegalArgumentException {

        if (param < SlhDsa.SLH_DSA_SHAKE_128S ||
            param > SlhDsa.SLH_DSA_SHA2_256F) {

            throw new IllegalArgumentException(
                "Invalid SLH-DSA parameter set: " + param);
        }
    }

    /**
     * Get the standard algorithm name for this key.
     *
     * @return "SLH-DSA"
     */
    @Override
    public String getAlgorithm() {
        return "SLH-DSA";
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
     * @return JDK {@code NamedParameterSpec} on JDK 11+, else null
     */
    public AlgorithmParameterSpec getParams() {
        return WolfPQCJdkCompat.slhDsaNamedParameterSpec(this.param);
    }

    /**
     * Get the SLH-DSA parameter set.
     *
     * @return parameter set value, one of {@code SlhDsa.SLH_DSA_*} (0-11)
     */
    public int getParam() {
        return this.param;
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
     * Hash code based on encoded key and parameter set.
     *
     * @return hash code, or 0 if destroyed
     */
    @Override
    public int hashCode() {
        synchronized (stateLock) {
            if (destroyed) {
                return 0;
            }
            return Arrays.hashCode(encoded) ^ param;
        }
    }

    /**
     * Equality based on algorithm and encoded key. The SLH-DSA parameter
     * set is carried in the X.509 SPKI AlgorithmIdentifier OID, so byte
     * equality of the encoded form also implies the same parameter set.
     *
     * @return true if obj is a PublicKey with algorithm "SLH-DSA" and the
     *         same X.509 SPKI encoding, false otherwise or if destroyed.
     */
    @Override
    public boolean equals(Object obj) {

        PublicKey other;
        byte[] otherEncoded;
        String otherAlg;

        if (this == obj) {
            return true;
        }

        if (!(obj instanceof PublicKey)) {
            return false;
        }

        other = (PublicKey) obj;
        otherEncoded = other.getEncoded();
        otherAlg = other.getAlgorithm();

        synchronized (stateLock) {
            if (destroyed) {
                return false;
            }
            return otherEncoded != null &&
                "SLH-DSA".equals(otherAlg) &&
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
                return "WolfCryptSlhDsaPublicKey[DESTROYED]";
            }
            return "WolfCryptSlhDsaPublicKey[algorithm=SLH-DSA, " +
                "params=" + WolfPQCJdkCompat.slhDsaParamToName(param) +
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
