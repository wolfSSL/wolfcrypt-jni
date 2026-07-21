/* WolfCryptSlhDsaPrivateKey.java
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
import java.security.PrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import javax.security.auth.Destroyable;

import com.wolfssl.wolfcrypt.SlhDsa;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfJCE SLH-DSA (FIPS 205) private key.
 *
 * <p>{@link #getAlgorithm()} returns the family name {@code "SLH-DSA"}. The
 * parameter set is exposed via {@link #getParams()}.</p>
 *
 * <p>{@link #getEncoded()} returns PKCS#8 PrivateKeyInfo DER (RFC 9909)
 * generated via wolfCrypt {@code wc_SlhDsaKey_KeyToDer}. The encoded buffer
 * is zeroed on {@link #destroy()}.</p>
 */
public class WolfCryptSlhDsaPrivateKey implements PrivateKey, Destroyable {

    private static final long serialVersionUID = 1L;

    /** PKCS#8 PrivateKeyInfo DER. Zeroed on destroy(). */
    private byte[] encoded = null;

    /** SLH-DSA parameter set, one of {@code SlhDsa.SLH_DSA_*} (0-11). */
    private final int param;

    /** Track if object has been destroyed. */
    private boolean destroyed = false;

    /** Lock around use of destroyed boolean and encoded buffer. */
    private transient Object stateLock = new Object();

    /**
     * Create from PKCS#8 PrivateKeyInfo DER. The parameter set is detected
     * from the AlgorithmIdentifier OID by wolfCrypt.
     *
     * @param pkcs8Der PKCS#8 PrivateKeyInfo DER
     *
     * @throws IllegalArgumentException if DER is malformed, not a
     *         recognized SLH-DSA PKCS#8, or private-key support for it is
     *         not compiled into native wolfSSL
     */
    public WolfCryptSlhDsaPrivateKey(byte[] pkcs8Der)
        throws IllegalArgumentException {

        if (pkcs8Der == null || pkcs8Der.length == 0) {
            throw new IllegalArgumentException(
                "Encoded key data cannot be null or empty");
        }

        try {
            /* Parse PKCS#8 DER to verify correctness and detect param set */
            this.param = SlhDsa.parseAndValidateSlhDsaPrivateKeyDer(pkcs8Der);
        }
        catch (WolfCryptException e) {
            throw decodeFailure(e);
        }

        this.encoded = pkcs8Der.clone();
    }

    /**
     * Create from PKCS#8 PrivateKeyInfo DER with explicit parameter set. The
     * DER is validated by importing through wolfCrypt at construction and the
     * detected parameter set must match {@code param}.
     *
     * @param pkcs8Der PKCS#8 PrivateKeyInfo DER
     * @param param SLH-DSA parameter set, one of {@code SlhDsa.SLH_DSA_*}
     *
     * @throws IllegalArgumentException on invalid param, malformed DER, a
     *         parameter set mismatch, or private-key support not compiled
     *         into native wolfSSL
     */
    public WolfCryptSlhDsaPrivateKey(byte[] pkcs8Der, int param)
        throws IllegalArgumentException {

        int detected;

        validateParam(param);

        if (pkcs8Der == null || pkcs8Der.length == 0) {
            throw new IllegalArgumentException(
                "Encoded key data cannot be null or empty");
        }

        try {
            detected = SlhDsa.parseAndValidateSlhDsaPrivateKeyDer(pkcs8Der);
        }
        catch (WolfCryptException e) {
            throw decodeFailure(e);
        }

        if (detected != param) {
            throw new IllegalArgumentException(
                "SLH-DSA PKCS#8 parameter set " +
                WolfPQCJdkCompat.slhDsaParamToName(detected) +
                " does not match requested " +
                WolfPQCJdkCompat.slhDsaParamToName(param));
        }

        this.param = param;
        this.encoded = pkcs8Der.clone();
    }

    /**
     * Map a PKCS#8 decode failure to an IllegalArgumentException.
     *
     * @param e decode exception from parseAndValidateSlhDsaPrivateKeyDer
     *
     * @return IllegalArgumentException for the caller to throw
     */
    private static IllegalArgumentException decodeFailure(
        WolfCryptException e) {

        if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
            return new IllegalArgumentException(
                "SLH-DSA private-key support or this parameter set is " +
                "not compiled into native wolfSSL", e);
        }

        return new IllegalArgumentException(
            "Not a valid SLH-DSA PKCS#8 DER: " + e.getMessage(), e);
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
     * Equality based on encoded key and parameter set.
     *
     * @return true if obj is a PrivateKey with algorithm "SLH-DSA" and the
     *         same encoded key, false otherwise or if destroyed.
     */
    @Override
    public boolean equals(Object obj) {

        PrivateKey other;
        byte[] otherEncoded;
        String otherAlg;

        if (this == obj) {
            return true;
        }

        if (!(obj instanceof PrivateKey)) {
            return false;
        }

        other = (PrivateKey) obj;
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
     * @return string describing this key, or indicating destroyed state
     */
    @Override
    public String toString() {
        synchronized (stateLock) {
            if (destroyed) {
                return "WolfCryptSlhDsaPrivateKey[DESTROYED]";
            }
            return "WolfCryptSlhDsaPrivateKey[algorithm=SLH-DSA, " +
                "params=" + WolfPQCJdkCompat.slhDsaParamToName(param) +
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
