/* WolfCryptEdDSAPublicKey.java
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
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.security.auth.Destroyable;

/**
 * wolfJCE EdDSA (Ed25519 / Ed448) public key.
 *
 * <p>On JDK 15 and later, keys produced by wolfJCE KeyPairGenerator and
 * KeyFactory are instances of a subclass (shipped in the
 * {@code META-INF/versions/15} layer of the JAR) that also implements
 * {@code java.security.interfaces.EdECPublicKey}, so they can be handed
 * directly to SunEC and other providers. Keys created through the public
 * constructors of this class are plain base instances. Re-create them through
 * the wolfJCE KeyFactory from their encoding to get the JDK 15 variant.</p>
 *
 * <p>getAlgorithm() returns "EdDSA" (SunEC convention). The curve is available
 * from getParams() as a NamedParameterSpec on JDK 11+ and from getCurveName()
 * everywhere. getEncoded() is the RFC 8410 X.509 SubjectPublicKeyInfo with
 * absent AlgorithmIdentifier parameters.</p>
 */
public class WolfCryptEdDSAPublicKey implements PublicKey, Destroyable {

    private static final long serialVersionUID = 1L;

    /** Curve of this key */
    private final WolfCryptEdDSACurve curve;

    /** Raw RFC 8032 public key */
    private byte[] rawPub;

    /** X.509 SubjectPublicKeyInfo DER produced by native wolfCrypt.
     * Transient: rebuilt (and re-validated) on deserialization. */
    private transient byte[] encoded;

    /** Track if object has been destroyed */
    private boolean destroyed = false;

    /** Lock around destroyed flag and raw key. Not final because it is
     * reinitialized after deserialization. */
    private transient Object stateLock = new Object();

    /**
     * Create from a raw public key.
     *
     * @param curve curve
     * @param rawPub raw public key (copied)
     *
     * @throws IllegalArgumentException if the key is not a valid point,
     *         has the wrong length, or the curve is not compiled in
     */
    WolfCryptEdDSAPublicKey(WolfCryptEdDSACurve curve, byte[] rawPub)
        throws IllegalArgumentException {

        if (curve == null) {
            throw new IllegalArgumentException("Curve cannot be null");
        }

        byte[][] r = curve.importPublic(rawPub);
        this.curve = curve;
        this.rawPub = r[0];
        this.encoded = r[1];
    }

    /**
     * Create from a raw public key and its SubjectPublicKeyInfo.
     *
     * @param curve curve
     * @param rawPub raw public key (copied)
     * @param spkiDer SubjectPublicKeyInfo DER from native (copied)
     *
     * @throws IllegalArgumentException if curve, rawPub or spkiDer is null
     *         or rawPub has the wrong length
     */
    WolfCryptEdDSAPublicKey(WolfCryptEdDSACurve curve, byte[] rawPub,
        byte[] spkiDer) throws IllegalArgumentException {

        if (curve == null || rawPub == null || spkiDer == null ||
            rawPub.length != curve.getPublicKeySize()) {
            throw new IllegalArgumentException("Invalid raw public key");
        }

        this.curve = curve;
        this.rawPub = rawPub.clone();
        this.encoded = spkiDer.clone();
    }

    /**
     * Create from an X.509 SubjectPublicKeyInfo DER. Curve is taken from the
     * AlgorithmIdentifier OID.
     *
     * @param spkiDer SubjectPublicKeyInfo DER
     *
     * @throws IllegalArgumentException if the DER is malformed, not an
     *         Ed25519/Ed448 key, or the curve is not compiled in
     */
    public WolfCryptEdDSAPublicKey(byte[] spkiDer)
        throws IllegalArgumentException {

        WolfCryptEdDSACurve found = null;
        byte[][] r = null;
        IllegalArgumentException first = null;

        if (spkiDer == null || spkiDer.length == 0) {
            throw new IllegalArgumentException(
                "Encoded key data cannot be null or empty");
        }

        /* Remove NULL AlgorithmIdentifier (JDK re-encoding) if present */
        spkiDer = WolfCryptSpkiUtil.stripNullAlgIdParams(spkiDer);

        for (WolfCryptEdDSACurve c : WolfCryptEdDSACurve.values()) {
            if (!c.isEnabled()) {
                continue;
            }
            try {
                r = c.decodeSpki(spkiDer);
                found = c;
                break;
            }
            catch (IllegalArgumentException e) {
                if (first == null) {
                    first = e;
                }
                else {
                    /* keep the other curve's failure visible too */
                    first.addSuppressed(e);
                }
            }
        }

        if (found == null) {
            if (first == null) {
                throw new IllegalArgumentException(
                    "Ed25519 and Ed448 are not compiled into native wolfSSL");
            }
            throw new IllegalArgumentException(
                "Not a valid Ed25519 or Ed448 SubjectPublicKeyInfo", first);
        }

        this.rawPub = r[0];
        this.encoded = r[1];
        this.curve = found;
    }

    /**
     * Create from a curve name and raw RFC 8032 public key.
     *
     * @param curveName "Ed25519" or "Ed448"
     * @param rawPublicKey raw public key (32 or 57 bytes)
     *
     * @throws IllegalArgumentException if the curve name is unknown, the key
     *         is not a valid point, or the curve is not compiled in
     */
    public WolfCryptEdDSAPublicKey(String curveName, byte[] rawPublicKey)
        throws IllegalArgumentException {

        this(requireCurve(curveName), rawPublicKey);
    }

    /**
     * Resolve a curve name, throwing when it is not Ed25519 or Ed448.
     *
     * @param curveName curve name
     *
     * @return curve
     *
     * @throws IllegalArgumentException on an unknown name
     */
    static WolfCryptEdDSACurve requireCurve(String curveName)
        throws IllegalArgumentException {

        WolfCryptEdDSACurve c = WolfCryptEdDSACurve.fromName(curveName);
        if (c == null) {
            throw new IllegalArgumentException(
                "Unknown EdDSA curve: " + curveName);
        }
        return c;
    }

    /**
     * Get the curve of this key.
     *
     * @return the curve of this key
     */
    WolfCryptEdDSACurve curve() {
        return this.curve;
    }

    /**
     * Get the standard algorithm name for this key.
     *
     * @return "EdDSA"
     */
    @Override
    public String getAlgorithm() {
        return WolfCryptEdDSACurve.ALGORITHM_NAME;
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
     * @return SubjectPublicKeyInfo DER, or null if the key has been destroyed
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
     * Get the curve parameters of this key.
     *
     * @return {@code NamedParameterSpec} for {@code "Ed25519"} or
     *         {@code "Ed448"} on JDK 11+, null on JDK 8-10
     */
    public AlgorithmParameterSpec getParams() {
        return WolfEdECJdkCompat.namedParameterSpec(curve);
    }

    /**
     * Get the curve name of this key.
     *
     * @return "Ed25519" or "Ed448"
     */
    public String getCurveName() {
        return curve.getJcaName();
    }

    /**
     * Get the raw RFC 8032 public key: the little-endian y coordinate with the
     * x parity in the top bit of the last byte.
     *
     * @return a copy of the raw public key, or null if destroyed
     */
    public byte[] getRawPublicKey() {
        synchronized (stateLock) {
            if (destroyed) {
                return null;
            }
            return rawPub.clone();
        }
    }

    /**
     * Destroy this key: zero the raw key and mark as destroyed.
     */
    @Override
    public void destroy() {
        synchronized (stateLock) {
            if (!destroyed) {
                WolfCryptEdDSACurve.zero(rawPub);
                WolfCryptEdDSACurve.zero(encoded);
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
     * Hash code over the canonical SubjectPublicKeyInfo encoding, which
     * matches keys from other providers and agrees with equals().
     *
     * @return hash code, or 0 if destroyed
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
     * Test Equality, another wolfJCE EdDSA public key with the same curve and
     * raw key, or any other {@link PublicKey} whose X.509 encoding is
     * identical.
     *
     * @return true if equal, false otherwise or if destroyed
     */
    @Override
    public boolean equals(Object obj) {

        if (this == obj) {
            return true;
        }

        if (!(obj instanceof PublicKey)) {
            return false;
        }

        if (obj instanceof WolfCryptEdDSAPublicKey) {
            WolfCryptEdDSAPublicKey o = (WolfCryptEdDSAPublicKey) obj;
            byte[] otherRaw = o.getRawPublicKey();
            byte[] otherEncoded = o.getEncoded();
            synchronized (stateLock) {
                /* the encoding is derived from the raw key, comparing it
                 * too keeps equals() and hashCode() consistent */
                return !destroyed && otherRaw != null &&
                    otherEncoded != null && curve == o.curve &&
                    MessageDigest.isEqual(rawPub, otherRaw) &&
                    MessageDigest.isEqual(encoded, otherEncoded);
            }
        }

        PublicKey other = (PublicKey) obj;
        if (!"X.509".equalsIgnoreCase(other.getFormat())) {
            return false;
        }

        byte[] otherEncoded = other.getEncoded();
        byte[] thisEncoded = getEncoded();

        return thisEncoded != null && otherEncoded != null &&
            MessageDigest.isEqual(thisEncoded, otherEncoded);
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
                return getClass().getSimpleName() + "[DESTROYED]";
            }
            return getClass().getSimpleName() + "[algorithm=EdDSA, curve=" +
                curve.getJcaName() + ", format=X.509]";
        }
    }

    /**
     * Re-create the key through the key factory after deserialization, so
     * a JDK 15+ runtime gets the overlay class even though the stream only
     * carries this base class.
     *
     * @return the resolved key
     */
    Object readResolve() {
        synchronized (stateLock) {
            if (destroyed) {
                WolfCryptEdDSAPublicKey gone = WolfCryptEdDSAKeys
                    .trustedPublicKey(curve, new byte[curve.getPublicKeySize()],
                        new byte[0]);
                gone.destroy();
                return gone;
            }
            return WolfCryptEdDSAKeys.trustedPublicKey(curve, rawPub, encoded);
        }
    }

    /**
     * Custom deserialization. Reinitialize transient state and re-validate
     * the raw key through native wolfCrypt.
     *
     * @param in ObjectInputStream to read from
     *
     * @throws IOException if an I/O error occurs or the key is invalid
     * @throws ClassNotFoundException if a class cannot be found
     */
    private void readObject(ObjectInputStream in)
        throws IOException, ClassNotFoundException {

        in.defaultReadObject();
        stateLock = new Object();

        if (curve == null || rawPub == null) {
            throw new InvalidObjectException("Missing EdDSA key data");
        }

        if (!destroyed) {
            try {
                /* re-validates the point and rebuilds the transient DER */
                encoded = curve.importPublic(rawPub)[1];
            }
            catch (IllegalArgumentException e) {
                InvalidObjectException ioe = new InvalidObjectException(
                    "Invalid EdDSA public key: " + e.getMessage());
                ioe.initCause(e);
                throw ioe;
            }
        }
        else {
            encoded = new byte[0];
        }
    }
}
