/* WolfCryptEdDSAPrivateKey.java
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
import java.security.PrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Optional;
import javax.security.auth.Destroyable;

/**
 * wolfJCE EdDSA (Ed25519 / Ed448) private key.
 *
 * On JDK 15 and later, keys produced by wolfJCE KeyPairGenerator and
 * KeyFactory are instances of a subclass (shipped in the META-INF/versions/15
 * layer of the JAR) that also implements
 * java.security.interfaces.EdECPrivateKey, so they can be handed directly to
 * SunEC and other providers. Keys created through the public constructors of
 * this class are plain base instances. Re-create them through the wolfJCE
 * KeyFactory from their encoding to get the JDK 15 variant.
 *
 * The key holds the raw private key and the matching raw public key (derived
 * at construction when not supplied). getEncoded() is the RFC 8410 PKCS#8 v1
 * form: private key only, no public key.
 *
 * <p>Java serialization writes the raw private key unprotected. Persist
 * keys through {@code getEncoded()} inside an encrypted container.</p>
 */
public class WolfCryptEdDSAPrivateKey implements PrivateKey, Destroyable {

    private static final long serialVersionUID = 1L;

    /** Curve of this key */
    private final WolfCryptEdDSACurve curve;

    /** Raw private key (32 or 57 bytes) */
    private byte[] rawPriv;

    /** Raw public key matching rawPriv (32 or 57 bytes) */
    private byte[] rawPub;

    /** PKCS#8 v1 DER produced by native wolfCrypt */
    private transient byte[] encoded;

    /** Track if object has been destroyed */
    private boolean destroyed = false;

    /** Lock around destroyed flag and raw keys */
    private transient Object stateLock = new Object();

    /**
     * Create from a raw private key.
     *
     * @param curve curve
     * @param rawPriv raw private key (copied)
     *
     * @throws IllegalArgumentException if the key has the wrong length or
     *         the curve is not compiled in
     */
    WolfCryptEdDSAPrivateKey(WolfCryptEdDSACurve curve, byte[] rawPriv)
        throws IllegalArgumentException {

        if (curve == null) {
            throw new IllegalArgumentException("Curve cannot be null");
        }

        byte[][] r = curve.importPrivate(rawPriv);
        this.rawPriv = r[0];
        this.rawPub  = r[1];
        this.encoded = r[2];
        this.curve = curve;
    }

    /**
     * Create from a raw key pair and its PKCS#8 encoding.
     *
     * @param curve curve
     * @param rawPriv raw private key (copied)
     * @param rawPub raw public key (copied)
     * @param pkcs8Der PKCS#8 v1 DER from native (copied)
     *
     * @throws IllegalArgumentException on wrong lengths
     */
    WolfCryptEdDSAPrivateKey(WolfCryptEdDSACurve curve, byte[] rawPriv,
        byte[] rawPub, byte[] pkcs8Der) throws IllegalArgumentException {

        if (curve == null || rawPriv == null || rawPub == null ||
            pkcs8Der == null || rawPriv.length != curve.getPrivateKeySize() ||
            rawPub.length != curve.getPublicKeySize()) {
            throw new IllegalArgumentException("Invalid raw key pair");
        }

        this.curve = curve;
        this.rawPriv = rawPriv.clone();
        this.rawPub = rawPub.clone();
        this.encoded = pkcs8Der.clone();
    }

    /**
     * Create from a PKCS#8 DER (v1 private-only or v2 with public key).
     *
     * @param pkcs8Der PKCS#8 PrivateKeyInfo / OneAsymmetricKey DER
     *
     * @throws IllegalArgumentException if the DER is malformed, not an
     *         Ed25519/Ed448 key, or the curve is not compiled in
     */
    public WolfCryptEdDSAPrivateKey(byte[] pkcs8Der)
        throws IllegalArgumentException {

        if (pkcs8Der == null || pkcs8Der.length == 0) {
            throw new IllegalArgumentException(
                "Encoded key data cannot be null or empty");
        }

        WolfCryptEdDSACurve found = WolfCryptEdDSACurve.fromPkcs8Der(pkcs8Der);
        byte[][] r = null;
        IllegalArgumentException first = null;

        if (found != null && !found.isEnabled()) {
            throw new IllegalArgumentException(found.getJcaName() +
                " not compiled into native wolfSSL");
        }

        if (found != null) {
            r = found.decodePkcs8(pkcs8Der);
        }
        else {
            /* Could not identify envelope (PKCS#8 not compiled in, or a form
             * we can't parse). Try each compiled-in curve's native decoder */
            for (WolfCryptEdDSACurve c : WolfCryptEdDSACurve.values()) {
                if (!c.isEnabled()) {
                    continue;
                }
                try {
                    r = c.decodePkcs8(pkcs8Der);
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
                        "Ed25519/Ed448 are not compiled into wolfSSL");
                }
                throw new IllegalArgumentException(
                    "Not a valid Ed25519 or Ed448 PKCS#8 key", first);
            }
        }
        this.rawPriv = r[0];
        this.rawPub = r[1];
        this.encoded = r[2];
        this.curve = found;
    }

    /**
     * Create from a curve name and raw private key.
     *
     * @param curveName "Ed25519" or "Ed448"
     * @param rawPrivateKey raw private key (32 or 57 bytes)
     *
     * @throws IllegalArgumentException if the curve name is unknown, the
     *         key has the wrong length, or the curve is not compiled in
     */
    public WolfCryptEdDSAPrivateKey(String curveName, byte[] rawPrivateKey)
        throws IllegalArgumentException {

        this(WolfCryptEdDSAPublicKey.requireCurve(curveName), rawPrivateKey);
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
     * @return "PKCS#8"
     */
    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    /**
     * Get the PKCS#8 v1 DER encoding of this key (private key only).
     *
     * @return PKCS#8 DER, or null if the key has been destroyed
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
     * @return NamedParameterSpec for "Ed25519" or "Ed448" on JDK 11+, null on
     *         JDK 8-10
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
     * Get the raw private key.
     *
     * @return a copy of the raw private key, or null if destroyed
     */
    public byte[] getRawPrivateKey() {

        synchronized (stateLock) {
            if (destroyed) {
                return null;
            }
            return rawPriv.clone();
        }
    }

    /**
     * Get the raw RFC 8032 public key matching this private key.
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
     * Get the raw private key, with the signature of
     * java.security.interfaces.EdECPrivateKey.getBytes().
     *
     * @return the raw private key, or empty if destroyed
     */
    public Optional<byte[]> getBytes() {
        byte[] b = getRawPrivateKey();
        return (b == null) ? Optional.<byte[]>empty() : Optional.of(b);
    }

    /**
     * Destroy key, zero the raw keys and mark as destroyed.
     */
    @Override
    public void destroy() {
        synchronized (stateLock) {
            if (!destroyed) {
                WolfCryptEdDSACurve.zero(rawPriv);
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
     * Hash code over the canonical PKCS#8 encoding, which matches keys from
     * other providers and agrees with equals().
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
     * To consider equal, another wolfJCE EdDSA private key must have the same
     * curve and raw private key, or any other PrivateKey whose PKCS#8 encoding
     * is identical.
     *
     * @return true if equal, false otherwise or if destroyed
     */
    @Override
    public boolean equals(Object obj) {

        if (this == obj) {
            return true;
        }

        if (!(obj instanceof PrivateKey)) {
            return false;
        }

        if (obj instanceof WolfCryptEdDSAPrivateKey) {
            WolfCryptEdDSAPrivateKey o = (WolfCryptEdDSAPrivateKey) obj;
            byte[] otherRaw = o.getRawPrivateKey();
            byte[] otherEncoded = o.getEncoded();
            try {
                synchronized (stateLock) {
                    /* the encoding is derived from the raw key, comparing
                     * it too keeps equals() and hashCode() consistent */
                    return !destroyed && otherRaw != null &&
                        otherEncoded != null && curve == o.curve &&
                        MessageDigest.isEqual(rawPriv, otherRaw) &&
                        MessageDigest.isEqual(encoded, otherEncoded);
                }
            }
            finally {
                WolfCryptEdDSACurve.zero(otherRaw);
                WolfCryptEdDSACurve.zero(otherEncoded);
            }
        }

        PrivateKey other = (PrivateKey) obj;
        if (!"PKCS#8".equalsIgnoreCase(other.getFormat())) {
            return false;
        }
        byte[] otherEncoded = other.getEncoded();
        byte[] thisEncoded = getEncoded();
        try {
            return thisEncoded != null && otherEncoded != null &&
                MessageDigest.isEqual(thisEncoded, otherEncoded);
        }
        finally {
            /* otherEncoded belongs to the other key and is left alone */
            WolfCryptEdDSACurve.zero(thisEncoded);
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
                return getClass().getSimpleName() + "[DESTROYED]";
            }
            return getClass().getSimpleName() + "[algorithm=EdDSA, curve=" +
                curve.getJcaName() + ", format=PKCS#8]";
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
                /* keep the overlay class for a destroyed key too */
                WolfCryptEdDSAPrivateKey gone =
                    WolfCryptEdDSAKeys.trustedPrivateKey(curve,
                        new byte[curve.getPrivateKeySize()],
                        new byte[curve.getPublicKeySize()], new byte[0]);
                gone.destroy();
                return gone;
            }
            WolfCryptEdDSAPrivateKey resolved =
                WolfCryptEdDSAKeys.trustedPrivateKey(curve, rawPriv, rawPub,
                    encoded);
            /* stream discards this instance, drop its copy of the secret */
            WolfCryptEdDSACurve.zero(rawPriv);
            WolfCryptEdDSACurve.zero(rawPub);
            WolfCryptEdDSACurve.zero(encoded);
            destroyed = true;
            return resolved;
        }
    }

    /**
     * Deserialization: reinitialize transient state, re-validate key pair.
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

        if (curve == null || rawPriv == null || rawPub == null) {
            throw new InvalidObjectException("Missing EdDSA key data");
        }

        if (!destroyed) {
            byte[][] r = null;
            try {
                /* Re-derive public key, rebuilds transient DER */
                r = curve.importPrivate(rawPriv);
                if (!MessageDigest.isEqual(r[1], rawPub)) {
                    WolfCryptEdDSACurve.zero(r[2]);
                    WolfCryptEdDSACurve.zero(rawPriv);
                    throw new InvalidObjectException(
                        "EdDSA public key does not match private key");
                }
                encoded = r[2];
            }
            catch (IllegalArgumentException e) {
                WolfCryptEdDSACurve.zero(rawPriv);
                InvalidObjectException ioe = new InvalidObjectException(
                    "Invalid EdDSA private key: " + e.getMessage());
                ioe.initCause(e);
                throw ioe;
            }
            finally {
                if (r != null) {
                    WolfCryptEdDSACurve.zero(r[0]);
                    WolfCryptEdDSACurve.zero(r[1]);
                }
            }
        }
        else {
            encoded = new byte[0];
        }
    }
}
