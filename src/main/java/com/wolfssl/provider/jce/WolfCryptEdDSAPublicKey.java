/* WolfCryptEdDSAPublicKey.java
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
import java.math.BigInteger;
import java.util.Arrays;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.NamedParameterSpec;
import javax.security.auth.Destroyable;

/**
 * wolfJCE EdECPublicKey implementation for Ed25519.
 *
 * Stores the 32-byte compressed public key (RFC 8032 encoding) and a
 * DER-encoded SubjectPublicKeyInfo form using OID 1.3.101.112 (id-Ed25519).
 */
public class WolfCryptEdDSAPublicKey implements EdECPublicKey, Destroyable {

    private static final long serialVersionUID = 1L;

    /** Raw 32-byte Ed25519 public key (RFC 8032 compressed encoding). */
    private byte[] rawKey = null;

    /** DER SubjectPublicKeyInfo encoded form. */
    private byte[] spkiEncoded = null;

    /** Whether this key has been destroyed. */
    private boolean destroyed = false;

    /** Lock around state. */
    private transient Object stateLock = new Object();

    /*
     * SPKI DER prefix for Ed25519 public key (12 bytes).
     * Full encoding: prefix (12 bytes) + 32-byte public key = 44 bytes total.
     *
     *   30 2a              SEQUENCE, 42 bytes
     *     30 05            SEQUENCE, 5 bytes (AlgorithmIdentifier)
     *       06 03 2b 65 70 OID 1.3.101.112 (id-Ed25519)
     *     03 21            BIT STRING, 33 bytes
     *       00             0 unused bits
     */
    private static final byte[] SPKI_PREFIX = {
        0x30, 0x2a,
        0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x70,
        0x03, 0x21,
        0x00
    };

    private static final int SPKI_TOTAL_LEN = SPKI_PREFIX.length + 32; /* 44 */

    /**
     * Create WolfCryptEdDSAPublicKey from raw 32-byte Ed25519 public key.
     *
     * @param rawKey 32-byte Ed25519 compressed public key (RFC 8032 encoding)
     * @throws IllegalArgumentException if rawKey is null or not 32 bytes
     */
    public WolfCryptEdDSAPublicKey(byte[] rawKey) {
        if (rawKey == null || rawKey.length != 32) {
            throw new IllegalArgumentException(
                "Ed25519 public key must be exactly 32 bytes");
        }
        this.rawKey = rawKey.clone();
        this.spkiEncoded = buildSpki(this.rawKey);
    }

    /**
     * Create WolfCryptEdDSAPublicKey from DER-encoded SubjectPublicKeyInfo.
     *
     * @param spkiDer DER-encoded SPKI public key (44 bytes)
     * @throws IllegalArgumentException if the DER data is invalid
     */
    public WolfCryptEdDSAPublicKey(byte[] spkiDer, boolean isSpki) {
        if (spkiDer == null) {
            throw new IllegalArgumentException("SPKI DER cannot be null");
        }
        this.rawKey = extractRawFromSpki(spkiDer);
        this.spkiEncoded = spkiDer.clone();
    }

    /**
     * Create WolfCryptEdDSAPublicKey from an EdECPoint and NamedParameterSpec.
     *
     * @param spec must be NamedParameterSpec.ED25519
     * @param point EdECPoint encoding the public key
     * @throws IllegalArgumentException if spec is not Ed25519 or point is null
     */
    public WolfCryptEdDSAPublicKey(NamedParameterSpec spec, EdECPoint point) {
        if (spec == null || !spec.getName().equalsIgnoreCase("Ed25519")) {
            throw new IllegalArgumentException(
                "Only Ed25519 is supported");
        }
        if (point == null) {
            throw new IllegalArgumentException("EdECPoint cannot be null");
        }
        this.rawKey = edECPointToBytes(point);
        this.spkiEncoded = buildSpki(this.rawKey);
    }

    /** Build SPKI DER from 32-byte raw public key. */
    static byte[] buildSpki(byte[] rawKey) {
        byte[] out = new byte[SPKI_TOTAL_LEN];
        System.arraycopy(SPKI_PREFIX, 0, out, 0, SPKI_PREFIX.length);
        System.arraycopy(rawKey, 0, out, SPKI_PREFIX.length, 32);
        return out;
    }

    /** Extract 32-byte raw public key from SPKI DER, validating structure. */
    static byte[] extractRawFromSpki(byte[] der) {
        if (der.length != SPKI_TOTAL_LEN) {
            throw new IllegalArgumentException(
                "Invalid Ed25519 SPKI DER: expected " + SPKI_TOTAL_LEN +
                " bytes, got " + der.length);
        }
        for (int i = 0; i < SPKI_PREFIX.length; i++) {
            if (der[i] != SPKI_PREFIX[i]) {
                throw new IllegalArgumentException(
                    "Invalid Ed25519 SPKI DER structure at byte " + i);
            }
        }
        byte[] out = new byte[32];
        System.arraycopy(der, SPKI_PREFIX.length, out, 0, 32);
        return out;
    }

    /**
     * Convert an EdECPoint to a 32-byte RFC 8032 compressed Ed25519 encoding.
     * The y-coordinate is stored in little-endian order; the MSB of the last
     * byte encodes the parity (odd/even) of the x-coordinate.
     */
    static byte[] edECPointToBytes(EdECPoint point) {
        BigInteger y = point.getY();
        boolean xOdd = point.isXOdd();

        /* Convert y (big-endian BigInteger) to 32-byte little-endian */
        byte[] yBytes = y.toByteArray();
        /* strip possible leading sign byte */
        if (yBytes.length > 0 && yBytes[0] == 0x00) {
            byte[] trimmed = new byte[yBytes.length - 1];
            System.arraycopy(yBytes, 1, trimmed, 0, trimmed.length);
            yBytes = trimmed;
        }

        byte[] raw = new byte[32];
        /* copy big-endian bytes into raw, right-aligned */
        int srcStart = Math.max(0, yBytes.length - 32);
        int copyLen  = Math.min(yBytes.length, 32);
        int dstStart = 32 - copyLen;
        System.arraycopy(yBytes, srcStart, raw, dstStart, copyLen);

        /* reverse to little-endian */
        byte[] le = new byte[32];
        for (int i = 0; i < 32; i++) {
            le[i] = raw[31 - i];
        }

        /* encode x-parity in MSB of last byte */
        if (xOdd) {
            le[31] = (byte) (le[31] | 0x80);
        } else {
            le[31] = (byte) (le[31] & 0x7f);
        }

        return le;
    }

    /**
     * Decode the 32-byte RFC 8032 compressed Ed25519 public key to EdECPoint.
     * The point y-coordinate is little-endian in bytes 0..31, with the sign
     * of x encoded in the MSB of byte 31.
     */
    private EdECPoint bytesToEdECPoint(byte[] raw) {
        boolean xOdd = (raw[31] & 0x80) != 0;

        /* mask out sign bit to isolate y value */
        byte[] yLE = raw.clone();
        yLE[31] = (byte) (yLE[31] & 0x7f);

        /* convert little-endian to big-endian for BigInteger */
        byte[] yBE = new byte[32];
        for (int i = 0; i < 32; i++) {
            yBE[i] = yLE[31 - i];
        }

        BigInteger y = new BigInteger(1, yBE);
        return new EdECPoint(xOdd, y);
    }

    /**
     * Return the package-private raw 32-byte public key for use by wolfJCE
     * components (e.g. WolfCryptEdDSASignature).
     *
     * @return cloned 32-byte raw public key, or null if destroyed
     */
    byte[] getRawPublicKey() {
        synchronized (stateLock) {
            if (destroyed) {
                return null;
            }
            return rawKey.clone();
        }
    }

    @Override
    public EdECPoint getPoint() {
        synchronized (stateLock) {
            if (destroyed) {
                throw new IllegalStateException("Key has been destroyed");
            }
            return bytesToEdECPoint(rawKey);
        }
    }

    @Override
    public NamedParameterSpec getParams() {
        return NamedParameterSpec.ED25519;
    }

    @Override
    public String getAlgorithm() {
        return "EdDSA";
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        synchronized (stateLock) {
            if (destroyed) {
                return null;
            }
            return spkiEncoded.clone();
        }
    }

    @Override
    public void destroy() {
        synchronized (stateLock) {
            if (!destroyed) {
                if (rawKey != null) {
                    Arrays.fill(rawKey, (byte) 0);
                    rawKey = null;
                }
                if (spkiEncoded != null) {
                    Arrays.fill(spkiEncoded, (byte) 0);
                    spkiEncoded = null;
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
            return Arrays.hashCode(spkiEncoded);
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof WolfCryptEdDSAPublicKey)) {
            return false;
        }
        WolfCryptEdDSAPublicKey other = (WolfCryptEdDSAPublicKey) obj;

        /* Snapshot each key's encoded form under its own lock to avoid
         * ABBA deadlock. */
        byte[] thisEncoded;
        byte[] otherEncoded;

        synchronized (stateLock) {
            if (destroyed) {
                return false;
            }
            thisEncoded = spkiEncoded.clone();
        }
        synchronized (other.stateLock) {
            if (other.destroyed) {
                return false;
            }
            otherEncoded = other.spkiEncoded.clone();
        }
        return Arrays.equals(thisEncoded, otherEncoded);
    }

    @Override
    public String toString() {
        synchronized (stateLock) {
            if (destroyed) {
                return "WolfCryptEdDSAPublicKey[DESTROYED]";
            }
            return "WolfCryptEdDSAPublicKey[algorithm=EdDSA, format=X.509]";
        }
    }

    private void readObject(ObjectInputStream in)
        throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        stateLock = new Object();
        if (!destroyed) {
            if (rawKey == null || rawKey.length != 32 ||
                spkiEncoded == null ||
                spkiEncoded.length != SPKI_TOTAL_LEN) {
                throw new InvalidObjectException(
                    "Invalid deserialized Ed25519 public key state");
            }
            if (!Arrays.equals(
                    Arrays.copyOf(spkiEncoded, SPKI_PREFIX.length),
                    SPKI_PREFIX)) {
                throw new InvalidObjectException(
                    "SPKI prefix invalid in deserialized Ed25519 public key");
            }
            if (!Arrays.equals(
                    Arrays.copyOfRange(spkiEncoded,
                        SPKI_PREFIX.length, SPKI_TOTAL_LEN),
                    rawKey)) {
                throw new InvalidObjectException(
                    "SPKI encoding inconsistent with rawKey in " +
                    "deserialized Ed25519 public key");
            }
        }
    }
}
