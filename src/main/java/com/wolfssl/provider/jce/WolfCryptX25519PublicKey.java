/* WolfCryptX25519PublicKey.java
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
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import javax.security.auth.Destroyable;

/**
 * wolfJCE XECPublicKey implementation for X25519 (XDH key agreement).
 *
 * Stores the 32-byte public key (u-coordinate, little-endian per RFC 7748)
 * and a DER-encoded SubjectPublicKeyInfo form using OID 1.3.101.110 (id-X25519).
 */
public class WolfCryptX25519PublicKey implements XECPublicKey, Destroyable {

    private static final long serialVersionUID = 1L;

    /** Raw 32-byte X25519 public key (u-coordinate, little-endian). */
    private byte[] rawKey = null;

    /** DER SubjectPublicKeyInfo encoded form. */
    private byte[] spkiEncoded = null;

    /** Whether this key has been destroyed. */
    private boolean destroyed = false;

    /** Lock around state. */
    private transient Object stateLock = new Object();

    /*
     * SPKI DER prefix for X25519 public key (12 bytes).
     * Full encoding: prefix (12 bytes) + 32-byte public key = 44 bytes total.
     *
     *   30 2a              SEQUENCE, 42 bytes
     *     30 05            SEQUENCE, 5 bytes (AlgorithmIdentifier)
     *       06 03 2b 65 6e OID 1.3.101.110 (id-X25519)
     *     03 21            BIT STRING, 33 bytes
     *       00             0 unused bits
     */
    private static final byte[] SPKI_PREFIX = {
        0x30, 0x2a,
        0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x6e,
        0x03, 0x21,
        0x00
    };

    private static final int SPKI_TOTAL_LEN = SPKI_PREFIX.length + 32; /* 44 */

    /**
     * Create WolfCryptX25519PublicKey from raw 32-byte X25519 public key.
     *
     * @param rawKey 32-byte X25519 public key (little-endian u-coordinate)
     * @throws IllegalArgumentException if rawKey is null or not 32 bytes
     */
    public WolfCryptX25519PublicKey(byte[] rawKey) {
        if (rawKey == null || rawKey.length != 32) {
            throw new IllegalArgumentException(
                "X25519 public key must be exactly 32 bytes");
        }
        this.rawKey = rawKey.clone();
        this.spkiEncoded = buildSpki(this.rawKey);
    }

    /**
     * Create WolfCryptX25519PublicKey from DER-encoded SubjectPublicKeyInfo.
     *
     * @param spkiDer DER-encoded SPKI public key (44 bytes)
     * @throws IllegalArgumentException if the DER data is invalid
     */
    public WolfCryptX25519PublicKey(byte[] spkiDer, boolean isSpki) {
        if (spkiDer == null) {
            throw new IllegalArgumentException("SPKI DER cannot be null");
        }
        this.rawKey = extractRawFromSpki(spkiDer);
        this.spkiEncoded = spkiDer.clone();
    }

    /**
     * Create WolfCryptX25519PublicKey from a BigInteger u-coordinate.
     *
     * @param spec must be NamedParameterSpec.X25519
     * @param u the u-coordinate as a non-negative BigInteger
     * @throws IllegalArgumentException if spec is not X25519 or u is null
     */
    public WolfCryptX25519PublicKey(NamedParameterSpec spec, BigInteger u) {
        if (spec == null || !spec.getName().equalsIgnoreCase("X25519")) {
            throw new IllegalArgumentException("Only X25519 is supported");
        }
        if (u == null) {
            throw new IllegalArgumentException("u-coordinate cannot be null");
        }
        this.rawKey = bigIntegerToX25519Bytes(u);
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
                "Invalid X25519 SPKI DER: expected " + SPKI_TOTAL_LEN +
                " bytes, got " + der.length);
        }
        for (int i = 0; i < SPKI_PREFIX.length; i++) {
            if (der[i] != SPKI_PREFIX[i]) {
                throw new IllegalArgumentException(
                    "Invalid X25519 SPKI DER structure at byte " + i);
            }
        }
        byte[] out = new byte[32];
        System.arraycopy(der, SPKI_PREFIX.length, out, 0, 32);
        return out;
    }

    /**
     * Convert a BigInteger u-coordinate to 32-byte little-endian X25519 format.
     * The MSB of the last byte is cleared per RFC 7748.
     */
    static byte[] bigIntegerToX25519Bytes(BigInteger u) {
        byte[] uBytes = u.toByteArray();
        /* strip possible leading sign byte */
        if (uBytes.length > 0 && uBytes[0] == 0x00) {
            byte[] trimmed = new byte[uBytes.length - 1];
            System.arraycopy(uBytes, 1, trimmed, 0, trimmed.length);
            uBytes = trimmed;
        }

        /* copy into 32-byte big-endian buffer (right-aligned) */
        byte[] be = new byte[32];
        int srcStart = Math.max(0, uBytes.length - 32);
        int copyLen  = Math.min(uBytes.length, 32);
        int dstStart = 32 - copyLen;
        System.arraycopy(uBytes, srcStart, be, dstStart, copyLen);

        /* reverse to little-endian */
        byte[] le = new byte[32];
        for (int i = 0; i < 32; i++) {
            le[i] = be[31 - i];
        }

        /* clear MSB of last byte per RFC 7748 */
        le[31] = (byte) (le[31] & 0x7f);

        return le;
    }

    /**
     * Convert a 32-byte little-endian X25519 public key to a BigInteger
     * u-coordinate. The MSB of the last byte is cleared per RFC 7748.
     */
    private BigInteger x25519BytesToBigInteger(byte[] raw) {
        byte[] copy = raw.clone();
        /* clear top bit per RFC 7748 */
        copy[31] = (byte) (copy[31] & 0x7f);
        /* reverse to big-endian */
        byte[] be = new byte[32];
        for (int i = 0; i < 32; i++) {
            be[i] = copy[31 - i];
        }
        return new BigInteger(1, be);
    }

    /**
     * Return the package-private raw 32-byte public key for use by wolfJCE
     * components (e.g. WolfCryptKeyAgreement for X25519).
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
    public BigInteger getU() {
        synchronized (stateLock) {
            if (destroyed) {
                throw new IllegalStateException("Key has been destroyed");
            }
            return x25519BytesToBigInteger(rawKey);
        }
    }

    @Override
    public NamedParameterSpec getParams() {
        return NamedParameterSpec.X25519;
    }

    @Override
    public String getAlgorithm() {
        return "XDH";
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
        if (!(obj instanceof WolfCryptX25519PublicKey)) {
            return false;
        }
        WolfCryptX25519PublicKey other = (WolfCryptX25519PublicKey) obj;

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
                return "WolfCryptX25519PublicKey[DESTROYED]";
            }
            return "WolfCryptX25519PublicKey[algorithm=XDH, format=X.509]";
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
                    "Invalid deserialized X25519 public key state");
            }
            if (!Arrays.equals(
                    Arrays.copyOf(spkiEncoded, SPKI_PREFIX.length),
                    SPKI_PREFIX)) {
                throw new InvalidObjectException(
                    "SPKI prefix invalid in deserialized X25519 public key");
            }
            if (!Arrays.equals(
                    Arrays.copyOfRange(spkiEncoded,
                        SPKI_PREFIX.length, SPKI_TOTAL_LEN),
                    rawKey)) {
                throw new InvalidObjectException(
                    "SPKI encoding inconsistent with rawKey in " +
                    "deserialized X25519 public key");
            }
        }
    }
}
