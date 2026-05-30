/* WolfCryptX25519PrivateKey.java
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
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Optional;
import java.security.interfaces.XECPrivateKey;
import java.security.spec.NamedParameterSpec;
import javax.security.auth.Destroyable;

/**
 * wolfJCE XECPrivateKey implementation for X25519 (XDH key agreement).
 *
 * Stores the 32-byte private scalar and a DER-encoded PKCS#8 form using
 * OID 1.3.101.110 (id-X25519).
 */
public class WolfCryptX25519PrivateKey implements XECPrivateKey, Destroyable {

    private static final long serialVersionUID = 1L;

    /** Raw 32-byte X25519 private scalar. Zeroed on destroy(). */
    private byte[] scalar = null;

    /** DER PKCS#8 encoded form. Zeroed on destroy(). */
    private byte[] pkcs8Encoded = null;

    /** Whether this key has been destroyed. */
    private boolean destroyed = false;

    /** Lock around state and sensitive fields. */
    private transient Object stateLock = new Object();

    /*
     * PKCS#8 DER prefix for X25519 private key (16 bytes).
     * Full encoding: prefix (16 bytes) + 32-byte scalar = 48 bytes total.
     *
     *   30 2e              SEQUENCE, 46 bytes
     *     02 01 00         INTEGER 0 (version)
     *     30 05            SEQUENCE, 5 bytes (AlgorithmIdentifier)
     *       06 03 2b 65 6e OID 1.3.101.110 (id-X25519)
     *     04 22            OCTET STRING, 34 bytes (PrivateKey)
     *       04 20          OCTET STRING, 32 bytes (scalar)
     */
    private static final byte[] PKCS8_PREFIX = {
        0x30, 0x2e,
        0x02, 0x01, 0x00,
        0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x6e,
        0x04, 0x22,
        0x04, 0x20
    };

    private static final int PKCS8_TOTAL_LEN = PKCS8_PREFIX.length + 32; /* 48 */

    /**
     * Create WolfCryptX25519PrivateKey from a raw 32-byte X25519 scalar.
     *
     * @param scalar 32-byte private scalar
     * @throws IllegalArgumentException if scalar is null or not 32 bytes
     */
    public WolfCryptX25519PrivateKey(byte[] scalar) {
        if (scalar == null || scalar.length != 32) {
            throw new IllegalArgumentException(
                "X25519 private scalar must be exactly 32 bytes");
        }
        this.scalar = scalar.clone();
        this.pkcs8Encoded = buildPkcs8(this.scalar);
    }

    /**
     * Create WolfCryptX25519PrivateKey from DER-encoded PKCS#8 data.
     *
     * @param pkcs8Der DER-encoded PKCS#8 private key (48 bytes)
     * @throws IllegalArgumentException if the DER data is invalid
     */
    public WolfCryptX25519PrivateKey(byte[] pkcs8Der, boolean isPkcs8) {
        if (pkcs8Der == null) {
            throw new IllegalArgumentException("PKCS#8 DER cannot be null");
        }
        this.scalar = extractScalarFromPkcs8(pkcs8Der);
        this.pkcs8Encoded = pkcs8Der.clone();
    }

    /** Build PKCS#8 DER from a 32-byte scalar. */
    static byte[] buildPkcs8(byte[] scalar) {
        byte[] out = new byte[PKCS8_TOTAL_LEN];
        System.arraycopy(PKCS8_PREFIX, 0, out, 0, PKCS8_PREFIX.length);
        System.arraycopy(scalar, 0, out, PKCS8_PREFIX.length, 32);
        return out;
    }

    /** Extract 32-byte scalar from PKCS#8 DER, validating structure. */
    static byte[] extractScalarFromPkcs8(byte[] der) {
        if (der.length != PKCS8_TOTAL_LEN) {
            throw new IllegalArgumentException(
                "Invalid X25519 PKCS#8 DER: expected " + PKCS8_TOTAL_LEN +
                " bytes, got " + der.length);
        }
        for (int i = 0; i < PKCS8_PREFIX.length; i++) {
            if (der[i] != PKCS8_PREFIX[i]) {
                throw new IllegalArgumentException(
                    "Invalid X25519 PKCS#8 DER structure at byte " + i);
            }
        }
        byte[] out = new byte[32];
        System.arraycopy(der, PKCS8_PREFIX.length, out, 0, 32);
        return out;
    }

    /**
     * Return the raw 32-byte X25519 private scalar.
     * Returns empty Optional if the key has been destroyed.
     */
    @Override
    public Optional<byte[]> getScalar() {
        synchronized (stateLock) {
            if (destroyed) {
                return Optional.empty();
            }
            return Optional.of(scalar.clone());
        }
    }

    /**
     * Return the raw scalar bytes for use within the JCE provider package.
     * Caller is responsible for zeroing the returned array after use.
     *
     * @return cloned 32-byte scalar, or null if destroyed
     */
    byte[] getRawScalar() {
        synchronized (stateLock) {
            if (destroyed) {
                return null;
            }
            return scalar.clone();
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
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        synchronized (stateLock) {
            if (destroyed) {
                return null;
            }
            return pkcs8Encoded.clone();
        }
    }

    @Override
    public void destroy() {
        synchronized (stateLock) {
            if (!destroyed) {
                if (scalar != null) {
                    Arrays.fill(scalar, (byte) 0);
                    scalar = null;
                }
                if (pkcs8Encoded != null) {
                    Arrays.fill(pkcs8Encoded, (byte) 0);
                    pkcs8Encoded = null;
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
            return Arrays.hashCode(pkcs8Encoded);
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof WolfCryptX25519PrivateKey)) {
            return false;
        }
        WolfCryptX25519PrivateKey other = (WolfCryptX25519PrivateKey) obj;

        /* Snapshot each key's encoded form under its own lock to avoid ABBA
         * deadlock. Compare outside both locks using constant-time equality
         * to reduce timing side-channel exposure for private key material.
         * Copies are zeroed in finally to limit exposure on the heap. */
        byte[] thisEncoded;
        byte[] otherEncoded = null;

        synchronized (stateLock) {
            if (destroyed) {
                return false;
            }
            thisEncoded = pkcs8Encoded.clone();
        }
        try {
            synchronized (other.stateLock) {
                if (other.destroyed) {
                    return false;
                }
                otherEncoded = other.pkcs8Encoded.clone();
            }
            return MessageDigest.isEqual(thisEncoded, otherEncoded);
        } finally {
            Arrays.fill(thisEncoded, (byte) 0);
            if (otherEncoded != null) {
                Arrays.fill(otherEncoded, (byte) 0);
            }
        }
    }

    @Override
    public String toString() {
        synchronized (stateLock) {
            if (destroyed) {
                return "WolfCryptX25519PrivateKey[DESTROYED]";
            }
            return "WolfCryptX25519PrivateKey[algorithm=XDH, format=PKCS#8]";
        }
    }

    private void readObject(ObjectInputStream in)
        throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        stateLock = new Object();
        if (!destroyed) {
            if (scalar == null || scalar.length != 32 ||
                pkcs8Encoded == null ||
                pkcs8Encoded.length != PKCS8_TOTAL_LEN) {
                throw new InvalidObjectException(
                    "Invalid deserialized X25519 private key state");
            }
        }
    }
}
