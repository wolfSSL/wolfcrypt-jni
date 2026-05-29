/* WolfCryptEdDSAPrivateKey.java
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
import java.util.Optional;
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.NamedParameterSpec;
import javax.security.auth.Destroyable;

/**
 * wolfJCE EdECPrivateKey implementation for Ed25519.
 *
 * Stores the 32-byte private key seed and a corresponding DER-encoded
 * PKCS#8 form. The PKCS#8 structure uses OID 1.3.101.112 (id-Ed25519).
 */
public class WolfCryptEdDSAPrivateKey implements EdECPrivateKey, Destroyable {

    private static final long serialVersionUID = 1L;

    /** Raw 32-byte Ed25519 private key seed. Zeroed on destroy(). */
    private byte[] seed = null;

    /** DER PKCS#8 encoded form. Zeroed on destroy(). */
    private byte[] pkcs8Encoded = null;

    /** Whether this key has been destroyed. */
    private boolean destroyed = false;

    /** Lock around state and sensitive fields. */
    private transient Object stateLock = new Object();

    /*
     * PKCS#8 DER prefix for Ed25519 private key (16 bytes).
     * Full encoding: prefix (16 bytes) + 32-byte seed = 48 bytes total.
     *
     *   30 2e              SEQUENCE, 46 bytes
     *     02 01 00         INTEGER 0 (version)
     *     30 05            SEQUENCE, 5 bytes (AlgorithmIdentifier)
     *       06 03 2b 65 70 OID 1.3.101.112 (id-Ed25519)
     *     04 22            OCTET STRING, 34 bytes (PrivateKey)
     *       04 20          OCTET STRING, 32 bytes (seed)
     */
    static final byte[] PKCS8_PREFIX = {
        0x30, 0x2e,
        0x02, 0x01, 0x00,
        0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x70,
        0x04, 0x22,
        0x04, 0x20
    };

    static final int PKCS8_TOTAL_LEN = PKCS8_PREFIX.length + 32; /* 48 */

    /**
     * Create WolfCryptEdDSAPrivateKey from a raw 32-byte Ed25519 seed.
     *
     * @param seed 32-byte private key seed
     * @throws IllegalArgumentException if seed is null or not 32 bytes
     */
    public WolfCryptEdDSAPrivateKey(byte[] seed) {
        if (seed == null || seed.length != 32) {
            throw new IllegalArgumentException(
                "Ed25519 private key seed must be exactly 32 bytes");
        }
        this.seed = seed.clone();
        this.pkcs8Encoded = buildPkcs8(this.seed);
    }

    /**
     * Create WolfCryptEdDSAPrivateKey from DER-encoded PKCS#8 data.
     *
     * @param pkcs8Der DER-encoded PKCS#8 private key (48 bytes)
     * @param isPkcs8  must be true; present only to disambiguate from
     *                 the seed constructor
     * @throws IllegalArgumentException if the DER data is invalid
     */
    public WolfCryptEdDSAPrivateKey(byte[] pkcs8Der, boolean isPkcs8) {
        if (pkcs8Der == null) {
            throw new IllegalArgumentException("PKCS#8 DER cannot be null");
        }
        this.seed = extractSeedFromPkcs8(pkcs8Der);
        this.pkcs8Encoded = pkcs8Der.clone();
    }

    /** Build PKCS#8 DER from a 32-byte seed. */
    static byte[] buildPkcs8(byte[] seed) {
        byte[] out = new byte[PKCS8_TOTAL_LEN];
        System.arraycopy(PKCS8_PREFIX, 0, out, 0, PKCS8_PREFIX.length);
        System.arraycopy(seed, 0, out, PKCS8_PREFIX.length, 32);
        return out;
    }

    /** Extract 32-byte seed from PKCS#8 DER, validating structure. */
    static byte[] extractSeedFromPkcs8(byte[] der) {
        if (der.length != PKCS8_TOTAL_LEN) {
            throw new IllegalArgumentException(
                "Invalid Ed25519 PKCS#8 DER: expected " + PKCS8_TOTAL_LEN +
                " bytes, got " + der.length);
        }
        for (int i = 0; i < PKCS8_PREFIX.length; i++) {
            if (der[i] != PKCS8_PREFIX[i]) {
                throw new IllegalArgumentException(
                    "Invalid Ed25519 PKCS#8 DER structure at byte " + i);
            }
        }
        byte[] out = new byte[32];
        System.arraycopy(der, PKCS8_PREFIX.length, out, 0, 32);
        return out;
    }

    /**
     * Return the raw 32-byte Ed25519 private key seed.
     * Returns empty Optional if the key has been destroyed.
     */
    @Override
    public Optional<byte[]> getBytes() {
        synchronized (stateLock) {
            if (destroyed) {
                return Optional.empty();
            }
            return Optional.of(seed.clone());
        }
    }

    /**
     * Return the raw seed bytes for use within the JCE provider package.
     * Caller is responsible for zeroing the returned array after use.
     *
     * @return cloned 32-byte seed, or null if destroyed
     */
    byte[] getRawSeed() {
        synchronized (stateLock) {
            if (destroyed) {
                return null;
            }
            return seed.clone();
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
                if (seed != null) {
                    Arrays.fill(seed, (byte) 0);
                    seed = null;
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
        if (!(obj instanceof WolfCryptEdDSAPrivateKey)) {
            return false;
        }
        WolfCryptEdDSAPrivateKey other = (WolfCryptEdDSAPrivateKey) obj;
        synchronized (stateLock) {
            if (destroyed) {
                return false;
            }
            synchronized (other.stateLock) {
                if (other.destroyed) {
                    return false;
                }
                return Arrays.equals(this.pkcs8Encoded, other.pkcs8Encoded);
            }
        }
    }

    @Override
    public String toString() {
        synchronized (stateLock) {
            if (destroyed) {
                return "WolfCryptEdDSAPrivateKey[DESTROYED]";
            }
            return "WolfCryptEdDSAPrivateKey[algorithm=EdDSA, format=PKCS#8]";
        }
    }

    private void readObject(ObjectInputStream in)
        throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        stateLock = new Object();
    }
}
