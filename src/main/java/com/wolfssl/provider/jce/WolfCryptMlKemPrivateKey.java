/* WolfCryptMlKemPrivateKey.java
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
import javax.security.auth.Destroyable;

import com.wolfssl.wolfcrypt.MlKem;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfCrypt JCE ML-KEM (FIPS 203) private key.
 *
 * Holds the ML-KEM parameter set level, the raw expanded (FIPS 203)
 * decapsulation key bytes, and optionally the 64-byte FIPS 203 key
 * generation seed. getEncoded() returns a PKCS#8 PrivateKeyInfo (RFC 9935)
 * in the CHOICE form selected by the {@code jdk.mlkem.pkcs8.encoding}
 * property (default expandedKey, byte-for-byte compatible with the JDK
 * reference implementation). The seed and both forms require a retained
 * seed and otherwise fall back to expandedKey. Input keys in any of the
 * three CHOICE forms (seed, expandedKey, both) are accepted. A seed-only
 * key is expanded via native ML-KEM key generation so the expanded key is
 * always available for decapsulation. getAlgorithm() returns "ML-KEM" to
 * match the JDK regardless of parameter set.
 */
public class WolfCryptMlKemPrivateKey implements PrivateKey, Destroyable {

    private static final long serialVersionUID = 1L;

    /** ML-KEM parameter set (MlKem.ML_KEM_512/768/1024). */
    private int level;

    /** Raw expanded (FIPS 203) decapsulation key bytes. */
    private byte[] expanded = null;

    /** 64-byte FIPS 203 key generation seed, or null if not available.
     * Retained so the seed and both PKCS#8 output forms can be produced. */
    private byte[] seed = null;

    /** Cached PKCS#8 encoding (form per jdk.mlkem.pkcs8.encoding). */
    private byte[] encoded = null;

    /** Cached expandedKey form PKCS#8 used for equals()/hashCode()
     * so key identity is independent of the configured output form.
     * Transient: recomputed from level+expanded after deserialization. */
    private transient byte[] canonical = null;

    /** True once this key has been destroyed. */
    private boolean destroyed = false;

    /** Lock around object state. */
    private transient Object stateLock = new Object();

    /**
     * Create an ML-KEM private key from a parameter set and raw expanded key.
     *
     * @param level ML-KEM parameter set
     * @param expanded raw expanded (FIPS 203) decapsulation key bytes
     *
     * @throws IllegalArgumentException if inputs are invalid
     */
    public WolfCryptMlKemPrivateKey(int level, byte[] expanded)
        throws IllegalArgumentException {

        this(level, expanded, null);
    }

    /**
     * Create an ML-KEM private key from a parameter set, raw expanded key,
     * and optionally the 64-byte generation seed.
     *
     * Retaining the seed allows the seed and both PKCS#8 output forms (see
     * the {@code jdk.mlkem.pkcs8.encoding} property) to be produced.
     *
     * @param level ML-KEM parameter set
     * @param expanded raw expanded (FIPS 203) decapsulation key bytes
     * @param seed 64-byte generation seed, or null if unavailable
     *
     * @throws IllegalArgumentException if inputs are invalid
     */
    public WolfCryptMlKemPrivateKey(int level, byte[] expanded, byte[] seed)
        throws IllegalArgumentException {

        if (expanded == null || expanded.length == 0) {
            throw new IllegalArgumentException(
                "ML-KEM private key bytes cannot be null or empty");
        }

        WolfCryptMlKemUtil.checkExpandedKeyLength(level, expanded.length);

        if (seed != null && seed.length != MlKem.ML_KEM_SEED_SIZE) {
            throw new IllegalArgumentException(
                "ML-KEM seed length " + seed.length + " is invalid");
        }

        this.level = level;
        this.expanded = expanded.clone();
        this.seed = (seed == null) ? null : seed.clone();
        this.encoded = buildEncoded(this.level, this.expanded, this.seed);
    }

    /**
     * Create an ML-KEM private key from a PKCS#8 PrivateKeyInfo encoding.
     *
     * Accepts the seed [0], expandedKey, and both CHOICE forms. A seed-only
     * key is expanded via native ML-KEM key generation.
     *
     * @param pkcs8Der DER-encoded PrivateKeyInfo
     *
     * @throws IllegalArgumentException if the encoding is invalid
     */
    public WolfCryptMlKemPrivateKey(byte[] pkcs8Der)
        throws IllegalArgumentException {

        WolfCryptMlKemUtil.ParsedPrivate parsed;
        byte[] exp;

        if (pkcs8Der == null) {
            throw new IllegalArgumentException("Encoded key cannot be null");
        }

        parsed = WolfCryptMlKemUtil.parsePrivateKey(pkcs8Der);

        try {
            if (parsed.seed != null) {
                /* Derive the expanded key from the seed. For the both form,
                 * verify the supplied expandedKey agrees with the seed-derived
                 * key so a mismatched key cannot later be re-encoded as an
                 * inconsistent seed form. */
                exp = expandSeed(parsed.level, parsed.seed);
                if (parsed.expanded != null &&
                    !Arrays.equals(parsed.expanded, exp)) {
                    throw new IllegalArgumentException(
                        "ML-KEM both encoding: seed and expandedKey disagree");
                }
            }
            else {
                exp = parsed.expanded;
            }

            this.level = parsed.level;
            this.expanded = exp;
            this.seed = (parsed.seed == null) ? null : parsed.seed.clone();
            this.encoded = buildEncoded(this.level, this.expanded, this.seed);
        }
        finally {
            if (parsed.seed != null) {
                Arrays.fill(parsed.seed, (byte) 0);
            }
            if ((parsed.expanded != null) &&
                (parsed.expanded != this.expanded)) {
                Arrays.fill(parsed.expanded, (byte) 0);
            }
        }
    }

    /**
     * Build the PKCS#8 encoding for this key, honoring the
     * {@code jdk.mlkem.pkcs8.encoding} property captured at creation time.
     * Falls back to the expandedKey form if the seed or both form is
     * requested but no seed is available (a key imported in expandedKey
     * form).
     */
    private static byte[] buildEncoded(int level, byte[] expanded,
        byte[] seed) {

        int pref = WolfCryptMlKemUtil.configuredPkcs8Encoding();

        if (seed != null && pref == WolfCryptMlKemUtil.ENCODING_SEED) {
            return WolfCryptMlKemUtil.encodePrivateKeySeed(level, seed);
        }
        else if (seed != null && pref == WolfCryptMlKemUtil.ENCODING_BOTH) {
            return WolfCryptMlKemUtil.encodePrivateKeyBoth(level, seed,
                expanded);
        }

        return WolfCryptMlKemUtil.encodePrivateKeyExpanded(level, expanded);
    }

    /**
     * Expand a 64-byte ML-KEM seed into the raw expanded decapsulation key
     * using native deterministic key generation.
     */
    static byte[] expandSeed(int level, byte[] seed)
        throws IllegalArgumentException {

        MlKem key = null;

        try {
            key = new MlKem(level);
            key.makeKeyFromSeed(seed);
            return key.exportPrivate();

        } catch (WolfCryptException e) {
            throw new IllegalArgumentException(
                "Failed to expand ML-KEM seed: " + e.getMessage(), e);

        } finally {
            if (key != null) {
                key.releaseNativeStruct();
            }
        }
    }

    /**
     * Get the ML-KEM parameter set of this key.
     *
     * @return one of MlKem.ML_KEM_512/768/1024
     */
    int getLevel() {
        synchronized (stateLock) {
            return this.level;
        }
    }

    /**
     * Get the raw expanded decapsulation key bytes.
     *
     * @return clone of the expanded private key bytes, or null if destroyed
     */
    byte[] getExpandedPrivateKey() {
        synchronized (stateLock) {
            if (destroyed || expanded == null) {
                return null;
            }
            return expanded.clone();
        }
    }

    @Override
    public String getAlgorithm() {
        return "ML-KEM";
    }

    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        synchronized (stateLock) {
            if (destroyed || encoded == null) {
                return null;
            }
            return encoded.clone();
        }
    }

    @Override
    public void destroy() {
        synchronized (stateLock) {
            if (!destroyed) {
                if (expanded != null) {
                    Arrays.fill(expanded, (byte) 0);
                    expanded = null;
                }
                if (seed != null) {
                    Arrays.fill(seed, (byte) 0);
                    seed = null;
                }
                if (encoded != null) {
                    Arrays.fill(encoded, (byte) 0);
                    encoded = null;
                }
                if (canonical != null) {
                    Arrays.fill(canonical, (byte) 0);
                    canonical = null;
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

    /**
     * ExpandedKey form PKCS#8 used for equals()/hashCode(), so key identity
     * is independent of the configured output form. Returns fresh copy or
     * null if destroyed.
     */
    private byte[] canonicalEncoding() {
        synchronized (stateLock) {
            if (destroyed || expanded == null) {
                return null;
            }
            if (canonical == null) {
                canonical = WolfCryptMlKemUtil.encodePrivateKeyExpanded(
                    level, expanded);
            }
            return canonical.clone();
        }
    }

    @Override
    public int hashCode() {
        synchronized (stateLock) {
            if (destroyed || expanded == null) {
                return 0;
            }
            if (canonical == null) {
                canonical = WolfCryptMlKemUtil.encodePrivateKeyExpanded(
                    level, expanded);
            }
            return Arrays.hashCode(canonical);
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PrivateKey)) {
            return false;
        }

        /* Compare on the canonical expandedKey-form encoding so the same
         * logical key compares equal regardless of the configured PKCS#8
         * output form. */
        byte[] mine = canonicalEncoding();
        if (mine == null) {
            return false;
        }

        byte[] theirs;
        if (obj instanceof WolfCryptMlKemPrivateKey) {
            theirs = ((WolfCryptMlKemPrivateKey) obj).canonicalEncoding();
        }
        else {
            theirs = ((PrivateKey) obj).getEncoded();
        }

        return Arrays.equals(mine, theirs);
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
