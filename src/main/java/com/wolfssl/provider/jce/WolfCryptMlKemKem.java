/* WolfCryptMlKemKem.java
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

import java.util.Arrays;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.DecapsulateException;
import javax.crypto.spec.SecretKeySpec;

import com.wolfssl.wolfcrypt.MlKem;
import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfCrypt JCE ML-KEM (FIPS 203) Key Encapsulation Mechanism implementation.
 *
 * Implements the javax.crypto.KEMSpi interface (JDK 21+). This class is
 * compiled and registered only on JDK 21 or later. On Java 8 it is excluded
 * from the build and the provider does not register a "KEM" service.
 *
 * The base class works with any ML-KEM parameter set (taken from the key
 * passed to newEncapsulator/newDecapsulator). The level-specific inner
 * classes (wcMlKem512/768/1024) additionally require keys to match their
 * parameter set.
 */
public class WolfCryptMlKemKem implements KEMSpi {

    /* Required parameter set level, or -1 to accept any level. */
    private final int requiredLevel;

    /**
     * Create a new ML-KEM KEM accepting any parameter set.
     */
    public WolfCryptMlKemKem() {
        this.requiredLevel = -1;
    }

    /**
     * Create a new ML-KEM KEM restricted to a single parameter set.
     *
     * @param level required ML-KEM parameter set level
     */
    protected WolfCryptMlKemKem(int level) {
        this.requiredLevel = level;
    }

    /**
     * Create an encapsulator for the given ML-KEM public key.
     *
     * The SecureRandom parameter is intentionally ignored. wolfCrypt uses its
     * own internal RNG for ML-KEM encapsulation to ensure FIPS-compliant
     * randomness, consistent with the rest of wolfJCE.
     *
     * @param publicKey ML-KEM public key, either a wolfJCE key or a foreign
     *        key supplying an X.509 SubjectPublicKeyInfo encoding
     * @param spec must be null, ML-KEM takes no encapsulation parameters
     * @param secureRandom caller-supplied randomness (ignored)
     *
     * @return an encapsulator bound to the public key
     *
     * @throws InvalidAlgorithmParameterException if spec is non-null
     * @throws InvalidKeyException if the key is null or not a valid ML-KEM
     *         public key
     */
    @Override
    public KEMSpi.EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey,
        AlgorithmParameterSpec spec, SecureRandom secureRandom)
        throws InvalidAlgorithmParameterException, InvalidKeyException {

        int level;
        byte[] rawPublic;
        byte[] enc;

        if (publicKey == null) {
            throw new InvalidKeyException("PublicKey cannot be null");
        }

        /* ML-KEM does not take encapsulation parameters */
        if (spec != null) {
            throw new InvalidAlgorithmParameterException(
                "ML-KEM does not accept an AlgorithmParameterSpec");
        }

        if (publicKey instanceof WolfCryptMlKemPublicKey) {
            WolfCryptMlKemPublicKey wk = (WolfCryptMlKemPublicKey)publicKey;
            level = wk.getLevel();
            rawPublic = wk.getRawPublicKey();
        }
        else {
            if (!WolfCryptMlKemUtil.isMlKemAlgorithm(
                publicKey.getAlgorithm())) {
                throw new InvalidKeyException(
                    "Key is not an ML-KEM key: " + publicKey.getAlgorithm());
            }

            enc = publicKey.getEncoded();
            if (enc == null) {
                throw new InvalidKeyException(
                    "PublicKey.getEncoded() returned null");
            }

            try {
                WolfCryptMlKemUtil.ParsedPublic p =
                    WolfCryptMlKemUtil.parsePublicKey(enc);
                level = p.level;
                rawPublic = p.rawPublic;
            } catch (IllegalArgumentException e) {
                throw new InvalidKeyException(
                    "Invalid ML-KEM public key: " + e.getMessage(), e);
            }
        }

        if (rawPublic == null) {
            throw new InvalidKeyException("ML-KEM public key is unavailable");
        }
        checkRequiredLevel(level);

        return new WolfCryptMlKemEncapsulator(level, rawPublic);
    }

    @Override
    public KEMSpi.DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey,
        AlgorithmParameterSpec spec) throws InvalidAlgorithmParameterException,
        InvalidKeyException {

        int level;
        byte[] expanded = null;
        byte[] enc;

        if (privateKey == null) {
            throw new InvalidKeyException("PrivateKey cannot be null");
        }

        if (spec != null) {
            throw new InvalidAlgorithmParameterException(
                "ML-KEM does not accept an AlgorithmParameterSpec");
        }

        if (privateKey instanceof WolfCryptMlKemPrivateKey) {
            WolfCryptMlKemPrivateKey wk = (WolfCryptMlKemPrivateKey)privateKey;
            level = wk.getLevel();
            expanded = wk.getExpandedPrivateKey();
        }
        else {
            if (!WolfCryptMlKemUtil.isMlKemAlgorithm(
                privateKey.getAlgorithm())) {
                throw new InvalidKeyException(
                    "Key is not an ML-KEM key: " + privateKey.getAlgorithm());
            }

            enc = privateKey.getEncoded();
            if (enc == null) {
                throw new InvalidKeyException(
                    "PrivateKey.getEncoded() returned null");
            }

            WolfCryptMlKemUtil.ParsedPrivate p = null;
            try {
                /* Parse the raw key directly rather than building a full
                 * WolfCryptMlKemPrivateKey (avoids re-encoding PKCS#8).
                 * Parsing accepts all CHOICE forms. A seed-only key is
                 * expanded to the FIPS 203 key. */
                p = WolfCryptMlKemUtil.parsePrivateKey(enc);
                level = p.level;
                if (p.seed != null) {
                    /* Derive expanded key from seed and, for both form,
                     * verify the supplied expandedKey agrees */
                    expanded = WolfCryptMlKemPrivateKey.expandSeed(
                        p.level, p.seed);
                    if (p.expanded != null &&
                        !Arrays.equals(p.expanded, expanded)) {
                        throw new IllegalArgumentException(
                            "ML-KEM both encoding: seed and " +
                            "expandedKey disagree");
                    }
                }
                else {
                    expanded = p.expanded;
                }

            } catch (IllegalArgumentException e) {
                throw new InvalidKeyException(
                    "Invalid ML-KEM private key: " + e.getMessage(), e);

            } finally {
                Arrays.fill(enc, (byte)0);
                if ((p != null) && (p.seed != null)) {
                    Arrays.fill(p.seed, (byte)0);
                }
                if ((p != null) && (p.expanded != null) &&
                    (p.expanded != expanded)) {
                    Arrays.fill(p.expanded, (byte)0);
                }
            }
        }

        if (expanded == null) {
            throw new InvalidKeyException("ML-KEM private key is unavailable");
        }
        checkRequiredLevel(level);

        return new WolfCryptMlKemDecapsulator(level, expanded);
    }

    /**
     * Reject a key whose parameter set does not match the level this KEM
     * instance is locked to (the per-level wcMlKem512/768/1024 aliases).
     */
    private void checkRequiredLevel(int level) throws InvalidKeyException {

        if (this.requiredLevel >= 0 && level != this.requiredLevel) {
            throw new InvalidKeyException("ML-KEM key level " + level +
                " does not match required level " + this.requiredLevel);
        }
    }

    /**
     * Validate the from/to/algorithm arguments of an encapsulate or
     * decapsulate call against the shared secret size reported by
     * engineSecretSize().
     */
    private static void checkRange(int from, int to, String algorithm,
        int secretSize) {

        if (algorithm == null) {
            throw new NullPointerException("algorithm cannot be null");
        }
        /* Reject an empty or out-of-bounds range. A zero-length range
         * (from == to) is not a valid shared secret. */
        if (from < 0 || from >= to || to > secretSize) {
            throw new IndexOutOfBoundsException(
                "Invalid range [" + from + ", " + to + ") for ML-KEM " +
                "shared secret of size " + secretSize);
        }
    }

    /**
     * ML-KEM encapsulator. Immutable, holds the parameter set level and raw
     * public key.
     */
    private static final class WolfCryptMlKemEncapsulator
        implements KEMSpi.EncapsulatorSpi {

        private final int level;
        private final byte[] rawPublic;

        private Rng rng = null;
        private final Object rngLock = new Object();

        WolfCryptMlKemEncapsulator(int level, byte[] rawPublic) {
            this.level = level;
            this.rawPublic = rawPublic;
        }

        @Override
        public KEM.Encapsulated engineEncapsulate(int from, int to,
            String algorithm) {

            MlKem mlkem = null;
            byte[] ct;
            byte[] ss;
            byte[] secret;

            checkRange(from, to, algorithm, engineSecretSize());

            synchronized (rngLock) {
                if (this.rng == null) {
                    this.rng = new Rng();
                    this.rng.init();
                }

                try {
                    mlkem = new MlKem(this.level);
                    mlkem.importPublic(this.rawPublic);

                    byte[][] result = mlkem.encapsulate(this.rng);
                    ct = result[0];
                    ss = result[1];

                } catch (WolfCryptException e) {
                    throw new IllegalStateException(
                        "ML-KEM encapsulation failed: " + e.getMessage(), e);

                } finally {
                    if (mlkem != null) {
                        mlkem.releaseNativeStruct();
                    }
                }
            }

            secret = Arrays.copyOfRange(ss, from, to);
            Arrays.fill(ss, (byte)0);
            SecretKey key = new SecretKeySpec(secret, algorithm);
            Arrays.fill(secret, (byte)0);

            return new KEM.Encapsulated(key, ct, null);
        }

        @Override
        public int engineSecretSize() {
            return MlKem.ML_KEM_SHARED_SECRET_SIZE;
        }

        @Override
        public int engineEncapsulationSize() {
            return WolfCryptMlKemUtil.expectedCiphertextSize(this.level);
        }

        @SuppressWarnings({"deprecation", "removal"})
        @Override
        protected synchronized void finalize() throws Throwable {
            try {
                synchronized (rngLock) {
                    if (this.rng != null) {
                        this.rng.free();
                        this.rng.releaseNativeStruct();
                    }
                }
            } finally {
                super.finalize();
            }
        }
    }

    /**
     * ML-KEM decapsulator. Immutable, holds the parameter set level and raw
     * expanded private key.
     */
    private static final class WolfCryptMlKemDecapsulator
        implements KEMSpi.DecapsulatorSpi {

        private final int level;
        private final byte[] expanded;

        WolfCryptMlKemDecapsulator(int level, byte[] expanded) {
            this.level = level;
            this.expanded = expanded;
        }

        @Override
        public SecretKey engineDecapsulate(byte[] encapsulation, int from,
            int to, String algorithm) throws DecapsulateException {

            MlKem mlkem = null;
            byte[] ss;
            byte[] secret;

            checkRange(from, to, algorithm, engineSecretSize());

            if (encapsulation == null) {
                throw new NullPointerException("encapsulation cannot be null");
            }

            if (encapsulation.length !=
                WolfCryptMlKemUtil.expectedCiphertextSize(this.level)) {
                throw new DecapsulateException(
                    "Invalid ML-KEM ciphertext length: " +
                    encapsulation.length);
            }

            try {
                mlkem = new MlKem(this.level);
                mlkem.importPrivate(this.expanded);
                ss = mlkem.decapsulate(encapsulation);

            } catch (WolfCryptException e) {
                throw new DecapsulateException(
                    "ML-KEM decapsulation failed: " + e.getMessage(), e);

            } finally {
                if (mlkem != null) {
                    mlkem.releaseNativeStruct();
                }
            }

            secret = Arrays.copyOfRange(ss, from, to);
            Arrays.fill(ss, (byte)0);
            SecretKey key = new SecretKeySpec(secret, algorithm);
            Arrays.fill(secret, (byte)0);

            return key;
        }

        @Override
        public int engineSecretSize() {
            return MlKem.ML_KEM_SHARED_SECRET_SIZE;
        }

        @Override
        public int engineEncapsulationSize() {
            return WolfCryptMlKemUtil.expectedCiphertextSize(this.level);
        }

        /**
         * Zero the retained expanded private (decapsulation) key when this
         * decapsulator is collected. DecapsulatorSpi exposes no destroy()
         * hook, so this is the only point the held key copy can be wiped.
         */
        @SuppressWarnings({"deprecation", "removal"})
        @Override
        protected void finalize() throws Throwable {
            try {
                if (this.expanded != null) {
                    Arrays.fill(this.expanded, (byte) 0);
                }
            } finally {
                super.finalize();
            }
        }
    }

    /**
     * wolfCrypt ML-KEM-512 KEM class.
     */
    public static final class wcMlKem512 extends WolfCryptMlKemKem {
        /**
         * Create new wcMlKem512 object.
         */
        public wcMlKem512() {
            super(MlKem.ML_KEM_512);
        }
    }

    /**
     * wolfCrypt ML-KEM-768 KEM class.
     */
    public static final class wcMlKem768 extends WolfCryptMlKemKem {
        /**
         * Create new wcMlKem768 object.
         */
        public wcMlKem768() {
            super(MlKem.ML_KEM_768);
        }
    }

    /**
     * wolfCrypt ML-KEM-1024 KEM class.
     */
    public static final class wcMlKem1024 extends WolfCryptMlKemKem {
        /**
         * Create new wcMlKem1024 object.
         */
        public wcMlKem1024() {
            super(MlKem.ML_KEM_1024);
        }
    }
}

