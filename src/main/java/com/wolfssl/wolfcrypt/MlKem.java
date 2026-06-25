/* MlKem.java
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

package com.wolfssl.wolfcrypt;

import java.util.Arrays;

/**
 * Wrapper for the native wolfCrypt ML-KEM (FIPS 203) implementation.
 *
 * ML-KEM is a Key Encapsulation Mechanism (KEM), formerly known as Kyber.
 * This thin wrapper exposes the raw native operations: key generation
 * (from an internal RNG or a deterministic 64-byte seed), encapsulation,
 * decapsulation, and raw key import/export. All higher level encoding
 * (X.509 SubjectPublicKeyInfo, PKCS#8) is handled by the JCE provider
 * classes in com.wolfssl.provider.jce.
 */
public class MlKem extends NativeStruct {

    /** ML-KEM-512 parameter set, NIST security category 1. */
    public static final int ML_KEM_512 = 512;

    /** ML-KEM-768 parameter set, NIST security category 3. */
    public static final int ML_KEM_768 = 768;

    /** ML-KEM-1024 parameter set, NIST security category 5. */
    public static final int ML_KEM_1024 = 1024;

    /** ML-KEM key generation seed length, in bytes (FIPS 203, d || z). */
    public static final int ML_KEM_SEED_SIZE = 64;

    /** ML-KEM shared secret length, in bytes (all parameter sets). */
    public static final int ML_KEM_SHARED_SECRET_SIZE = 32;

    /** ML-KEM encapsulation randomness length, in bytes (FIPS 203 m). */
    public static final int ML_KEM_ENCAPS_RANDOM_SIZE = 32;

    /** ML-KEM-512 raw public (encapsulation) key size, in bytes. */
    public static final int ML_KEM_512_PUBLIC_KEY_SIZE = 800;
    /** ML-KEM-512 raw expanded private (decapsulation) key size, bytes. */
    public static final int ML_KEM_512_PRIVATE_KEY_SIZE = 1632;
    /** ML-KEM-512 ciphertext size, in bytes. */
    public static final int ML_KEM_512_CIPHERTEXT_SIZE = 768;

    /** ML-KEM-768 raw public (encapsulation) key size, in bytes. */
    public static final int ML_KEM_768_PUBLIC_KEY_SIZE = 1184;
    /** ML-KEM-768 raw expanded private (decapsulation) key size, bytes. */
    public static final int ML_KEM_768_PRIVATE_KEY_SIZE = 2400;
    /** ML-KEM-768 ciphertext size, in bytes. */
    public static final int ML_KEM_768_CIPHERTEXT_SIZE = 1088;

    /** ML-KEM-1024 raw public (encapsulation) key size, in bytes. */
    public static final int ML_KEM_1024_PUBLIC_KEY_SIZE = 1568;
    /** ML-KEM-1024 raw expanded private (decapsulation) key size, bytes. */
    public static final int ML_KEM_1024_PRIVATE_KEY_SIZE = 3168;
    /** ML-KEM-1024 ciphertext size, in bytes. */
    public static final int ML_KEM_1024_CIPHERTEXT_SIZE = 1568;

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /** ML-KEM parameter set for this object. */
    private final int level;

    /** Lock around object state */
    protected final Object stateLock = new Object();

    /**
     * Create a new ML-KEM object for the given parameter set.
     *
     * @param level one of {@link #ML_KEM_512}, {@link #ML_KEM_768},
     *              {@link #ML_KEM_1024}.
     *
     * @throws WolfCryptException if ML-KEM is not compiled into native
     *         wolfCrypt or {@code level} is not a valid parameter set.
     */
    public MlKem(int level) throws WolfCryptException {

        if (!FeatureDetect.MlKemEnabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }

        if (level != ML_KEM_512 && level != ML_KEM_768 &&
            level != ML_KEM_1024) {
            throw new WolfCryptException(WolfCryptError.BAD_FUNC_ARG.getCode());
        }
        this.level = level;
        /* Internal state is initialized on first use */
    }

    /**
     * Get the ML-KEM parameter set of this object.
     *
     * @return one of {@link #ML_KEM_512}, {@link #ML_KEM_768},
     *         {@link #ML_KEM_1024}.
     */
    public int getLevel() {
        return this.level;
    }

    @Override
    public void releaseNativeStruct() {
        synchronized (stateLock) {
            if ((state != WolfCryptState.UNINITIALIZED) &&
                (state != WolfCryptState.RELEASED)) {

                synchronized (pointerLock) {
                    wc_mlkem_free();
                }
                super.releaseNativeStruct();
                state = WolfCryptState.RELEASED;
            }
        }
    }

    /**
     * Malloc native JNI ML-KEM structure
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails with memory error
     */
    protected native long mallocNativeStruct() throws OutOfMemoryError;

    private native void wc_mlkem_init(int level);
    private native void wc_mlkem_free();
    private native void wc_mlkem_make_key(Rng rng);
    private native void wc_mlkem_make_key_from_seed(byte[] seed);
    private native byte[] wc_mlkem_encapsulate(Rng rng);
    private native byte[] wc_mlkem_encapsulate_with_random(byte[] rand);
    private native byte[] wc_mlkem_decapsulate(byte[] ciphertext);
    private native byte[] wc_mlkem_export_public();
    private native byte[] wc_mlkem_export_private();
    private native void wc_mlkem_import_public(byte[] pubKey);
    private native void wc_mlkem_import_private(byte[] privKey);
    private native int wc_mlkem_public_key_size();
    private native int wc_mlkem_private_key_size();
    private native int wc_mlkem_ciphertext_size();
    private native int wc_mlkem_shared_secret_size();

    /**
     * Internal helper method to initialize object if needed.
     *
     * @throws IllegalStateException on failure to initialize properly, or
     *         if releaseNativeStruct() has been called and object has been
     *         released
     */
    private synchronized void checkStateAndInitialize()
        throws IllegalStateException {

        synchronized (stateLock) {
            if (state == WolfCryptState.RELEASED) {
                throw new IllegalStateException("Object has been released");
            }

            if (state == WolfCryptState.UNINITIALIZED) {
                init();
                if (state != WolfCryptState.INITIALIZED) {
                    throw new IllegalStateException(
                        "Failed to initialize Object");
                }
            }
        }
    }

    /**
     * Initialize ML-KEM object.
     */
    private void init() {
        synchronized (pointerLock) {
            /* Allocate native struct pointer from NativeStruct */
            initNativeStruct();
            wc_mlkem_init(this.level);
        }

        state = WolfCryptState.INITIALIZED;
    }

    /**
     * Throw exception if key has been loaded already.
     *
     * @throws IllegalStateException if key has been loaded already
     */
    private void throwIfKeyExists() throws IllegalStateException {
        synchronized (stateLock) {
            if (state == WolfCryptState.READY) {
                throw new IllegalStateException("Object already has a key");
            }
        }
    }

    /**
     * Throw exception if key has not been loaded.
     *
     * @throws IllegalStateException if key has not been loaded
     */
    private void throwIfKeyNotLoaded() throws IllegalStateException {
        synchronized (stateLock) {
            if (state != WolfCryptState.READY) {
                throw new IllegalStateException(
                    "No key available to perform the operation");
            }
        }
    }

    /**
     * Generate a new ML-KEM key pair using the provided RNG.
     *
     * @param rng initialized Rng object to use for randomness
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public void makeKey(Rng rng)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_mlkem_make_key(rng);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Deterministically generate a new ML-KEM key pair from a 64-byte seed.
     *
     * The seed is the FIPS 203 key generation randomness (d || z). This is
     * the path used to retain the seed for compact PKCS#8 encoding.
     *
     * @param seed 64-byte key generation seed
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if seed is null or not
     *         ML_KEM_SEED_SIZE (64) bytes
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public void makeKeyFromSeed(byte[] seed)
        throws WolfCryptException, IllegalStateException {

        if (seed == null || seed.length != ML_KEM_SEED_SIZE) {
            throw new IllegalArgumentException(
                "ML-KEM keygen seed must be " + ML_KEM_SEED_SIZE + " bytes");
        }

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_mlkem_make_key_from_seed(seed);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Encapsulate to this object's public key, producing a ciphertext and
     * shared secret.
     *
     * @param rng initialized Rng object to use for randomness
     *
     * @return a two element array, where index 0 is the ciphertext and
     *         index 1 is the shared secret.
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if no public key has been loaded, if
     *         object fails to initialize, or if releaseNativeStruct() has
     *         been called and object has been released.
     */
    public byte[][] encapsulate(Rng rng)
        throws WolfCryptException, IllegalStateException {

        byte[] combined = null;

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            combined = wc_mlkem_encapsulate(rng);
        }

        /* Native returns ciphertext || sharedSecret, shared secret is the
         * trailing ML_KEM_SHARED_SECRET_SIZE bytes. */
        int ctLen = combined.length - ML_KEM_SHARED_SECRET_SIZE;
        byte[] ciphertext = Arrays.copyOfRange(combined, 0, ctLen);
        byte[] secret = Arrays.copyOfRange(combined, ctLen, combined.length);

        /* Wipe intermediate buffer */
        Arrays.fill(combined, (byte) 0);

        return new byte[][] { ciphertext, secret };
    }

    /**
     * Encapsulate to this object's public key using caller-supplied
     * randomness, producing a deterministic ciphertext and shared secret.
     *
     * This is intended for known-answer testing and other deterministic use.
     * For normal operation use {@link #encapsulate(Rng)}. Supplying
     * predictable or reused randomness here breaks the security of the KEM.
     *
     * @param rand encapsulation randomness, ML_KEM_ENCAPS_RANDOM_SIZE bytes
     *
     * @return a two element array: index 0 is the ciphertext, index 1 is the
     *         shared secret (ML_KEM_SHARED_SECRET_SIZE bytes)
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if rand is null or not
     *         ML_KEM_ENCAPS_RANDOM_SIZE (32) bytes
     * @throws IllegalStateException if the object fails to initialize
     */
    public byte[][] encapsulateWithRandom(byte[] rand)
        throws WolfCryptException, IllegalStateException {

        byte[] combined = null;

        if (rand == null || rand.length != ML_KEM_ENCAPS_RANDOM_SIZE) {
            throw new IllegalArgumentException(
                "ML-KEM encapsulation randomness must be " +
                ML_KEM_ENCAPS_RANDOM_SIZE + " bytes");
        }

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            combined = wc_mlkem_encapsulate_with_random(rand);
        }

        /* Native returns ciphertext || sharedSecret, shared secret is the
         * trailing ML_KEM_SHARED_SECRET_SIZE bytes. */
        int ctLen = combined.length - ML_KEM_SHARED_SECRET_SIZE;
        byte[] ciphertext = Arrays.copyOfRange(combined, 0, ctLen);
        byte[] secret = Arrays.copyOfRange(combined, ctLen, combined.length);

        /* Wipe intermediate buffer */
        Arrays.fill(combined, (byte) 0);

        return new byte[][] { ciphertext, secret };
    }

    /**
     * Decapsulate a ciphertext using this object's private key, producing
     * the shared secret.
     *
     * @param ciphertext ciphertext received from the encapsulating party
     *
     * @return the shared secret (ML_KEM_SHARED_SECRET_SIZE bytes)
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if no private key has been loaded, if
     *         object fails to initialize, or if releaseNativeStruct() has
     *         been called and object has been released.
     */
    public byte[] decapsulate(byte[] ciphertext)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_mlkem_decapsulate(ciphertext);
        }
    }

    /**
     * Export the raw public (encapsulation) key.
     *
     * @return raw public key bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if no key has been loaded, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public byte[] exportPublic()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_mlkem_export_public();
        }
    }

    /**
     * Export the raw expanded private (decapsulation) key.
     *
     * @return raw expanded private key bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if no key has been loaded, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public byte[] exportPrivate()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_mlkem_export_private();
        }
    }

    /**
     * Import a raw public (encapsulation) key.
     *
     * @param pubKey raw public key bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public void importPublic(byte[] pubKey)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_mlkem_import_public(pubKey);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Import a raw expanded private (decapsulation) key.
     *
     * @param privKey raw expanded private key bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public void importPrivate(byte[] privKey)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_mlkem_import_private(privKey);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Get the raw public (encapsulation) key size for this parameter set.
     *
     * @return public key size in bytes
     *
     * @throws IllegalStateException if object fails to initialize, or if
     *         releaseNativeStruct() has been called.
     */
    public int publicKeySize() throws IllegalStateException {

        checkStateAndInitialize();

        synchronized (pointerLock) {
            return wc_mlkem_public_key_size();
        }
    }

    /**
     * Get the raw expanded private (decapsulation) key size for this
     * parameter set.
     *
     * @return private key size in bytes
     *
     * @throws IllegalStateException if object fails to initialize, or if
     *         releaseNativeStruct() has been called.
     */
    public int privateKeySize() throws IllegalStateException {

        checkStateAndInitialize();

        synchronized (pointerLock) {
            return wc_mlkem_private_key_size();
        }
    }

    /**
     * Get the ciphertext size for this parameter set.
     *
     * @return ciphertext size in bytes
     *
     * @throws IllegalStateException if object fails to initialize, or if
     *         releaseNativeStruct() has been called.
     */
    public int ciphertextSize() throws IllegalStateException {

        checkStateAndInitialize();

        synchronized (pointerLock) {
            return wc_mlkem_ciphertext_size();
        }
    }

    /**
     * Get the shared secret size for this parameter set.
     *
     * @return shared secret size in bytes
     *
     * @throws IllegalStateException if object fails to initialize, or if
     *         releaseNativeStruct() has been called.
     */
    public int sharedSecretSize() throws IllegalStateException {

        checkStateAndInitialize();

        synchronized (pointerLock) {
            return wc_mlkem_shared_secret_size();
        }
    }
}
