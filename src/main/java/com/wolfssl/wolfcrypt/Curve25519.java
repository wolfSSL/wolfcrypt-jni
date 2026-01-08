/* Curve25519.java
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

/**
 * Wrapper for the native WolfCrypt Curve25519 implementation.
 */
public class Curve25519 extends NativeStruct {

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /** Lock around object state */
    protected final Object stateLock = new Object();

    /**
     * Create new Curve25519 object.
     *
     * @throws WolfCryptException if Curve25519 has not been compiled into
     *         native wolfCrypt library.
     */
    public Curve25519() {
        if (!FeatureDetect.Curve25519Enabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }
        /* Internal state is initialized on first use */
    }

    @Override
    public void releaseNativeStruct() {
        synchronized (stateLock) {
            if ((state != WolfCryptState.UNINITIALIZED) &&
                (state != WolfCryptState.RELEASED)) {

                synchronized (pointerLock) {
                    wc_curve25519_free();
                }
                super.releaseNativeStruct();
                state = WolfCryptState.RELEASED;
            }
        }
    }

    /**
     * Malloc native JNI Curve25519 structure
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails with memory error
     */
    protected native long mallocNativeStruct() throws OutOfMemoryError;

    private native void wc_curve25519_init();
    private native void wc_curve25519_free();
    private native void wc_curve25519_make_key(Rng rng, int size);
    private native void wc_curve25519_make_key_ex(Rng rng, int size, int endian);
    private native void wc_curve25519_check_key();
    private native byte[] wc_curve25519_make_shared_secret(Curve25519 pubKey);
    private native void wc_curve25519_import_private(byte[] privKey, byte[] key);
    private native void wc_curve25519_import_private_only(byte[] privKey);
    private native void wc_curve25519_import_public(byte[] pubKey);
    private native byte[] wc_curve25519_export_private();
    private native byte[] wc_curve25519_export_public();

    /**
     * Internal helper method to initialize object if/when needed.
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
     * Initialize Curve25519 object.
     */
    private void init() {
        synchronized (pointerLock) {
            /* Allocate native struct pointer from NativeStruct */
            initNativeStruct();
            wc_curve25519_init();
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
     * Generate new Curve25519 key.
     *
     * @param rng Initialized Rng object to use for randomness
     * @param size size of key to generate
     *
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public void makeKey(Rng rng, int size) throws IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_curve25519_make_key(rng, size);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Generate new Curve25519 key with specified endianness.
     *
     * @param rng initialized Rng object to use for randomness
     * @param size size of key to generate
     * @param endian endianness of key
     *
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public void makeKeyWithEndian(Rng rng, int size, int endian)
        throws IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_curve25519_make_key_ex(rng, size, endian);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Check Curve25519 key for correctness.
     *
     * @throws WolfCryptException if key is not correct
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public void checkKey() throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            wc_curve25519_check_key();
        }
    }

    /**
     * Import private and public key.
     *
     * @param privKey private Curve25519 key array
     * @param xKey public Curve25519 key array
     *
     * @throws WolfCryptException if error occurs during key import
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public void importPrivate(byte[] privKey, byte[] xKey)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_curve25519_import_private(privKey, xKey);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Import private key from byte array.
     *
     * @param privKey byte array containing private Curve25519 key
     *
     * @throws WolfCryptException if error occurs during key import
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public void importPrivateOnly(byte[] privKey)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_curve25519_import_private_only(privKey);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Import public key from byte array.
     *
     * @param pubKey public Curve25519 key array
     *
     * @throws WolfCryptException if error occurs during key import
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
                wc_curve25519_import_public(pubKey);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Export private key as byte array.
     *
     * @return byte array of private Curve25519 key
     *
     * @throws WolfCryptException if error occurs during key export
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public byte[] exportPrivate()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_curve25519_export_private();
        }
    }

    /**
     * Export public key as byte array.
     *
     * @return byte array of public Curve25519 key
     *
     * @throws WolfCryptException if error occurs during key export
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public byte[] exportPublic()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_curve25519_export_public();
        }
    }

    /**
     * Generate shared secret between this object and specified public key.
     *
     * @param pubKey public key to use for secret generation
     *
     * @return shared secret as byte array
     *
     * @throws WolfCryptException if error occurs during secret generation
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public byte[] makeSharedSecret(Curve25519 pubKey)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_curve25519_make_shared_secret(pubKey);
        }
    }
}

